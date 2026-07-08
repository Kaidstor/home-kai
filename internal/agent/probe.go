package agent

import (
	"context"
	"strings"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
)

// M3 direct connections. Spokes install each other with EMPTY AllowedIPs and
// a candidate endpoint: handshakes are not subject to cryptokey routing, so
// probing never steals traffic from the hub path. Both sides probe at once
// (they share the netmap), which is exactly the simultaneous transmission
// that punches full-/restricted-cone NATs. Only after a confirmed handshake
// does the peer get its /32 — which then beats the hub's /16 by longest
// prefix. When the direct path dies, dropping back to empty AllowedIPs
// restores relaying instantly.
const (
	probeTick        = 3 * time.Second
	candidateWindow  = 10 * time.Second // per-candidate handshake budget
	directStaleAfter = 3 * time.Minute  // keepalive is 25s — 3 missed rekeys means the path is dead
	retryAfterFail   = 30 * time.Minute
	retryAfterDemote = 2 * time.Minute
)

type probePhase int

const (
	phaseIdle probePhase = iota
	phaseProbing
	phaseDirect
)

func (p probePhase) String() string {
	switch p {
	case phaseProbing:
		return "probing"
	case phaseDirect:
		return "direct"
	default:
		return "idle"
	}
}

type probeState struct {
	phase       probePhase
	candidates  []string
	candIdx     int
	attemptAt   time.Time // start of the current candidate attempt
	nextRetryAt time.Time
	hostname    string // for logs/status
	// confirmedEndpoint is the peer's real source address at promotion time —
	// WireGuard roaming may have moved it off the probed candidate (e.g. the
	// peer reached us first from a different port).
	confirmedEndpoint string
}

// endpoint returns the candidate endpoint to install, if any.
func (ps *probeState) endpoint() string {
	if ps.phase == phaseIdle || ps.candIdx >= len(ps.candidates) {
		return ""
	}
	return ps.candidates[ps.candIdx]
}

// syncProbes reconciles prober state with a fresh netmap. Callers hold a.mu.
func (a *Agent) syncProbes(nm *api.Netmap) {
	if a.probes == nil {
		a.probes = map[string]*probeState{}
	}
	seen := map[string]bool{}
	for _, p := range nm.Peers {
		if !a.probeManaged(p) {
			continue
		}
		seen[p.WGPublicKey] = true
		ps := a.probes[p.WGPublicKey]
		if ps == nil {
			ps = &probeState{}
			a.probes[p.WGPublicKey] = ps
		}
		ps.hostname = p.Hostname
		if strings.Join(ps.candidates, ",") != strings.Join(p.Candidates, ",") {
			ps.candidates = p.Candidates
			// New addresses are worth trying right away — unless the current
			// direct path still works.
			if ps.phase == phaseProbing {
				ps.candIdx, ps.attemptAt = 0, time.Now()
			}
			if ps.phase == phaseIdle {
				ps.nextRetryAt = time.Time{}
			}
		}
	}
	for key := range a.probes {
		if !seen[key] {
			delete(a.probes, key)
		}
	}
}

// probeManaged: on spokes, peers without a fixed endpoint (other spokes) are
// owned by the prober; the hub itself and everything on a hub node applies
// verbatim.
func (a *Agent) probeManaged(p api.Peer) bool {
	return a.st.Role != api.RoleHub && p.Endpoint == "" && p.Role == api.RoleNode
}

func (a *Agent) probeLoop(ctx context.Context) {
	t := time.NewTicker(probeTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.probeStep(time.Now())
		}
	}
}

func (a *Agent) probeStep(now time.Time) {
	statuses, err := a.dev.Peers()
	if err != nil {
		a.log.Warn("probe: reading device peers failed", "err", err)
		return
	}
	handshakes := map[string]time.Time{}
	liveEndpoints := map[string]string{}
	for _, st := range statuses {
		handshakes[st.PublicKey.String()] = st.LastHandshake
		liveEndpoints[st.PublicKey.String()] = st.Endpoint
	}

	a.mu.Lock()
	changed := false
	for key, ps := range a.probes {
		hs := handshakes[key]
		switch ps.phase {
		case phaseDirect:
			if now.Sub(hs) > directStaleAfter {
				ps.phase = phaseIdle
				ps.confirmedEndpoint = ""
				ps.nextRetryAt = now.Add(retryAfterDemote)
				changed = true
				a.log.Info("direct path lost — falling back to hub", "peer", ps.hostname)
			}
		case phaseProbing:
			if hs.After(ps.attemptAt) {
				ps.phase = phaseDirect
				ps.confirmedEndpoint = liveEndpoints[key]
				changed = true
				a.log.Info("direct path established", "peer", ps.hostname, "endpoint", ps.confirmedEndpoint)
			} else if now.Sub(ps.attemptAt) > candidateWindow {
				ps.candIdx++
				ps.attemptAt = now
				if ps.candIdx >= len(ps.candidates) {
					ps.phase = phaseIdle
					ps.nextRetryAt = now.Add(retryAfterFail)
					a.log.Info("no direct path — staying on hub relay", "peer", ps.hostname)
				}
				changed = true
			}
		case phaseIdle:
			if len(ps.candidates) > 0 && now.After(ps.nextRetryAt) {
				ps.phase = phaseProbing
				ps.candIdx = 0
				ps.attemptAt = now
				changed = true
				a.log.Info("probing for a direct path", "peer", ps.hostname, "candidates", ps.candidates)
			}
		}
	}
	nm := a.nm
	a.mu.Unlock()

	if changed && nm != nil {
		if err := a.applyNetmap(nm); err != nil {
			a.log.Error("probe: reapplying peers failed", "err", err)
		}
	}
}
