package agent

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/kaidstor/home-kai/internal/agent/wgdev"
	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/wgkeys"
)

// fakeDevice records applied peers and serves canned runtime statuses.
type fakeDevice struct {
	applied  []wgdev.PeerConfig
	statuses []wgdev.PeerStatus
	routes   []netip.Prefix
}

func (f *fakeDevice) Name() string                          { return "kai-test" }
func (f *fakeDevice) ApplyPeers(p []wgdev.PeerConfig) error { f.applied = p; return nil }
func (f *fakeDevice) Peers() ([]wgdev.PeerStatus, error)    { return f.statuses, nil }
func (f *fakeDevice) SyncRoutes(p []netip.Prefix) error     { f.routes = p; return nil }
func (f *fakeDevice) SetPrivateKey(_ wgtypes.Key) error     { return nil }
func (f *fakeDevice) Close() error                          { return nil }

func testAgent(t *testing.T) (*Agent, *fakeDevice, *api.Netmap, string) {
	t.Helper()
	hubKey, _ := wgkeys.Generate()
	peerKey, _ := wgkeys.Generate()
	nm := &api.Netmap{
		Version: 1,
		Self:    api.NetmapSelf{NodeID: "n_self", Role: api.RoleNode, OverlayIP: "100.87.0.2", OverlayCIDR: "100.87.0.0/16"},
		Peers: []api.Peer{
			{NodeID: "n_hub", Hostname: "hub", Role: api.RoleHub, WGPublicKey: hubKey.Public.String(),
				Endpoint: "203.0.113.1:51820", AllowedIPs: []string{"100.87.0.0/16"}, KeepaliveSec: 25},
			{NodeID: "n_peer", Hostname: "he-3", Role: api.RoleNode, WGPublicKey: peerKey.Public.String(),
				AllowedIPs: []string{"100.87.0.3/32"}, KeepaliveSec: 25,
				Candidates: []string{"192.168.1.7:51820", "203.0.113.5:51820"}},
		},
	}
	dev := &fakeDevice{}
	a := &Agent{
		st:  &State{Role: api.RoleNode, OverlayIP: "100.87.0.2", OverlayCIDR: "100.87.0.0/16", NoHosts: true},
		dev: dev,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return a, dev, nm, peerKey.Public.String()
}

// appliedPeer finds the direct peer in the last ApplyPeers call.
func appliedPeer(t *testing.T, dev *fakeDevice, pub string) wgdev.PeerConfig {
	t.Helper()
	for _, p := range dev.applied {
		if p.PublicKey.String() == pub {
			return p
		}
	}
	t.Fatalf("peer %s not applied", pub)
	return wgdev.PeerConfig{}
}

func TestProbeLifecycle(t *testing.T) {
	a, dev, nm, peerPub := testAgent(t)
	now := time.Now()

	// Fresh netmap: the direct peer must be installed WITHOUT allowed IPs and
	// without endpoint — relaying via the hub stays untouched.
	if err := a.applyNetmap(nm); err != nil {
		t.Fatal(err)
	}
	pc := appliedPeer(t, dev, peerPub)
	if len(pc.AllowedIPs) != 0 || pc.Endpoint != "" {
		t.Fatalf("idle peer must be inert: %+v", pc)
	}
	// No endpoint → no keepalive (else wireguard-go logs "no known endpoint").
	if pc.Keepalive != 0 {
		t.Fatalf("idle peer must not carry keepalive: %+v", pc)
	}

	// First tick: probing starts with the first (LAN) candidate.
	a.probeStep(now)
	pc = appliedPeer(t, dev, peerPub)
	if pc.Endpoint != "192.168.1.7:51820" || len(pc.AllowedIPs) != 0 {
		t.Fatalf("probing peer: %+v", pc)
	}

	// No handshake within the window → next candidate.
	a.probeStep(now.Add(candidateWindow + time.Second))
	pc = appliedPeer(t, dev, peerPub)
	if pc.Endpoint != "203.0.113.5:51820" {
		t.Fatalf("second candidate expected: %+v", pc)
	}

	// Handshake arrives (roamed port) → promote: /32 + confirmed endpoint.
	key, _ := wgkeys.ParsePublic(peerPub)
	dev.statuses = []wgdev.PeerStatus{{
		PublicKey: key, Endpoint: "203.0.113.5:44444",
		LastHandshake: now.Add(candidateWindow + 5*time.Second),
	}}
	a.probeStep(now.Add(candidateWindow + 6*time.Second))
	pc = appliedPeer(t, dev, peerPub)
	if pc.Endpoint != "203.0.113.5:44444" || len(pc.AllowedIPs) != 1 || pc.AllowedIPs[0].String() != "100.87.0.3/32" {
		t.Fatalf("direct peer: %+v", pc)
	}

	// Handshake goes stale → demote back to hub relay, retry later.
	a.probeStep(now.Add(candidateWindow + 6*time.Second + directStaleAfter + time.Minute))
	pc = appliedPeer(t, dev, peerPub)
	if len(pc.AllowedIPs) != 0 || pc.Endpoint != "" {
		t.Fatalf("demoted peer must be inert: %+v", pc)
	}
	ps := a.probes[peerPub]
	if ps.phase != phaseIdle || ps.nextRetryAt.IsZero() {
		t.Fatalf("probe state after demote: %+v", ps)
	}
}

func TestProbeAllCandidatesFail(t *testing.T) {
	a, dev, nm, peerPub := testAgent(t)
	now := time.Now()
	if err := a.applyNetmap(nm); err != nil {
		t.Fatal(err)
	}
	a.probeStep(now)                                    // start: candidate 0
	a.probeStep(now.Add(candidateWindow + time.Second)) // candidate 1
	a.probeStep(now.Add(2 * (candidateWindow + time.Second)))
	ps := a.probes[peerPub]
	if ps.phase != phaseIdle || !ps.nextRetryAt.After(now.Add(retryAfterFail/2)) {
		t.Fatalf("must back off after exhausting candidates: %+v", ps)
	}
	pc := appliedPeer(t, dev, peerPub)
	if len(pc.AllowedIPs) != 0 || pc.Endpoint != "" {
		t.Fatalf("failed peer must be inert: %+v", pc)
	}

	// Fresh candidates from a new netmap reset the backoff.
	nm2 := *nm
	nm2.Peers = append([]api.Peer{}, nm.Peers...)
	nm2.Peers[1].Candidates = []string{"198.51.100.9:51820"}
	if err := a.applyNetmap(&nm2); err != nil {
		t.Fatal(err)
	}
	a.probeStep(now.Add(3 * candidateWindow))
	pc = appliedPeer(t, dev, peerPub)
	if pc.Endpoint != "198.51.100.9:51820" {
		t.Fatalf("new candidates must re-trigger probing: %+v", pc)
	}
}

// The peer reboots and its probe handshakes us while we sit in the 30-minute
// retry backoff: promotion must not wait for our own retry — the peer's
// replies already flow over the direct session where empty AllowedIPs would
// drop them.
func TestProbePeerInitiatedPromotion(t *testing.T) {
	a, dev, nm, peerPub := testAgent(t)
	now := time.Now()
	if err := a.applyNetmap(nm); err != nil {
		t.Fatal(err)
	}
	a.probeStep(now)                                          // candidate 0
	a.probeStep(now.Add(candidateWindow + time.Second))       // candidate 1
	a.probeStep(now.Add(2 * (candidateWindow + time.Second))) // exhausted → backoff
	if ps := a.probes[peerPub]; ps.phase != phaseIdle {
		t.Fatalf("expected idle backoff: %+v", ps)
	}

	key, _ := wgkeys.ParsePublic(peerPub)
	hsAt := now.Add(5 * time.Minute) // deep inside retryAfterFail
	dev.statuses = []wgdev.PeerStatus{{
		PublicKey: key, Endpoint: "198.51.100.7:51820", LastHandshake: hsAt,
	}}
	a.probeStep(hsAt.Add(probeTick))
	pc := appliedPeer(t, dev, peerPub)
	if pc.Endpoint != "198.51.100.7:51820" || len(pc.AllowedIPs) != 1 || pc.AllowedIPs[0].String() != "100.87.0.3/32" {
		t.Fatalf("peer-initiated handshake must promote: %+v", pc)
	}
	if ps := a.probes[peerPub]; ps.phase != phaseDirect {
		t.Fatalf("probe state after peer-initiated promotion: %+v", ps)
	}
}

// Withdrawn candidates mean the coordinator (e.g. the ACL) forced this pair
// onto the hub relay — a still-live handshake must not resurrect the direct
// path from idle.
func TestProbeWithdrawnCandidatesIgnoreHandshake(t *testing.T) {
	a, dev, nm, peerPub := testAgent(t)
	now := time.Now()
	if err := a.applyNetmap(nm); err != nil {
		t.Fatal(err)
	}
	a.probeStep(now) // probing starts

	nm2 := *nm
	nm2.Peers = append([]api.Peer{}, nm.Peers...)
	nm2.Peers[1].Candidates = nil
	if err := a.applyNetmap(&nm2); err != nil {
		t.Fatal(err)
	}

	key, _ := wgkeys.ParsePublic(peerPub)
	dev.statuses = []wgdev.PeerStatus{{
		PublicKey: key, Endpoint: "198.51.100.7:51820", LastHandshake: now.Add(2 * probeTick),
	}}
	a.probeStep(now.Add(3 * probeTick))
	pc := appliedPeer(t, dev, peerPub)
	if len(pc.AllowedIPs) != 0 || pc.Endpoint != "" {
		t.Fatalf("withdrawn peer must stay inert: %+v", pc)
	}
}

func TestHubAppliesPeersVerbatim(t *testing.T) {
	hubKey, _ := wgkeys.Generate()
	spokeKey, _ := wgkeys.Generate()
	dev := &fakeDevice{}
	a := &Agent{
		st:  &State{Role: api.RoleHub, OverlayCIDR: "100.87.0.0/16", NoHosts: true},
		dev: dev,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	nm := &api.Netmap{
		Self: api.NetmapSelf{Role: api.RoleHub, OverlayCIDR: "100.87.0.0/16"},
		Peers: []api.Peer{
			{NodeID: "n_1", Role: api.RoleNode, WGPublicKey: spokeKey.Public.String(),
				AllowedIPs: []string{"100.87.0.2/32", "172.18.0.0/16"}},
			{NodeID: "n_2", Role: api.RoleNode, WGPublicKey: hubKey.Public.String(),
				AllowedIPs: []string{"100.87.0.3/32"}},
		},
	}
	if err := a.applyNetmap(nm); err != nil {
		t.Fatal(err)
	}
	if len(dev.applied) != 2 || len(dev.applied[0].AllowedIPs) != 2 {
		t.Fatalf("hub must apply verbatim: %+v", dev.applied)
	}
	if len(dev.routes) != 1 || dev.routes[0].String() != "172.18.0.0/16" {
		t.Fatalf("subnet route missing on hub: %+v", dev.routes)
	}
	if len(a.probes) != 0 {
		t.Fatalf("hub must not probe: %+v", a.probes)
	}
}
