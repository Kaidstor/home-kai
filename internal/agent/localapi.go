package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
)

// LocalSocketPath is where the agent exposes its read-only status API for the
// kai CLI (`kai status`, `kai ping`). World-connectable on purpose: it only
// reveals tunnel state, never keys, and requiring sudo for status would be
// needless friction on a single-user machine.
const LocalSocketPath = "/var/run/kai-agent.sock"

func (a *Agent) serveLocalAPI(ctx context.Context) {
	_ = os.Remove(LocalSocketPath)
	l, err := net.Listen("unix", LocalSocketPath)
	if err != nil {
		a.log.Warn("local api unavailable", "err", err)
		return
	}
	_ = os.Chmod(LocalSocketPath, 0o666)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/local/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := a.localStatus()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(api.ErrorResponse{Error: err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(st)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
		_ = os.Remove(LocalSocketPath)
	}()
	_ = srv.Serve(l)
}

func (a *Agent) localStatus() (api.LocalStatus, error) {
	statuses, err := a.dev.Peers()
	if err != nil {
		return api.LocalStatus{}, err
	}
	type live struct {
		endpoint  string
		handshake time.Time
		rx, tx    int64
	}
	byKey := map[string]live{}
	for _, s := range statuses {
		byKey[s.PublicKey.String()] = live{s.Endpoint, s.LastHandshake, s.RxBytes, s.TxBytes}
	}

	hostname, _ := os.Hostname()
	out := api.LocalStatus{
		NodeID:         a.st.NodeID,
		Hostname:       hostname,
		Role:           a.st.Role,
		OverlayIP:      a.st.OverlayIP,
		CoordinatorURL: a.st.CoordinatorURL,
		AgentVersion:   Version,
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	nm := a.nm
	if nm == nil {
		return out, nil
	}
	out.NetmapVersion = nm.Version
	out.Hosts = nm.Hosts
	now := time.Now()
	for _, p := range nm.Peers {
		lv := byKey[p.WGPublicKey]
		lp := api.LocalPeer{
			Hostname:  p.Hostname,
			OverlayIP: p.OverlayIP,
			Role:      p.Role,
			Endpoint:  lv.endpoint,
			RxBytes:   lv.rx,
			TxBytes:   lv.tx,
		}
		if lp.OverlayIP == "" && len(p.AllowedIPs) > 0 { // netmaps cached by older agents
			lp.OverlayIP = trimCIDR(p.AllowedIPs[0])
		}
		if lv.handshake.IsZero() {
			lp.LastHandshakeAgeSec = -1
		} else {
			lp.LastHandshakeAgeSec = int64(now.Sub(lv.handshake).Seconds())
		}
		switch {
		case p.Role == api.RoleHub:
			lp.Path = "hub"
		case a.st.Role == api.RoleHub:
			lp.Path = "in"
		default:
			lp.Path = "relay"
			if ps := a.probes[p.WGPublicKey]; ps != nil {
				lp.Candidates = ps.candidates
				if ps.phase == phaseDirect {
					lp.Path = "direct"
				}
				// While relaying, the WG peer entry may hold probe state — the
				// endpoint shown would be misleading.
				if ps.phase != phaseDirect {
					lp.Endpoint = ""
				}
			}
		}
		out.Peers = append(out.Peers, lp)
	}
	return out, nil
}

func trimCIDR(s string) string {
	for i := range s {
		if s[i] == '/' {
			return s[:i]
		}
	}
	return s
}
