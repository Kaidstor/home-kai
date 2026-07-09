package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
)

func (a *Agent) serveLocalAPI(ctx context.Context) {
	_ = os.Remove(api.LocalSocketPath)
	l, err := net.Listen("unix", api.LocalSocketPath)
	if err != nil {
		a.log.Warn("local api unavailable", "err", err)
		return
	}
	_ = os.Chmod(api.LocalSocketPath, 0o666)

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
		_ = os.Remove(api.LocalSocketPath)
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
	ip, _, _ := strings.Cut(s, "/")
	return ip
}
