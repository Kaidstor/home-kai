package coordinator

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// onlineWindow mirrors the web UI's definition of "online": agents touch the
// coordinator at least every ~70s (long-poll cycle), so two missed cycles
// means the node is gone.
const onlineWindow = 150 * time.Second

// handleMetrics serves a hand-rolled Prometheus exposition (admin bearer
// auth) — a scrape target for the zabbix/prometheus already on the VPS
// without pulling in a client library.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.Nodes()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	statics, err := s.store.StaticPeers()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	pubs, err := s.store.Publishes()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	policies, err := s.store.Policies()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	version, err := s.store.NetmapVersion()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	lockPub, lockActive, err := s.lockState()
	if err != nil {
		s.errInternal(w, err)
		return
	}

	online, pending := 0, 0
	now := time.Now()
	for _, n := range nodes {
		if now.Sub(n.LastSeen) < onlineWindow {
			online++
		}
		if !n.Approved {
			pending++
		}
	}
	s.sessMu.Lock()
	sessions := 0
	for _, exp := range s.sessions {
		if now.Before(exp) {
			sessions++
		}
	}
	s.sessMu.Unlock()

	b2i := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	var b strings.Builder
	metric := func(name, help string, value any) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", name, help, name, name, value)
	}
	metric("kai_nodes_total", "Enrolled agent nodes.", len(nodes))
	metric("kai_nodes_online", "Nodes seen within the last 150s.", online)
	metric("kai_nodes_pending_approval", "Nodes awaiting admin approval.", pending)
	metric("kai_policies_total", "ACL policies configured.", len(policies))
	metric("kai_static_peers_total", "Static peers (WireGuard-app devices).", len(statics))
	metric("kai_publishes_total", "Public TCP forwards on the hub.", len(pubs))
	metric("kai_netmap_version", "Current netmap version.", version)
	metric("kai_admin_sessions_active", "Live web UI sessions.", sessions)
	metric("kai_lock_enabled", "Network lock key uploaded.", b2i(lockPub != ""))
	metric("kai_lock_active", "Network lock enforced.", b2i(lockActive))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
