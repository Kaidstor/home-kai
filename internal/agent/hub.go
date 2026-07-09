package agent

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
)

// handshakeFreshness: only endpoints with a recent handshake are worth
// distributing as hole-punch candidates (M3).
const handshakeFreshness = 3 * time.Minute

// observedPeers reports the reflexive endpoints this hub sees for each peer
// with a fresh handshake — the coordinator turns them into M3 candidates.
func (a *Agent) observedPeers() []api.PeerObserved {
	peers, err := a.dev.Peers()
	if err != nil {
		a.log.Warn("reading device peers failed", "err", err)
		return nil
	}
	var out []api.PeerObserved
	for _, p := range peers {
		if p.Endpoint == "" || p.LastHandshake.IsZero() {
			continue
		}
		age := time.Since(p.LastHandshake)
		if age > handshakeFreshness {
			continue
		}
		out = append(out, api.PeerObserved{
			WGPublicKey:         p.PublicKey.String(),
			Endpoint:            p.Endpoint,
			LastHandshakeAgeSec: int64(age.Seconds()),
		})
	}
	return out
}

// localEndpoints lists this node's plausible LAN endpoints (M3 candidates for
// same-network peers). Virtual interfaces (docker bridges, veth, tunnels) are
// skipped — those addresses are unreachable from other machines and would
// waste a probe window each.
func (a *Agent) localEndpoints() []string {
	if a.st.ListenPort == 0 {
		return nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || virtualIface(ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || !ip4.IsPrivate() {
				continue
			}
			// Skip our own overlay (relevant when overlay_cidr is an RFC1918
			// range — the default 100.87/16 is not "private" to begin with).
			if nip, ok := netip.AddrFromSlice(ip4); ok && a.overlay.Contains(nip) {
				continue
			}
			out = append(out, fmt.Sprintf("%s:%d", ip4, a.st.ListenPort))
		}
	}
	return out
}

func virtualIface(name string) bool {
	for _, p := range []string{"docker", "br-", "veth", "utun", "kai", "virbr", "tailscale", "wg"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
