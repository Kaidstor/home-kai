package coordinator

import (
	"fmt"
	"net/netip"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/coordinator/store"
	"github.com/kaidstor/home-kai/internal/text"
)

// KeepaliveSec keeps NAT mappings alive on every spoke→hub tunnel; the hub
// also relies on it to observe fresh reflexive endpoints (M3).
const KeepaliveSec = 25

// buildHosts derives a stable name→overlay-IP list for every device. Names
// are sanitized to DNS labels; duplicates get -2, -3, … in enrollment order.
func buildHosts(nodes []store.Node, statics []store.StaticPeer) []api.HostEntry {
	used := map[string]bool{}
	var out []api.HostEntry
	add := func(name, ip string) {
		base := sanitizeHostLabel(name)
		label := base
		for i := 2; used[label]; i++ {
			label = fmt.Sprintf("%s-%d", base, i)
		}
		used[label] = true
		out = append(out, api.HostEntry{Name: label + api.HostsSuffix, IP: ip})
	}
	for _, n := range nodes {
		add(n.Name, n.OverlayIP)
	}
	for _, p := range statics {
		add(p.Name, p.OverlayIP)
	}
	return out
}

// sanitizeHostLabel slugs a device name into a DNS label, falling back to
// "device" when nothing usable remains.
func sanitizeHostLabel(s string) string {
	if label := text.Slug(s); label != "" {
		return label
	}
	return "device"
}

// BuildNetmap computes the full WireGuard state for one node.
//
// Topology:
//   - spoke: the hub with AllowedIPs = the whole overlay CIDR (cryptokey
//     routing sends overlay traffic through it) plus every other spoke as a
//     probe candidate — /32 with no endpoint but with Candidates (M3: the
//     agent installs it with empty AllowedIPs, probes, and only a confirmed
//     direct path wins over the hub's /16 by longest prefix);
//   - hub: every other node and every static peer as a /32 with no endpoint
//     (they dial in).
//
// candidates maps node ID → fresh "ip:port" endpoints (LAN first, then
// hub-observed reflexive addresses). lockPub (base64 ed25519, empty when the
// network lock is off) is pinned by agents; each peer carries its binding
// signature so locked agents can verify before installing.
func BuildNetmap(self store.Node, nodes []store.Node, statics []store.StaticPeer,
	candidates map[string][]string, publishes []store.Publish, lockPub string,
	cidr netip.Prefix, hubEndpoint string, mtu int, version int64) (api.Netmap, error) {

	nm := api.Netmap{
		Version: version,
		Self: api.NetmapSelf{
			NodeID:        self.ID,
			Role:          api.NodeRole(self.Role),
			OverlayIP:     self.OverlayIP,
			OverlayCIDR:   cidr.String(),
			DNSName:       self.DNSName,
			MTU:           mtu,
			LockPublicKey: lockPub,
		},
		Hosts: buildHosts(nodes, statics),
	}

	if self.Role == string(api.RoleHub) {
		for _, n := range nodes {
			if n.ID == self.ID {
				continue
			}
			// Enabled subnet routes ride on the advertising node's peer entry:
			// cryptokey routing then forwards subnet traffic to that node.
			nm.Peers = append(nm.Peers, api.Peer{
				NodeID:      n.ID,
				Hostname:    n.Name,
				Role:        api.NodeRole(n.Role),
				DNSName:     n.DNSName,
				OverlayIP:   n.OverlayIP,
				WGPublicKey: n.WGPubKey,
				AllowedIPs:  append([]string{n.OverlayIP + "/32"}, n.RoutesEnabled...),
				LockSig:     n.LockSig,
			})
		}
		for _, p := range statics {
			nm.Peers = append(nm.Peers, api.Peer{
				NodeID:      p.ID,
				Hostname:    p.Name,
				Role:        api.RoleNode,
				DNSName:     p.DNSName,
				OverlayIP:   p.OverlayIP,
				WGPublicKey: p.WGPubKey,
				AllowedIPs:  []string{p.OverlayIP + "/32"},
				LockSig:     p.LockSig,
			})
		}
		for _, p := range publishes {
			nm.Publishes = append(nm.Publishes, api.Publish{
				ID: p.ID, Name: p.Name, ListenPort: p.ListenPort, Target: p.Target,
			})
		}
		return nm, nil
	}

	// Spoke: find the hub.
	var hub *store.Node
	for i := range nodes {
		if nodes[i].Role == string(api.RoleHub) {
			hub = &nodes[i]
			break
		}
	}
	if hub == nil {
		return api.Netmap{}, fmt.Errorf("netmap: no hub node registered")
	}
	// Every other node's enabled subnets are reached via the hub (which
	// forwards to the advertising node). Own subnets are local — excluded.
	hubAllowed := []string{cidr.Masked().String()}
	for _, n := range nodes {
		if n.ID == self.ID {
			continue
		}
		hubAllowed = append(hubAllowed, n.RoutesEnabled...)
	}
	nm.Peers = append(nm.Peers, api.Peer{
		NodeID:       hub.ID,
		Hostname:     hub.Name,
		Role:         api.RoleHub,
		DNSName:      hub.DNSName,
		OverlayIP:    hub.OverlayIP,
		WGPublicKey:  hub.WGPubKey,
		Endpoint:     hubEndpoint,
		AllowedIPs:   hubAllowed,
		KeepaliveSec: KeepaliveSec,
		LockSig:      hub.LockSig,
	})
	// Other spokes: direct-path candidates for the prober.
	for _, n := range nodes {
		if n.ID == self.ID || n.Role == string(api.RoleHub) {
			continue
		}
		nm.Peers = append(nm.Peers, api.Peer{
			NodeID:       n.ID,
			Hostname:     n.Name,
			Role:         api.NodeRole(n.Role),
			DNSName:      n.DNSName,
			OverlayIP:    n.OverlayIP,
			WGPublicKey:  n.WGPubKey,
			AllowedIPs:   []string{n.OverlayIP + "/32"},
			KeepaliveSec: KeepaliveSec,
			Candidates:   candidates[n.ID],
			LockSig:      n.LockSig,
		})
	}
	return nm, nil
}
