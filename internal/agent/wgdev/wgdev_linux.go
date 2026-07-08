//go:build linux

package wgdev

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const linkName = "kai0"

// linuxDevice drives kernel WireGuard (kernel >= 5.6) via netlink + wgctrl.
type linuxDevice struct {
	link   netlink.Link
	wg     *wgctrl.Client
	routes map[string]bool // extra subnet routes currently installed
}

func platformUp(cfg Config) (Device, error) {
	// Remove a stale interface from a previous run.
	if old, err := netlink.LinkByName(linkName); err == nil {
		_ = netlink.LinkDel(old)
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = linkName
	if cfg.MTU > 0 {
		attrs.MTU = cfg.MTU
	}
	wgLink := &netlink.Wireguard{LinkAttrs: attrs}
	if err := netlink.LinkAdd(wgLink); err != nil {
		return nil, fmt.Errorf("create %s: %w (is the wireguard kernel module available?)", linkName, err)
	}

	cleanup := func() { _ = netlink.LinkDel(wgLink) }

	wg, err := wgctrl.New()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("open wgctrl: %w", err)
	}
	port := cfg.ListenPort
	if err := wg.ConfigureDevice(linkName, wgtypes.Config{
		PrivateKey: &cfg.PrivateKey,
		ListenPort: &port,
	}); err != nil {
		wg.Close()
		cleanup()
		return nil, fmt.Errorf("configure %s: %w", linkName, err)
	}

	addr := &netlink.Addr{IPNet: &net.IPNet{
		IP:   cfg.Address.AsSlice(),
		Mask: net.CIDRMask(32, 32),
	}}
	if err := netlink.AddrAdd(wgLink, addr); err != nil {
		wg.Close()
		cleanup()
		return nil, fmt.Errorf("assign %s: %w", cfg.Address, err)
	}
	if err := netlink.LinkSetUp(wgLink); err != nil {
		wg.Close()
		cleanup()
		return nil, fmt.Errorf("link up: %w", err)
	}
	// Route the whole overlay into the tunnel. AllowedIPs decide which peer
	// gets each packet (cryptokey routing).
	overlay := &net.IPNet{
		IP:   cfg.OverlayNet.Masked().Addr().AsSlice(),
		Mask: net.CIDRMask(cfg.OverlayNet.Bits(), 32),
	}
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: wgLink.Index, Dst: overlay}); err != nil {
		wg.Close()
		cleanup()
		return nil, fmt.Errorf("route %s: %w", cfg.OverlayNet, err)
	}
	return &linuxDevice{link: wgLink, wg: wg, routes: map[string]bool{}}, nil
}

func (d *linuxDevice) Name() string { return linkName }

func prefixToIPNet(pfx netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   pfx.Masked().Addr().AsSlice(),
		Mask: net.CIDRMask(pfx.Bits(), pfx.Addr().BitLen()),
	}
}

// routeConflict reports an existing same-prefix route via another interface —
// typically a local docker bridge owning the subnet. Installing ours would
// shadow (with RouteReplace: silently DELETE) that route and break local
// traffic, so such prefixes must be skipped, not fought over.
func (d *linuxDevice) routeConflict(pfx netip.Prefix) (string, bool) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Dst: prefixToIPNet(pfx)}, netlink.RT_FILTER_DST)
	if err != nil {
		return "", false
	}
	for _, r := range routes {
		if r.LinkIndex != d.link.Attrs().Index {
			name := fmt.Sprintf("ifindex %d", r.LinkIndex)
			if l, err := netlink.LinkByIndex(r.LinkIndex); err == nil {
				name = l.Attrs().Name
			}
			return name, true
		}
	}
	return "", false
}

func (d *linuxDevice) SyncRoutes(prefixes []netip.Prefix) error {
	want := map[string]bool{}
	for _, p := range prefixes {
		want[p.Masked().String()] = true
	}
	for s := range d.routes {
		if want[s] {
			continue
		}
		pfx, _ := netip.ParsePrefix(s)
		if err := netlink.RouteDel(&netlink.Route{LinkIndex: d.link.Attrs().Index, Dst: prefixToIPNet(pfx)}); err != nil {
			return fmt.Errorf("route del %s: %w", s, err)
		}
		delete(d.routes, s)
	}
	var conflicts []string
	for s := range want {
		if d.routes[s] {
			continue
		}
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			return err
		}
		if iface, clash := d.routeConflict(pfx); clash {
			conflicts = append(conflicts, fmt.Sprintf("%s (already routed via %s)", s, iface))
			continue
		}
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: d.link.Attrs().Index, Dst: prefixToIPNet(pfx)}); err != nil {
			return fmt.Errorf("route add %s: %w", s, err)
		}
		d.routes[s] = true
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("subnet routes skipped, they collide with local networks: %s", strings.Join(conflicts, ", "))
	}
	return nil
}

func (d *linuxDevice) ApplyPeers(peers []PeerConfig) error {
	cfgs, err := toWGPeerConfigs(peers)
	if err != nil {
		return err
	}
	return d.wg.ConfigureDevice(linkName, wgtypes.Config{ReplacePeers: true, Peers: cfgs})
}

func (d *linuxDevice) SetPrivateKey(key wgtypes.Key) error {
	return d.wg.ConfigureDevice(linkName, wgtypes.Config{PrivateKey: &key})
}

func (d *linuxDevice) Peers() ([]PeerStatus, error) {
	dev, err := d.wg.Device(linkName)
	if err != nil {
		return nil, err
	}
	return toPeerStatuses(dev.Peers), nil
}

func (d *linuxDevice) Close() error {
	err := netlink.LinkDel(d.link)
	if cerr := d.wg.Close(); err == nil {
		err = cerr
	}
	return err
}
