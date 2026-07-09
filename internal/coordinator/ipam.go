package coordinator

import (
	"errors"
	"fmt"
	"net/netip"
)

// HubHostOffset: the hub is always the first host in the overlay range.
const HubHostOffset = 1

// AllocateIP returns the lowest free host address in cidr, skipping the
// network and broadcast addresses and everything in `used`. Sequential
// allocation is fine at homelab scale and keeps addresses human-readable.
func AllocateIP(cidr netip.Prefix, used map[string]bool) (netip.Addr, error) {
	if !cidr.Addr().Is4() {
		return netip.Addr{}, errors.New("ipam: only IPv4 overlays are supported")
	}
	network := cidr.Masked()
	broadcast := broadcastAddr(network)
	addr := network.Addr().Next() // skip network address
	for network.Contains(addr) && addr != broadcast {
		if !used[addr.String()] {
			return addr, nil
		}
		addr = addr.Next()
	}
	return netip.Addr{}, fmt.Errorf("ipam: overlay %s exhausted", cidr)
}

// broadcastAddr is the highest address of an IPv4 prefix (all host bits set).
func broadcastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	for i := p.Bits(); i < 32; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	return netip.AddrFrom4(b)
}

// allocateIP hands out the next free overlay address, keeping the hub's fixed
// address reserved even before the hub enrolls.
func (s *Server) allocateIP() (netip.Addr, error) {
	used, err := s.store.AllocatedIPs()
	if err != nil {
		return netip.Addr{}, err
	}
	used[HubIP(s.cfg.OverlayCIDR).String()] = true
	return AllocateIP(s.cfg.OverlayCIDR, used)
}

// HubIP is the fixed address of the relay hub inside the overlay.
func HubIP(cidr netip.Prefix) netip.Addr {
	addr := cidr.Masked().Addr()
	for range HubHostOffset {
		addr = addr.Next()
	}
	return addr
}
