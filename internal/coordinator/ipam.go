package coordinator

import (
	"errors"
	"fmt"
	"net/netip"
)

// HubHostOffset: the hub is always the first host in the overlay range.
const HubHostOffset = 1

// AllocateIP returns the lowest free host address in cidr, skipping the
// network address and everything in `used`. Sequential allocation is fine at
// homelab scale and keeps addresses human-readable.
func AllocateIP(cidr netip.Prefix, used map[string]bool) (netip.Addr, error) {
	if !cidr.Addr().Is4() {
		return netip.Addr{}, errors.New("ipam: only IPv4 overlays are supported")
	}
	network := cidr.Masked()
	addr := network.Addr().Next() // skip network address
	for network.Contains(addr) {
		if !used[addr.String()] {
			return addr, nil
		}
		addr = addr.Next()
	}
	return netip.Addr{}, fmt.Errorf("ipam: overlay %s exhausted", cidr)
}

// HubIP is the fixed address of the relay hub inside the overlay.
func HubIP(cidr netip.Prefix) netip.Addr {
	addr := cidr.Masked().Addr()
	for range HubHostOffset {
		addr = addr.Next()
	}
	return addr
}
