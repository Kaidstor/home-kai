package coordinator

import (
	"fmt"
	"net/netip"
	"sort"
)

// normalizeRoutes validates subnet-router announcements: IPv4 CIDRs only, no
// default route (that would be an exit node, a different feature) and nothing
// overlapping the overlay itself. Returns the canonical (masked, sorted,
// deduplicated) form so string comparisons are meaningful.
func normalizeRoutes(routes []string, overlay netip.Prefix) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, r := range routes {
		pfx, err := netip.ParsePrefix(r)
		if err != nil {
			return nil, fmt.Errorf("bad route %q: %w", r, err)
		}
		if !pfx.Addr().Is4() {
			return nil, fmt.Errorf("route %q: only IPv4 subnets are supported", r)
		}
		if pfx.Bits() == 0 {
			return nil, fmt.Errorf("route %q: default route is not a subnet route", r)
		}
		if pfx.Overlaps(overlay) {
			return nil, fmt.Errorf("route %q overlaps the overlay %s", r, overlay)
		}
		c := pfx.Masked().String()
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out, nil
}
