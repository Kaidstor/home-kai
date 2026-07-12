package coordinator

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/coordinator/store"
	"github.com/kaidstor/home-kai/internal/text"
)

// ACL policies. Nodes and static peers carry tags; a policy allows traffic
// from any device tagged with a SrcTag to any device tagged with a DstTag on
// a protocol/port set. The coordinator compiles policies into per-node
// inbound allow-rules (FilterRules) and ships them in the netmap; each Linux
// agent enforces them on its overlay interface. As soon as one policy exists
// the network is default-deny for overlay app traffic; with zero policies the
// filter stays off (open network, backward compatible).
//
// Destinations that cannot enforce their own inbound filter are covered in
// the FORWARD path instead (ForwardRules): the hub filters everything it
// relays (static peers, spoke↔spoke relay, subnets reached through it) and a
// subnet router filters traffic it forwards into its LAN. A LAN subnet
// inherits the tags of the node advertising it. Non-Linux nodes cannot
// enforce locally, so while any policy is enabled the coordinator withholds
// their p2p candidates — their traffic is forced through the hub, where the
// forward filter applies.

var validProtocols = map[string]bool{"any": true, "tcp": true, "udp": true, "icmp": true}

// normalizeTags slugs, dedups and sorts tag labels to [a-z0-9-], dropping
// anything that reduces to empty.
func normalizeTags(tags []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range tags {
		label := text.Slug(t)
		if label == "" || seen[label] {
			continue
		}
		seen[label] = true
		out = append(out, label)
	}
	sort.Strings(out)
	return out
}

// normalizePorts validates 1..65535 ports (single values), dedups and sorts.
func normalizePorts(ports []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, p := range ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("bad port %q", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := strconv.Atoi(out[i])
		b, _ := strconv.Atoi(out[j])
		return a < b
	})
	return out, nil
}

func intersects(a, b []string) bool {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, y := range b {
		if set[y] {
			return true
		}
	}
	return false
}

// tagsOf returns the tag set of a device; empty SrcTags/DstTags in a policy
// match anything, which matchTag handles.
func matchTag(policyTags, deviceTags []string) bool {
	if len(policyTags) == 0 {
		return true // "any"
	}
	return intersects(policyTags, deviceTags)
}

// aclDev is one policy participant: a node, a static peer or an advertised
// LAN subnet (which inherits the tags of its advertising node).
type aclDev struct {
	cidr string
	tags []string
}

func aclSources(nodes []store.Node, statics []store.StaticPeer) []aclDev {
	var out []aclDev
	for _, n := range nodes {
		out = append(out, aclDev{n.OverlayIP + "/32", n.Tags})
	}
	for _, p := range statics {
		out = append(out, aclDev{p.OverlayIP + "/32", p.Tags})
	}
	return out
}

// policySources collects the source CIDRs one enabled policy grants access
// from, excluding the destination itself (a device never needs a rule to
// reach itself).
func policySources(pol store.Policy, sources []aclDev, dstCIDR string) []string {
	var out []string
	for _, s := range sources {
		if s.cidr == dstCIDR {
			continue
		}
		if matchTag(pol.SrcTags, s.tags) {
			out = append(out, s.cidr)
		}
	}
	sort.Strings(out)
	return out
}

// computeFilterRules builds the inbound allow-rules for one destination node
// from the enabled policies. Returns nil when there are no policies (filter
// stays off).
func computeFilterRules(dst store.Node, nodes []store.Node, statics []store.StaticPeer, policies []store.Policy) []api.FilterRule {
	sources := aclSources(nodes, statics)
	var rules []api.FilterRule
	for _, pol := range policies {
		if !pol.Enabled || !matchTag(pol.DstTags, dst.Tags) {
			continue
		}
		srcCIDRs := policySources(pol, sources, dst.OverlayIP+"/32")
		if len(srcCIDRs) == 0 {
			continue
		}
		rules = append(rules, api.FilterRule{SrcCIDRs: srcCIDRs, Protocol: pol.Protocol, Ports: pol.Ports})
	}
	return rules
}

// computeForwardRules builds the allow-rules for traffic `self` forwards on
// behalf of others. The hub filters everything it relays: other nodes, static
// peers and every enabled subnet. A subnet router filters what it forwards
// into its own enabled LANs. Destinations enforcing their own inbound filter
// are still listed on the hub — relayed traffic is then checked twice, which
// keeps the semantics identical on both paths.
func computeForwardRules(self store.Node, nodes []store.Node, statics []store.StaticPeer, policies []store.Policy) []api.ForwardRule {
	var dsts []aclDev
	if self.Role == string(api.RoleHub) {
		for _, n := range nodes {
			if n.ID == self.ID {
				continue // traffic to the hub itself goes through its INPUT filter
			}
			dsts = append(dsts, aclDev{n.OverlayIP + "/32", n.Tags})
			for _, rt := range n.RoutesEnabled {
				dsts = append(dsts, aclDev{rt, n.Tags})
			}
		}
		for _, p := range statics {
			dsts = append(dsts, aclDev{p.OverlayIP + "/32", p.Tags})
		}
	}
	// Own enabled subnets: the advertising node forwards into them (this also
	// covers a hub that is a subnet router itself).
	for _, rt := range self.RoutesEnabled {
		dsts = append(dsts, aclDev{rt, self.Tags})
	}

	sources := aclSources(nodes, statics)
	var rules []api.ForwardRule
	for _, pol := range policies {
		if !pol.Enabled {
			continue
		}
		// Group destinations sharing the same source set into one rule: for a
		// given policy the set only differs by the self-exclusion.
		bySrc := map[string][]string{}
		var order []string
		for _, dst := range dsts {
			if !matchTag(pol.DstTags, dst.tags) {
				continue
			}
			srcs := policySources(pol, sources, dst.cidr)
			if len(srcs) == 0 {
				continue
			}
			key := strings.Join(srcs, ",")
			if _, seen := bySrc[key]; !seen {
				order = append(order, key)
			}
			bySrc[key] = append(bySrc[key], dst.cidr)
		}
		for _, key := range order {
			dstCIDRs := bySrc[key]
			sort.Strings(dstCIDRs)
			rules = append(rules, api.ForwardRule{
				SrcCIDRs: strings.Split(key, ","), DstCIDRs: dstCIDRs,
				Protocol: pol.Protocol, Ports: pol.Ports,
			})
		}
	}
	return rules
}

// --- admin handlers ---

func (s *Server) handlePolicyCreate(w http.ResponseWriter, r *http.Request) {
	var req api.PolicyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	proto := req.Protocol
	if proto == "" {
		proto = "any"
	}
	if !validProtocols[proto] {
		writeErr(w, http.StatusBadRequest, "protocol must be any|tcp|udp|icmp")
		return
	}
	ports, err := normalizePorts(req.Ports)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(ports) > 0 && (proto == "any" || proto == "icmp") {
		writeErr(w, http.StatusBadRequest, "ports require protocol tcp or udp")
		return
	}
	id, err := randomHex(8)
	if err != nil {
		s.errInternal(w, err)
		return
	}
	pol := store.Policy{
		ID: "pol_" + id, Name: req.Name,
		SrcTags: normalizeTags(req.SrcTags), DstTags: normalizeTags(req.DstTags),
		Protocol: proto, Ports: ports, Enabled: req.Enabled, CreatedAt: time.Now(),
	}
	if err := s.store.CreatePolicy(pol); err != nil {
		s.errInternal(w, err)
		return
	}
	if _, err := s.bumpNetmap(); err != nil {
		s.errInternal(w, err)
		return
	}
	s.logEvent(evPolicyCreate, "admin", fmt.Sprintf("политика %q: %s → %s (%s)",
		pol.Name, text.JoinOr(pol.SrcTags, "любой"), text.JoinOr(pol.DstTags, "любой"), protoPorts(pol.Protocol, pol.Ports)))
	writeJSON(w, http.StatusOK, toAPIPolicy(pol))
}

func (s *Server) handlePolicyList(w http.ResponseWriter, r *http.Request) {
	pols, err := s.store.Policies()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	out := make([]api.Policy, 0, len(pols))
	for _, p := range pols {
		out = append(out, toAPIPolicy(p))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePolicyDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeletePolicy(id); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such policy")
		return
	} else if err != nil {
		s.errInternal(w, err)
		return
	}
	if _, err := s.bumpNetmap(); err != nil {
		s.errInternal(w, err)
		return
	}
	s.logEvent(evPolicyDelete, "admin", "политика удалена")
	w.WriteHeader(http.StatusNoContent)
}

func toAPIPolicy(p store.Policy) api.Policy {
	return api.Policy{
		ID: p.ID, Name: p.Name, SrcTags: p.SrcTags, DstTags: p.DstTags,
		Protocol: p.Protocol, Ports: p.Ports, Enabled: p.Enabled, CreatedAt: p.CreatedAt,
	}
}

func protoPorts(proto string, ports []string) string {
	if len(ports) == 0 {
		return proto
	}
	return proto + " " + strings.Join(ports, ",")
}
