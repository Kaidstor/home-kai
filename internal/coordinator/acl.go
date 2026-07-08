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

// computeFilterRules builds the inbound allow-rules for one destination node
// from the enabled policies. Returns nil when there are no policies (filter
// stays off).
func computeFilterRules(dst store.Node, nodes []store.Node, statics []store.StaticPeer, policies []store.Policy) []api.FilterRule {
	type dev struct {
		ip   string
		tags []string
	}
	var sources []dev
	for _, n := range nodes {
		sources = append(sources, dev{n.OverlayIP, n.Tags})
	}
	for _, p := range statics {
		sources = append(sources, dev{p.OverlayIP, p.Tags})
	}

	var rules []api.FilterRule
	for _, pol := range policies {
		if !pol.Enabled || !matchTag(pol.DstTags, dst.Tags) {
			continue
		}
		var srcCIDRs []string
		for _, s := range sources {
			if s.ip == dst.OverlayIP {
				continue // a node never needs a rule to reach itself
			}
			if matchTag(pol.SrcTags, s.tags) {
				srcCIDRs = append(srcCIDRs, s.ip+"/32")
			}
		}
		if len(srcCIDRs) == 0 {
			continue
		}
		sort.Strings(srcCIDRs)
		rules = append(rules, api.FilterRule{SrcCIDRs: srcCIDRs, Protocol: pol.Protocol, Ports: pol.Ports})
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
	if err := s.bumpNetmap(); err != nil {
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
	if err := s.bumpNetmap(); err != nil {
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
