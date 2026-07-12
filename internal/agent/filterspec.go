package agent

// Pure builders of the iptables rule bodies for the ACL chains. Kept free of
// build tags so the compilation from netmap rules to iptables arguments is
// unit-testable on every platform, even though only the Linux agent applies
// the result.

import (
	"slices"
	"strings"

	"github.com/kaidstor/home-kai/internal/api"
)

// protoPortArgs expands one protocol/ports pair into iptables matcher
// suffixes. Multiport takes a comma list of at most 15 ports — larger sets
// are chunked into several rules. An unknown protocol yields no matcher at
// all: the chain's DROP tail then applies.
func protoPortArgs(protocol string, ports []string) [][]string {
	switch protocol {
	case "", "any":
		return [][]string{nil}
	case "icmp":
		return [][]string{{"-p", "icmp"}}
	case "tcp", "udp":
		if len(ports) == 0 {
			return [][]string{{"-p", protocol}}
		}
		var out [][]string
		for chunk := range slices.Chunk(ports, 15) {
			out = append(out, []string{"-p", protocol, "-m", "multiport", "--dports", strings.Join(chunk, ",")})
		}
		return out
	default:
		return nil
	}
}

// filterChainSpecs are the rule bodies (`iptables -A <chain> ...` arguments)
// of the inbound ACL chain: established flows pass, then the compiled
// allow-rules, then everything else is dropped.
func filterChainSpecs(rules []api.FilterRule) [][]string {
	specs := [][]string{{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}}
	for _, rule := range rules {
		for _, src := range rule.SrcCIDRs {
			for _, pp := range protoPortArgs(rule.Protocol, rule.Ports) {
				spec := append([]string{"-s", src}, pp...)
				specs = append(specs, append(spec, "-j", "ACCEPT"))
			}
		}
	}
	return append(specs, []string{"-j", "DROP"})
}

// forwardChainSpecs are the rule bodies of the forward ACL chain — traffic
// this node forwards for other devices (hub relay, subnet router), matched on
// both source and destination.
func forwardChainSpecs(rules []api.ForwardRule) [][]string {
	specs := [][]string{{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}}
	for _, rule := range rules {
		for _, src := range rule.SrcCIDRs {
			for _, dst := range rule.DstCIDRs {
				for _, pp := range protoPortArgs(rule.Protocol, rule.Ports) {
					spec := append([]string{"-s", src, "-d", dst}, pp...)
					specs = append(specs, append(spec, "-j", "ACCEPT"))
				}
			}
		}
	}
	return append(specs, []string{"-j", "DROP"})
}
