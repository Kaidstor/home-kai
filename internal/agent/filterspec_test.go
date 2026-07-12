package agent

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/kaidstor/home-kai/internal/api"
)

func TestFilterChainSpecs(t *testing.T) {
	specs := filterChainSpecs([]api.FilterRule{
		{SrcCIDRs: []string{"100.87.0.3/32"}, Protocol: "tcp", Ports: []string{"22", "443"}},
		{SrcCIDRs: []string{"100.87.0.4/32"}, Protocol: "icmp"},
		{SrcCIDRs: []string{"100.87.0.5/32"}, Protocol: "any"},
	})
	want := [][]string{
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-s", "100.87.0.3/32", "-p", "tcp", "-m", "multiport", "--dports", "22,443", "-j", "ACCEPT"},
		{"-s", "100.87.0.4/32", "-p", "icmp", "-j", "ACCEPT"},
		{"-s", "100.87.0.5/32", "-j", "ACCEPT"},
		{"-j", "DROP"},
	}
	if !reflect.DeepEqual(specs, want) {
		t.Fatalf("specs:\n got %v\nwant %v", specs, want)
	}
}

// Multiport takes at most 15 ports per rule — larger sets are chunked.
func TestFilterChainSpecsChunksPorts(t *testing.T) {
	var ports []string
	for i := range 20 {
		ports = append(ports, fmt.Sprint(1000+i))
	}
	specs := filterChainSpecs([]api.FilterRule{{SrcCIDRs: []string{"10.0.0.0/8"}, Protocol: "udp", Ports: ports}})
	// conntrack + 2 chunks (15 + 5) + drop
	if len(specs) != 4 {
		t.Fatalf("want 4 specs, got %d: %v", len(specs), specs)
	}
}

func TestForwardChainSpecs(t *testing.T) {
	specs := forwardChainSpecs([]api.ForwardRule{{
		SrcCIDRs: []string{"100.87.0.3/32", "100.87.0.9/32"},
		DstCIDRs: []string{"100.87.0.2/32", "10.1.0.0/24"},
		Protocol: "tcp", Ports: []string{"443"},
	}})
	want := [][]string{
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-s", "100.87.0.3/32", "-d", "100.87.0.2/32", "-p", "tcp", "-m", "multiport", "--dports", "443", "-j", "ACCEPT"},
		{"-s", "100.87.0.3/32", "-d", "10.1.0.0/24", "-p", "tcp", "-m", "multiport", "--dports", "443", "-j", "ACCEPT"},
		{"-s", "100.87.0.9/32", "-d", "100.87.0.2/32", "-p", "tcp", "-m", "multiport", "--dports", "443", "-j", "ACCEPT"},
		{"-s", "100.87.0.9/32", "-d", "10.1.0.0/24", "-p", "tcp", "-m", "multiport", "--dports", "443", "-j", "ACCEPT"},
		{"-j", "DROP"},
	}
	if !reflect.DeepEqual(specs, want) {
		t.Fatalf("specs:\n got %v\nwant %v", specs, want)
	}
	// An unknown protocol compiles to no allow-rule at all (fail closed).
	specs = forwardChainSpecs([]api.ForwardRule{{SrcCIDRs: []string{"10.0.0.0/8"}, DstCIDRs: []string{"10.1.0.0/24"}, Protocol: "gre"}})
	if len(specs) != 2 { // conntrack + drop only
		t.Fatalf("unknown protocol must not compile: %v", specs)
	}
}

// Candidates from the coordinator are dial targets — only literal, routable
// ip:port is worth installing, and no more than maxCandidates.
func TestValidCandidates(t *testing.T) {
	in := []string{
		"nas.local:51820", "127.0.0.1:80", "0.0.0.0:1", "224.0.0.1:2", "10.0.0.5:0",
		"192.168.1.9:51820", "203.0.113.7:41641",
	}
	got := validCandidates(in)
	want := []string{"192.168.1.9:51820", "203.0.113.7:41641"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	var many []string
	for i := range 20 {
		many = append(many, fmt.Sprintf("10.0.0.%d:1000", i+1))
	}
	if got := validCandidates(many); len(got) != maxCandidates {
		t.Fatalf("cap: got %d", len(got))
	}
}
