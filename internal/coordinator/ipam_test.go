package coordinator

import (
	"net/netip"
	"testing"
)

func TestHubIP(t *testing.T) {
	cidr := netip.MustParsePrefix("100.87.0.0/16")
	if got := HubIP(cidr); got.String() != "100.87.0.1" {
		t.Fatalf("HubIP = %s, want 100.87.0.1", got)
	}
}

func TestAllocateIPSequential(t *testing.T) {
	cidr := netip.MustParsePrefix("100.87.0.0/16")
	used := map[string]bool{"100.87.0.1": true}
	ip, err := AllocateIP(cidr, used)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "100.87.0.2" {
		t.Fatalf("got %s, want 100.87.0.2", ip)
	}
	used[ip.String()] = true
	ip2, _ := AllocateIP(cidr, used)
	if ip2.String() != "100.87.0.3" {
		t.Fatalf("got %s, want 100.87.0.3", ip2)
	}
}

func TestAllocateIPExhausted(t *testing.T) {
	cidr := netip.MustParsePrefix("192.168.0.0/30") // hosts .1 .2 .3
	used := map[string]bool{"192.168.0.1": true, "192.168.0.2": true, "192.168.0.3": true}
	if _, err := AllocateIP(cidr, used); err == nil {
		t.Fatal("want exhaustion error")
	}
}
