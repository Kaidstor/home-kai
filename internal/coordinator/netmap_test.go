package coordinator

import (
	"net/netip"
	"testing"

	"github.com/kaidstor/home-kai/internal/coordinator/store"
)

var (
	testCIDR = netip.MustParsePrefix("100.87.0.0/16")
	hubNode  = store.Node{ID: "n_hub", Name: "vps", Role: "hub", WGPubKey: "HUBKEY", OverlayIP: "100.87.0.1"}
	spoke    = store.Node{ID: "n_1", Name: "srv", Role: "node", WGPubKey: "SRVKEY", OverlayIP: "100.87.0.2"}
	spoke2   = store.Node{ID: "n_2", Name: "mac", Role: "node", WGPubKey: "MACKEY", OverlayIP: "100.87.0.4"}
	static   = store.StaticPeer{ID: "sp_1", Name: "iphone", WGPubKey: "SPKEY", OverlayIP: "100.87.0.3"}
)

func TestBuildNetmapSpoke(t *testing.T) {
	cands := map[string][]string{"n_2": {"192.168.1.7:51820", "203.0.113.5:12345"}}
	nm, err := BuildNetmap(spoke, []store.Node{hubNode, spoke, spoke2}, []store.StaticPeer{static},
		cands, nil, "", testCIDR, "vps.example.com:51820", 1420, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(nm.Peers) != 2 {
		t.Fatalf("spoke must see hub + other spoke, got %d peers", len(nm.Peers))
	}
	p := nm.Peers[0]
	if p.WGPublicKey != "HUBKEY" || p.Endpoint != "vps.example.com:51820" {
		t.Fatalf("bad hub peer: %+v", p)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "100.87.0.0/16" {
		t.Fatalf("spoke must route the whole overlay to the hub, got %v", p.AllowedIPs)
	}
	if p.KeepaliveSec != KeepaliveSec {
		t.Fatalf("keepalive missing: %+v", p)
	}
	// The other spoke: no endpoint, /32, candidates for the prober; static
	// peers never appear in a spoke netmap.
	d := nm.Peers[1]
	if d.WGPublicKey != "MACKEY" || d.Endpoint != "" ||
		len(d.AllowedIPs) != 1 || d.AllowedIPs[0] != "100.87.0.4/32" ||
		len(d.Candidates) != 2 || d.Candidates[0] != "192.168.1.7:51820" {
		t.Fatalf("bad direct peer: %+v", d)
	}
	if len(nm.Hosts) != 4 {
		t.Fatalf("hosts: %+v", nm.Hosts)
	}
}

func TestBuildNetmapHub(t *testing.T) {
	nm, err := BuildNetmap(hubNode, []store.Node{hubNode, spoke}, []store.StaticPeer{static},
		nil, nil, "", testCIDR, "vps.example.com:51820", 1420, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(nm.Peers) != 2 {
		t.Fatalf("hub must see spoke + static, got %d", len(nm.Peers))
	}
	for _, p := range nm.Peers {
		if p.Endpoint != "" {
			t.Fatalf("hub peers dial in, endpoint must be empty: %+v", p)
		}
		if len(p.AllowedIPs) != 1 || p.AllowedIPs[0][len(p.AllowedIPs[0])-3:] != "/32" {
			t.Fatalf("hub peer must be a /32: %+v", p)
		}
	}
}

func TestBuildNetmapNoHub(t *testing.T) {
	if _, err := BuildNetmap(spoke, []store.Node{spoke}, nil, nil, nil, "", testCIDR, "", 1420, 1); err == nil {
		t.Fatal("want error when no hub is enrolled")
	}
}
