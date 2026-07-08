package coordinator

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/wgkeys"
)

func TestNormalizeRoutes(t *testing.T) {
	overlay := netip.MustParsePrefix("100.87.0.0/16")
	got, err := normalizeRoutes([]string{"192.168.1.5/24", "172.18.0.0/16", "192.168.1.0/24"}, overlay)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "172.18.0.0/16" || got[1] != "192.168.1.0/24" {
		t.Fatalf("normalized: %v", got)
	}
	for _, bad := range []string{"0.0.0.0/0", "100.87.1.0/24", "fd00::/64", "not-a-cidr"} {
		if _, err := normalizeRoutes([]string{bad}, overlay); err == nil {
			t.Fatalf("route %q must be rejected", bad)
		}
	}
}

func TestSubnetRoutes(t *testing.T) {
	ts := newTestServer(t)
	hub := enroll(t, ts, createToken(t, ts), api.RoleHub)
	router := enroll(t, ts, createToken(t, ts), api.RoleNode) // advertises a subnet
	client := enroll(t, ts, createToken(t, ts), api.RoleNode) // consumes it

	// The router node advertises two subnets via its status report.
	if code := call(t, ts, "POST", "/v1/status", router.AuthSecret, api.StatusReport{
		AdvertisedRoutes: []string{"172.18.0.0/16", "192.168.50.0/24"},
	}, nil); code != 204 {
		t.Fatalf("status: %d", code)
	}

	// Advertising alone must not touch any netmap (peer 0 is always the hub).
	var nm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", client.AuthSecret, nil, &nm)
	if len(nm.Peers) != 2 || len(nm.Peers[0].AllowedIPs) != 1 {
		t.Fatalf("advertised-but-not-enabled leaked into netmap: %+v", nm.Peers)
	}
	baseVersion := nm.Version

	// Enabling a route that was never advertised is a conflict.
	if code := call(t, ts, "POST", "/v1/admin/nodes/"+router.NodeID+"/routes", adminToken,
		api.NodeRoutesRequest{Enabled: []string{"10.0.0.0/8"}}, nil); code != 409 {
		t.Fatalf("enabling unadvertised route: %d", code)
	}

	// Enable one advertised route.
	if code := call(t, ts, "POST", "/v1/admin/nodes/"+router.NodeID+"/routes", adminToken,
		api.NodeRoutesRequest{Enabled: []string{"172.18.0.0/16"}}, nil); code != 204 {
		t.Fatalf("enable: %d", code)
	}

	// Hub: the subnet rides on the router's peer entry.
	var hubNm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &hubNm)
	var routerPeer *api.Peer
	for i := range hubNm.Peers {
		if hubNm.Peers[i].NodeID == router.NodeID {
			routerPeer = &hubNm.Peers[i]
		}
	}
	if routerPeer == nil || len(routerPeer.AllowedIPs) != 2 || routerPeer.AllowedIPs[1] != "172.18.0.0/16" {
		t.Fatalf("hub netmap router peer: %+v", routerPeer)
	}

	// Client spoke: the subnet is reachable via the hub peer; netmap bumped.
	call(t, ts, "GET", "/v1/netmap?since=0", client.AuthSecret, nil, &nm)
	if nm.Version <= baseVersion {
		t.Fatalf("netmap version not bumped: %d", nm.Version)
	}
	if len(nm.Peers[0].AllowedIPs) != 2 || nm.Peers[0].AllowedIPs[1] != "172.18.0.0/16" {
		t.Fatalf("client hub peer allowed: %+v", nm.Peers[0].AllowedIPs)
	}

	// The router itself must NOT get its own subnet routed into the tunnel.
	var routerNm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", router.AuthSecret, nil, &routerNm)
	if len(routerNm.Peers[0].AllowedIPs) != 1 {
		t.Fatalf("router's own subnet leaked into its netmap: %+v", routerNm.Peers[0].AllowedIPs)
	}

	// A second node may not serve the same prefix.
	if code := call(t, ts, "POST", "/v1/status", client.AuthSecret, api.StatusReport{
		AdvertisedRoutes: []string{"172.18.0.0/16"},
	}, nil); code != 204 {
		t.Fatal("client advertise failed")
	}
	if code := call(t, ts, "POST", "/v1/admin/nodes/"+client.NodeID+"/routes", adminToken,
		api.NodeRoutesRequest{Enabled: []string{"172.18.0.0/16"}}, nil); code != 409 {
		t.Fatalf("duplicate prefix must be 409, got %d", code)
	}

	// Router stops advertising the enabled subnet → it drops out of netmaps.
	call(t, ts, "GET", "/v1/netmap?since=0", client.AuthSecret, nil, &nm)
	v := nm.Version
	if code := call(t, ts, "POST", "/v1/status", router.AuthSecret, api.StatusReport{}, nil); code != 204 {
		t.Fatal("empty advertise failed")
	}
	call(t, ts, "GET", "/v1/netmap?since=0", client.AuthSecret, nil, &nm)
	if nm.Version <= v || len(nm.Peers[0].AllowedIPs) != 1 {
		t.Fatalf("retracted route still in netmap: v%d %+v", nm.Version, nm.Peers[0].AllowedIPs)
	}

	// Node list exposes both advertised and enabled sets.
	var nodes []api.NodeInfo
	call(t, ts, "GET", "/v1/admin/nodes", adminToken, nil, &nodes)
	for _, n := range nodes {
		if n.NodeID == client.NodeID && (len(n.RoutesAdvertised) != 1 || len(n.RoutesEnabled) != 0) {
			t.Fatalf("node list routes: %+v", n)
		}
	}
}

func TestNetmapHosts(t *testing.T) {
	ts := newTestServer(t)
	hub := enroll(t, ts, createToken(t, ts), api.RoleHub)
	enroll(t, ts, createToken(t, ts), api.RoleNode)
	call(t, ts, "POST", "/v1/admin/static-peers", adminToken,
		api.StaticPeerCreateRequest{Name: "Kai's iPhone"}, nil)

	var nm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &nm)
	if len(nm.Hosts) != 3 {
		t.Fatalf("hosts: %+v", nm.Hosts)
	}
	byName := map[string]string{}
	for _, h := range nm.Hosts {
		byName[h.Name] = h.IP
	}
	// Both enroll() nodes are named host-hub / host-node; the static peer name
	// must be sanitized into a DNS label.
	if byName["host-hub.kai"] != "100.87.0.1" || byName["kai-s-iphone.kai"] == "" {
		t.Fatalf("hosts: %+v", nm.Hosts)
	}
}

func TestSanitizeHostLabel(t *testing.T) {
	for in, want := range map[string]string{
		"MacBook-Pro-Kaidstor.local": "macbook-pro-kaidstor-local",
		"  ...  ":                    "device",
		"HELSINKI-S3-XHTTP":          "helsinki-s3-xhttp",
	} {
		if got := sanitizeHostLabel(in); got != want {
			t.Fatalf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStaticPeerFullTunnel(t *testing.T) {
	ts := newTestServer(t)
	enroll(t, ts, createToken(t, ts), api.RoleHub)

	var created api.StaticPeerCreateResponse
	if code := call(t, ts, "POST", "/v1/admin/static-peers", adminToken,
		api.StaticPeerCreateRequest{Name: "phone", Full: true}, &created); code != 200 {
		t.Fatalf("create: %d", code)
	}
	if !strings.Contains(created.ConfINI, "AllowedIPs = 0.0.0.0/0") ||
		!strings.Contains(created.ConfINI, "DNS = 1.1.1.1") {
		t.Fatalf("full conf:\n%s", created.ConfINI)
	}

	// The same peer re-renders in either mode.
	var conf api.StaticPeerConfigResponse
	call(t, ts, "GET", "/v1/admin/static-peers/"+created.ID+"/config?full=1", adminToken, nil, &conf)
	if conf.ConfINI != created.ConfINI {
		t.Fatalf("full re-render differs:\n%s\nvs\n%s", conf.ConfINI, created.ConfINI)
	}
	call(t, ts, "GET", "/v1/admin/static-peers/"+created.ID+"/config", adminToken, nil, &conf)
	if !strings.Contains(conf.ConfINI, "AllowedIPs = 100.87.0.0/16") || strings.Contains(conf.ConfINI, "DNS =") {
		t.Fatalf("split conf:\n%s", conf.ConfINI)
	}
}

func TestRekey(t *testing.T) {
	ts := newTestServer(t)
	hub := enroll(t, ts, createToken(t, ts), api.RoleHub)
	node := enroll(t, ts, createToken(t, ts), api.RoleNode)

	var before api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &before)

	// Re-asserting the current key is a silent no-op.
	var nodes []api.NodeInfo
	call(t, ts, "GET", "/v1/admin/nodes", adminToken, nil, &nodes)
	var cur string
	for _, n := range nodes {
		if n.NodeID == node.NodeID {
			for _, p := range before.Peers {
				if p.NodeID == node.NodeID {
					cur = p.WGPublicKey
				}
			}
		}
	}
	if code := call(t, ts, "POST", "/v1/rekey", node.AuthSecret, api.RekeyRequest{WGPublicKey: cur}, nil); code != 204 {
		t.Fatalf("noop rekey: %d", code)
	}
	var same api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &same)
	if same.Version != before.Version {
		t.Fatal("noop rekey must not bump the netmap")
	}

	// A fresh key replaces the old one and bumps.
	pair, _ := wgkeys.Generate()
	if code := call(t, ts, "POST", "/v1/rekey", node.AuthSecret, api.RekeyRequest{WGPublicKey: pair.Public.String()}, nil); code != 204 {
		t.Fatal("rekey failed")
	}
	var after api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &after)
	if after.Version <= before.Version {
		t.Fatal("rekey must bump the netmap")
	}
	found := false
	for _, p := range after.Peers {
		if p.NodeID == node.NodeID && p.WGPublicKey == pair.Public.String() {
			found = true
		}
	}
	if !found {
		t.Fatalf("new key not in netmap: %+v", after.Peers)
	}
	if code := call(t, ts, "POST", "/v1/rekey", node.AuthSecret, api.RekeyRequest{WGPublicKey: "garbage"}, nil); code != 400 {
		t.Fatal("bad key must be 400")
	}
}
