package coordinator

import (
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/coordinator/store"
	"github.com/kaidstor/home-kai/internal/wgkeys"
)

func TestNormalizeTagsAndPorts(t *testing.T) {
	got := normalizeTags([]string{"IT Dept", "  ", "it-dept", "AWS_Servers", "aws-servers"})
	if len(got) != 2 || got[0] != "aws-servers" || got[1] != "it-dept" {
		t.Fatalf("tags: %v", got)
	}
	if ps, err := normalizePorts([]string{"443", "22", "443"}); err != nil || len(ps) != 2 || ps[0] != "22" {
		t.Fatalf("ports: %v %v", ps, err)
	}
	if _, err := normalizePorts([]string{"70000"}); err == nil {
		t.Fatal("out-of-range port must fail")
	}
}

func TestACLFlow(t *testing.T) {
	ts := newTestServer(t)
	hub := enroll(t, ts, createToken(t, ts), api.RoleHub)
	web := enroll(t, ts, createToken(t, ts), api.RoleNode)   // 100.87.0.2 — destination
	it := enroll(t, ts, createToken(t, ts), api.RoleNode)    // 100.87.0.3 — allowed source
	other := enroll(t, ts, createToken(t, ts), api.RoleNode) // 100.87.0.4 — not allowed

	// No policies yet → filter is off everywhere.
	var nm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", web.AuthSecret, nil, &nm)
	if nm.Self.FilterEnabled {
		t.Fatal("filter must be off with no policies")
	}

	// Tag the devices.
	tag := func(id string, tags ...string) {
		if code := call(t, ts, "POST", "/v1/admin/nodes/"+id+"/tags", adminToken, api.TagsRequest{Tags: tags}, nil); code != 204 {
			t.Fatalf("tag %s: %d", id, code)
		}
	}
	tag(web.NodeID, "web")
	tag(it.NodeID, "it")
	// 'other' left untagged.

	// Policy: it → web on tcp/443.
	var pol api.Policy
	if code := call(t, ts, "POST", "/v1/admin/policies", adminToken, api.PolicyCreateRequest{
		Name: "it-to-web", SrcTags: []string{"it"}, DstTags: []string{"web"},
		Protocol: "tcp", Ports: []string{"443"}, Enabled: true,
	}, &pol); code != 200 {
		t.Fatalf("policy create: %d", code)
	}

	// web's netmap: filter on, one rule allowing it's /32 on tcp/443.
	call(t, ts, "GET", "/v1/netmap?since=0", web.AuthSecret, nil, &nm)
	if !nm.Self.FilterEnabled || len(nm.FilterRules) != 1 {
		t.Fatalf("web filter: enabled=%v rules=%+v", nm.Self.FilterEnabled, nm.FilterRules)
	}
	r := nm.FilterRules[0]
	if r.Protocol != "tcp" || len(r.Ports) != 1 || r.Ports[0] != "443" ||
		len(r.SrcCIDRs) != 1 || r.SrcCIDRs[0] != "100.87.0.3/32" {
		t.Fatalf("web rule: %+v", r)
	}

	// 'other' is a destination of no policy → filter on but zero rules (deny all inbound).
	var otherNm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", other.AuthSecret, nil, &otherNm)
	if !otherNm.Self.FilterEnabled || len(otherNm.FilterRules) != 0 {
		t.Fatalf("other must be default-deny: %+v", otherNm.FilterRules)
	}

	// Deleting the only policy turns the filter back off.
	if code := call(t, ts, "DELETE", "/v1/admin/policies/"+pol.ID, adminToken, nil, nil); code != 204 {
		t.Fatal("policy delete failed")
	}
	var afterNm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", web.AuthSecret, nil, &afterNm)
	if afterNm.Self.FilterEnabled {
		t.Fatal("filter must be off after deleting all policies")
	}
	_ = hub
}

// The hub's forward rules must cover everything it relays: nodes, static
// peers and enabled LAN subnets (which inherit the advertising node's tags).
// A subnet router gets rules only for its own enabled routes.
func TestComputeForwardRules(t *testing.T) {
	hub := store.Node{ID: "n_hub", Role: "hub", OverlayIP: "100.87.0.1"}
	web := store.Node{ID: "n_web", Role: "node", OverlayIP: "100.87.0.2",
		Tags: []string{"web"}, RoutesEnabled: []string{"10.1.0.0/24"}}
	it := store.Node{ID: "n_it", Role: "node", OverlayIP: "100.87.0.3", Tags: []string{"it"}}
	phone := store.StaticPeer{ID: "sp_1", OverlayIP: "100.87.0.9", Tags: []string{"it"}}
	nodes := []store.Node{hub, web, it}
	statics := []store.StaticPeer{phone}
	pols := []store.Policy{{
		SrcTags: []string{"it"}, DstTags: []string{"web"},
		Protocol: "tcp", Ports: []string{"443"}, Enabled: true,
	}}

	got := computeForwardRules(hub, nodes, statics, pols)
	want := []api.ForwardRule{{
		SrcCIDRs: []string{"100.87.0.3/32", "100.87.0.9/32"},
		DstCIDRs: []string{"10.1.0.0/24", "100.87.0.2/32"},
		Protocol: "tcp", Ports: []string{"443"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hub forward rules:\n got %+v\nwant %+v", got, want)
	}

	// The router filters only what it forwards into its own LAN.
	got = computeForwardRules(web, nodes, statics, pols)
	want = []api.ForwardRule{{
		SrcCIDRs: []string{"100.87.0.3/32", "100.87.0.9/32"},
		DstCIDRs: []string{"10.1.0.0/24"},
		Protocol: "tcp", Ports: []string{"443"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("router forward rules:\n got %+v\nwant %+v", got, want)
	}

	// A plain spoke forwards nothing.
	if got := computeForwardRules(it, nodes, statics, pols); got != nil {
		t.Fatalf("spoke must have no forward rules: %+v", got)
	}

	// Disabled policies compile to nothing.
	pols[0].Enabled = false
	if got := computeForwardRules(hub, nodes, statics, pols); got != nil {
		t.Fatalf("disabled policy must not compile: %+v", got)
	}

	// An open policy (no tags) covers static peers as destinations too.
	open := []store.Policy{{Protocol: "any", Enabled: true}}
	found := false
	for _, r := range computeForwardRules(hub, nodes, statics, open) {
		for _, d := range r.DstCIDRs {
			if d == "100.87.0.9/32" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("static peer must be a forward destination on the hub")
	}
}

func enrollOS(t *testing.T, ts *httptest.Server, token string, role api.NodeRole, osName string) api.EnrollResponse {
	t.Helper()
	pair, _ := wgkeys.Generate()
	var resp api.EnrollResponse
	code := call(t, ts, "POST", "/v1/enroll", token, api.EnrollRequest{
		Hostname: "host-" + osName, OS: osName, Role: role, WGPublicKey: pair.Public.String(),
	}, &resp)
	if code != 200 {
		t.Fatalf("enroll %s as %s: %d", osName, role, code)
	}
	return resp
}

// Non-Linux nodes cannot enforce the filter locally: while any policy is
// enabled they lose their p2p candidates in both directions, so their traffic
// relays via the hub — whose netmap carries the forward rules.
func TestACLForcesNonLinuxOntoHubRelay(t *testing.T) {
	ts := newTestServer(t)
	hub := enroll(t, ts, createToken(t, ts), api.RoleHub)
	lin := enroll(t, ts, createToken(t, ts), api.RoleNode)
	mac := enrollOS(t, ts, createToken(t, ts), api.RoleNode, "darwin")

	// Both spokes publish a LAN endpoint (p2p candidates).
	for _, n := range []api.EnrollResponse{lin, mac} {
		if code := call(t, ts, "POST", "/v1/status", n.AuthSecret,
			api.StatusReport{EndpointsLocal: []string{"192.168.1." + n.OverlayIP[len(n.OverlayIP)-1:] + ":51820"}}, nil); code != 204 {
			t.Fatalf("status: %d", code)
		}
	}

	candidatesFor := func(auth, peerIP string) []string {
		var nm api.Netmap
		call(t, ts, "GET", "/v1/netmap?since=0", auth, nil, &nm)
		for _, p := range nm.Peers {
			if p.OverlayIP == peerIP {
				return p.Candidates
			}
		}
		t.Fatalf("peer %s not in netmap", peerIP)
		return nil
	}

	// Open network: candidates flow in both directions.
	if len(candidatesFor(lin.AuthSecret, mac.OverlayIP)) == 0 {
		t.Fatal("open network: linux node must see mac candidates")
	}
	if len(candidatesFor(mac.AuthSecret, lin.OverlayIP)) == 0 {
		t.Fatal("open network: mac must see linux candidates")
	}

	// First enabled policy → mac is relay-only.
	if code := call(t, ts, "POST", "/v1/admin/policies", adminToken, api.PolicyCreateRequest{
		Name: "open", Enabled: true,
	}, nil); code != 200 {
		t.Fatal("policy create failed")
	}
	if got := candidatesFor(lin.AuthSecret, mac.OverlayIP); len(got) != 0 {
		t.Fatalf("ACL on: mac candidates must be withheld, got %v", got)
	}
	if got := candidatesFor(mac.AuthSecret, lin.OverlayIP); len(got) != 0 {
		t.Fatalf("ACL on: mac must not probe anyone, got %v", got)
	}

	// The hub enforces for those who can't: its netmap carries forward rules
	// with the mac node as a destination.
	var hubNm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &hubNm)
	if !hubNm.Self.FilterEnabled || len(hubNm.ForwardRules) == 0 {
		t.Fatalf("hub must get forward rules: enabled=%v rules=%+v", hubNm.Self.FilterEnabled, hubNm.ForwardRules)
	}
	found := false
	for _, r := range hubNm.ForwardRules {
		for _, d := range r.DstCIDRs {
			if d == mac.OverlayIP+"/32" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("mac must be a forward destination on the hub: %+v", hubNm.ForwardRules)
	}
	// Linux spokes keep their filter rules and don't get forward rules.
	var linNm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", lin.AuthSecret, nil, &linNm)
	if !linNm.Self.FilterEnabled || len(linNm.ForwardRules) != 0 {
		t.Fatalf("plain spoke: enabled=%v forward=%+v", linNm.Self.FilterEnabled, linNm.ForwardRules)
	}
}

// Static peers (phones) participate in ACL policies via tags, same as nodes.
func TestStaticPeerTags(t *testing.T) {
	ts := newTestServer(t)
	enroll(t, ts, createToken(t, ts), api.RoleHub)
	web := enroll(t, ts, createToken(t, ts), api.RoleNode) // 100.87.0.2 — destination

	var sp api.StaticPeerCreateResponse
	call(t, ts, "POST", "/v1/admin/static-peers", adminToken, api.StaticPeerCreateRequest{Name: "iphone"}, &sp)

	if code := call(t, ts, "POST", "/v1/admin/static-peers/"+sp.ID+"/tags", adminToken,
		api.TagsRequest{Tags: []string{"Phones"}}, nil); code != 204 {
		t.Fatalf("peer tag: %d", code)
	}
	var peers []api.StaticPeerInfo
	call(t, ts, "GET", "/v1/admin/static-peers", adminToken, nil, &peers)
	if len(peers) != 1 || len(peers[0].Tags) != 1 || peers[0].Tags[0] != "phones" {
		t.Fatalf("peer tags not normalized/listed: %+v", peers)
	}

	// Policy phones → web: the phone's /32 must land in web's filter rules.
	call(t, ts, "POST", "/v1/admin/nodes/"+web.NodeID+"/tags", adminToken, api.TagsRequest{Tags: []string{"web"}}, nil)
	call(t, ts, "POST", "/v1/admin/policies", adminToken, api.PolicyCreateRequest{
		Name: "phones-to-web", SrcTags: []string{"phones"}, DstTags: []string{"web"}, Enabled: true,
	}, nil)
	var nm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", web.AuthSecret, nil, &nm)
	if !nm.Self.FilterEnabled || len(nm.FilterRules) != 1 ||
		len(nm.FilterRules[0].SrcCIDRs) != 1 || nm.FilterRules[0].SrcCIDRs[0] != sp.OverlayIP+"/32" {
		t.Fatalf("phone must be an allowed source: %+v", nm.FilterRules)
	}

	// Unknown peer id → 404.
	if code := call(t, ts, "POST", "/v1/admin/static-peers/sp_nope/tags", adminToken,
		api.TagsRequest{Tags: []string{"x"}}, nil); code != 404 {
		t.Fatalf("tagging a ghost peer: %d", code)
	}
}
