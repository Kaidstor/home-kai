package coordinator

import (
	"testing"

	"github.com/kaidstor/home-kai/internal/api"
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
