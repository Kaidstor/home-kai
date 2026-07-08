package coordinator

import (
	"testing"

	"github.com/kaidstor/home-kai/internal/api"
)

func TestPeerApproval(t *testing.T) {
	ts, srv := newTestServerSrv(t)
	srv.cfg.RequireApproval = true

	// The hub is trusted implicitly even with approval on.
	hub := enroll(t, ts, createToken(t, ts), api.RoleHub)

	// A spoke enrolls but lands unapproved: it must not see the hub yet, and
	// nobody must see it.
	node := enroll(t, ts, createToken(t, ts), api.RoleNode)

	var nodes []api.NodeInfo
	call(t, ts, "GET", "/v1/admin/nodes", adminToken, nil, &nodes)
	var pendingSeen bool
	for _, n := range nodes {
		if n.NodeID == node.NodeID {
			pendingSeen = true
			if n.Approved {
				t.Fatal("new node must be unapproved")
			}
		}
	}
	if !pendingSeen {
		t.Fatal("pending node missing from admin list")
	}

	// The hub's netmap must not include the pending node.
	var hubNm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &hubNm)
	for _, p := range hubNm.Peers {
		if p.NodeID == node.NodeID {
			t.Fatal("pending node leaked into hub netmap")
		}
	}

	// Approve, then the hub sees it.
	if code := call(t, ts, "POST", "/v1/admin/nodes/"+node.NodeID+"/approve", adminToken, nil, nil); code != 204 {
		t.Fatalf("approve: %d", code)
	}
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &hubNm)
	found := false
	for _, p := range hubNm.Peers {
		if p.NodeID == node.NodeID {
			found = true
		}
	}
	if !found {
		t.Fatal("approved node must appear in hub netmap")
	}
}

func TestEventsLogged(t *testing.T) {
	ts := newTestServer(t)
	enroll(t, ts, createToken(t, ts), api.RoleHub)
	call(t, ts, "POST", "/v1/admin/static-peers", adminToken, api.StaticPeerCreateRequest{Name: "iphone"}, nil)

	var evs []api.Event
	call(t, ts, "GET", "/v1/admin/events?limit=10", adminToken, nil, &evs)
	if len(evs) < 2 {
		t.Fatalf("expected enroll + peer events, got %d", len(evs))
	}
	// Newest first.
	if evs[0].Kind != "peer.create" {
		t.Fatalf("newest event: %+v", evs[0])
	}
	kinds := map[string]bool{}
	for _, e := range evs {
		kinds[e.Kind] = true
	}
	if !kinds["node.enroll"] {
		t.Fatalf("enroll event missing: %+v", evs)
	}
}
