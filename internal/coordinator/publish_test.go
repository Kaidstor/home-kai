package coordinator

import (
	"testing"

	"github.com/kaidstor/home-kai/internal/api"
)

func TestPublishLifecycle(t *testing.T) {
	ts := newTestServer(t)
	hub := enroll(t, ts, createToken(t, ts), api.RoleHub)
	spoke := enroll(t, ts, createToken(t, ts), api.RoleNode)

	// Validation: reserved port, bad target, target outside overlay.
	for _, req := range []api.PublishCreateRequest{
		{Name: "x", ListenPort: 8443, Target: "100.87.0.2:80"},
		{Name: "x", ListenPort: 8080, Target: "not-a-target"},
		{Name: "x", ListenPort: 8080, Target: "10.0.0.5:80"},
		{Name: "x", ListenPort: 8080, Target: "example.com:80"},
	} {
		if code := call(t, ts, "POST", "/v1/admin/publishes", adminToken, req, nil); code < 400 {
			t.Fatalf("bad publish %+v accepted: %d", req, code)
		}
	}

	var pub api.Publish
	if code := call(t, ts, "POST", "/v1/admin/publishes", adminToken,
		api.PublishCreateRequest{Name: "jelly", ListenPort: 8096, Target: "100.87.0.2:8096"}, &pub); code != 200 {
		t.Fatalf("create: %d", code)
	}
	// Same port again → conflict.
	if code := call(t, ts, "POST", "/v1/admin/publishes", adminToken,
		api.PublishCreateRequest{Name: "other", ListenPort: 8096, Target: "100.87.0.2:1"}, nil); code != 409 {
		t.Fatal("duplicate port must be 409")
	}

	// Only the hub netmap carries publishes.
	var nm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &nm)
	if len(nm.Publishes) != 1 || nm.Publishes[0].ListenPort != 8096 {
		t.Fatalf("hub publishes: %+v", nm.Publishes)
	}
	var spokeNm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", spoke.AuthSecret, nil, &spokeNm)
	if len(spokeNm.Publishes) != 0 {
		t.Fatalf("spoke must not see publishes: %+v", spokeNm.Publishes)
	}

	var list []api.Publish
	call(t, ts, "GET", "/v1/admin/publishes", adminToken, nil, &list)
	if len(list) != 1 || list[0].ID != pub.ID {
		t.Fatalf("list: %+v", list)
	}

	if code := call(t, ts, "DELETE", "/v1/admin/publishes/"+pub.ID, adminToken, nil, nil); code != 204 {
		t.Fatal("delete failed")
	}
	var afterNm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &afterNm)
	if len(afterNm.Publishes) != 0 {
		t.Fatalf("publish survived delete: %+v", afterNm.Publishes)
	}
}
