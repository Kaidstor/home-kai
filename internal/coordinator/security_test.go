package coordinator

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/wgkeys"
)

// An enroll token must survive anything short of a successful enrollment:
// malformed JSON, a bad key, a role conflict.
func TestEnrollTokenSurvivesFailedRequests(t *testing.T) {
	ts := newTestServer(t)
	enroll(t, ts, createToken(t, ts), api.RoleHub)
	token := createToken(t, ts)

	// Truly malformed body.
	req, _ := http.NewRequest("POST", ts.URL+"/v1/enroll", strings.NewReader("{not json"))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("bad json: %d", resp.StatusCode)
	}

	// Garbage key, then a hub conflict.
	if code := call(t, ts, "POST", "/v1/enroll", token,
		api.EnrollRequest{Hostname: "x", WGPublicKey: "garbage"}, nil); code != 400 {
		t.Fatalf("bad key: %d", code)
	}
	pair, _ := wgkeys.Generate()
	if code := call(t, ts, "POST", "/v1/enroll", token,
		api.EnrollRequest{Hostname: "hub2", Role: api.RoleHub, WGPublicKey: pair.Public.String()}, nil); code != 409 {
		t.Fatalf("second hub: %d", code)
	}

	// After all those failures the token still enrolls a node.
	enroll(t, ts, token, api.RoleNode)
}

// Reported endpoints are redistributed to every peer as dial targets — only
// literal, routable ip:port survives, and no more than the cap.
func TestStatusEndpointSanitized(t *testing.T) {
	ts := newTestServer(t)
	enroll(t, ts, createToken(t, ts), api.RoleHub)
	a := enroll(t, ts, createToken(t, ts), api.RoleNode)
	b := enroll(t, ts, createToken(t, ts), api.RoleNode)

	junk := []string{
		"127.0.0.1:80",      // loopback
		"nas.local:51820",   // hostname — would make peers resolve DNS
		"224.0.0.1:5",       // multicast
		"0.0.0.0:9",         // unspecified
		"169.254.1.1:2",     // link-local
		"100.87.0.9:41641",  // inside the overlay
		"10.0.0.5:0",        // port 0
		"192.168.1.9:51820", // valid
		"203.0.113.7:41641", // valid
	}
	if code := call(t, ts, "POST", "/v1/status", b.AuthSecret,
		api.StatusReport{EndpointsLocal: junk}, nil); code != 204 {
		t.Fatalf("status: %d", code)
	}

	var nm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", a.AuthSecret, nil, &nm)
	var got []string
	for _, p := range nm.Peers {
		if p.OverlayIP == b.OverlayIP {
			got = p.Candidates
		}
	}
	slices.Sort(got)
	want := []string{"192.168.1.9:51820", "203.0.113.7:41641"}
	if !slices.Equal(got, want) {
		t.Fatalf("candidates: got %v, want %v", got, want)
	}

	// The endpoint count is capped.
	var many []string
	for i := range 20 {
		many = append(many, fmt.Sprintf("10.0.0.%d:1000", i+1))
	}
	call(t, ts, "POST", "/v1/status", b.AuthSecret, api.StatusReport{EndpointsLocal: many}, nil)
	var nm2 api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", a.AuthSecret, nil, &nm2)
	for _, p := range nm2.Peers {
		if p.OverlayIP == b.OverlayIP && len(p.Candidates) > maxReportedEndpoints {
			t.Fatalf("candidates not capped: %d", len(p.Candidates))
		}
	}
}

// Extra reserved ports come from the config; the built-ins only cover the
// coordinator's own services.
func TestPublishReservedPortsFromConfig(t *testing.T) {
	ts, srv := newTestServerSrv(t)
	enroll(t, ts, createToken(t, ts), api.RoleHub)
	srv.cfg.ReservedPorts = []int{9443}

	if code := call(t, ts, "POST", "/v1/admin/publishes", adminToken,
		api.PublishCreateRequest{Name: "x", ListenPort: 9443, Target: "100.87.0.2:80"}, nil); code != 409 {
		t.Fatalf("config-reserved port must be 409, got %d", code)
	}
	if code := call(t, ts, "POST", "/v1/admin/publishes", adminToken,
		api.PublishCreateRequest{Name: "x", ListenPort: 9444, Target: "100.87.0.2:80"}, nil); code != 200 {
		t.Fatalf("unreserved port must publish, got %d", code)
	}
}

// Request bodies are capped globally — the login endpoint is unauthenticated.
func TestRequestBodyCapped(t *testing.T) {
	ts := newTestServer(t)
	huge := `{"token":"` + strings.Repeat("a", maxRequestBody) + `"}`
	req, _ := http.NewRequest("POST", ts.URL+"/v1/admin/session", strings.NewReader(huge))
	req.Header.Set("X-Kai-UI", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Fatalf("oversized body must be rejected, got %d", resp.StatusCode)
	}
}
