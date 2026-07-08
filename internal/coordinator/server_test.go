package coordinator

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/coordinator/store"
	"github.com/kaidstor/home-kai/internal/wgkeys"
)

const adminToken = "test-admin-token"

func newTestServer(t *testing.T) *httptest.Server {
	ts, _ := newTestServerSrv(t)
	return ts
}

// newTestServerSrv also returns the *Server so tests can flip config toggles.
func newTestServerSrv(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "kai.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := NewServer(Config{
		PublicURL:      "https://coord.test:8443",
		HubEndpoint:    "coord.test:51820",
		OverlayCIDR:    netip.MustParsePrefix("100.87.0.0/16"),
		AdminTokenHash: sha256hex(adminToken),
		Fingerprint:    "ff00",
	}, st, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, srv
}

func call(t *testing.T, ts *httptest.Server, method, path, bearer string, in, out any) int {
	t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, ts.URL+path, body)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

func createToken(t *testing.T, ts *httptest.Server) string {
	var resp api.TokenCreateResponse
	if code := call(t, ts, "POST", "/v1/admin/tokens", adminToken, api.TokenCreateRequest{}, &resp); code != 200 {
		t.Fatalf("token create: %d", code)
	}
	return resp.Token
}

func enroll(t *testing.T, ts *httptest.Server, token string, role api.NodeRole) api.EnrollResponse {
	t.Helper()
	pair, _ := wgkeys.Generate()
	var resp api.EnrollResponse
	code := call(t, ts, "POST", "/v1/enroll", token, api.EnrollRequest{
		Hostname: "host-" + string(role), OS: "linux", Role: role, WGPublicKey: pair.Public.String(),
	}, &resp)
	if code != 200 {
		t.Fatalf("enroll as %s: %d", role, code)
	}
	return resp
}

func TestFullFlow(t *testing.T) {
	ts := newTestServer(t)

	// Hub enrolls first and gets the fixed hub address.
	hub := enroll(t, ts, createToken(t, ts), api.RoleHub)
	if hub.OverlayIP != "100.87.0.1" {
		t.Fatalf("hub ip = %s", hub.OverlayIP)
	}
	// Spoke gets the next address.
	node := enroll(t, ts, createToken(t, ts), api.RoleNode)
	if node.OverlayIP != "100.87.0.2" {
		t.Fatalf("node ip = %s", node.OverlayIP)
	}

	// Spoke netmap: only the hub, whole overlay routed through it.
	var nm api.Netmap
	if code := call(t, ts, "GET", "/v1/netmap?since=0", node.AuthSecret, nil, &nm); code != 200 {
		t.Fatalf("netmap: %d", code)
	}
	if len(nm.Peers) != 1 || nm.Peers[0].Role != api.RoleHub || nm.Peers[0].Endpoint != "coord.test:51820" {
		t.Fatalf("spoke netmap: %+v", nm.Peers)
	}

	// Hub netmap: sees the spoke as /32.
	var hubNm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &hubNm)
	if len(hubNm.Peers) != 1 || hubNm.Peers[0].AllowedIPs[0] != "100.87.0.2/32" {
		t.Fatalf("hub netmap: %+v", hubNm.Peers)
	}

	// Static peer: conf must reference the hub and its endpoint.
	var sp api.StaticPeerCreateResponse
	if code := call(t, ts, "POST", "/v1/admin/static-peers", adminToken,
		api.StaticPeerCreateRequest{Name: "iphone"}, &sp); code != 200 {
		t.Fatalf("static peer: %d", code)
	}
	if !strings.Contains(sp.ConfINI, "Endpoint = coord.test:51820") ||
		!strings.Contains(sp.ConfINI, "AllowedIPs = 100.87.0.0/16") {
		t.Fatalf("bad conf:\n%s", sp.ConfINI)
	}

	// Netmap version advanced; hub now sees 2 peers.
	var hubNm2 api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &hubNm2)
	if hubNm2.Version <= hubNm.Version || len(hubNm2.Peers) != 2 {
		t.Fatalf("after static peer: v%d peers=%d", hubNm2.Version, len(hubNm2.Peers))
	}

	// Admin node list, then delete the spoke.
	var nodes []api.NodeInfo
	call(t, ts, "GET", "/v1/admin/nodes", adminToken, nil, &nodes)
	if len(nodes) != 2 {
		t.Fatalf("nodes: %d", len(nodes))
	}
	if code := call(t, ts, "DELETE", "/v1/admin/nodes/"+node.NodeID, adminToken, nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	// Deleted node's credentials must stop working.
	if code := call(t, ts, "GET", "/v1/netmap?since=999999", node.AuthSecret, nil, nil); code != 401 {
		t.Fatalf("deleted node still authorized: %d", code)
	}
}

func TestStaticPeerLifecycle(t *testing.T) {
	ts := newTestServer(t)
	hub := enroll(t, ts, createToken(t, ts), api.RoleHub)

	var created api.StaticPeerCreateResponse
	if code := call(t, ts, "POST", "/v1/admin/static-peers", adminToken,
		api.StaticPeerCreateRequest{Name: "iphone"}, &created); code != 200 {
		t.Fatalf("create: %d", code)
	}
	if created.ID == "" {
		t.Fatal("create response has no id")
	}

	var peers []api.StaticPeerInfo
	call(t, ts, "GET", "/v1/admin/static-peers", adminToken, nil, &peers)
	if len(peers) != 1 || peers[0].ID != created.ID || peers[0].Name != "iphone" {
		t.Fatalf("list: %+v", peers)
	}

	// Config re-render must match the one issued at creation, QR must be a PNG.
	var conf api.StaticPeerConfigResponse
	if code := call(t, ts, "GET", "/v1/admin/static-peers/"+created.ID+"/config", adminToken, nil, &conf); code != 200 {
		t.Fatalf("config: %d", code)
	}
	if conf.ConfINI != created.ConfINI {
		t.Fatalf("re-rendered conf differs:\n%s\nvs\n%s", conf.ConfINI, created.ConfINI)
	}
	png, err := base64.StdEncoding.DecodeString(conf.QRPNGBase64)
	if err != nil || !bytes.HasPrefix(png, []byte("\x89PNG")) {
		t.Fatalf("qr is not a png (err=%v, %d bytes)", err, len(png))
	}

	// Static peers appear only in the hub's netmap; watch it shrink on delete.
	var before api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &before)

	if code := call(t, ts, "DELETE", "/v1/admin/static-peers/"+created.ID, adminToken, nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code := call(t, ts, "GET", "/v1/admin/static-peers/"+created.ID+"/config", adminToken, nil, nil); code != 404 {
		t.Fatalf("config after delete must be 404, got %d", code)
	}
	var after api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &after)
	if after.Version <= before.Version || len(after.Peers) != len(before.Peers)-1 {
		t.Fatalf("netmap after delete: v%d→v%d peers %d→%d",
			before.Version, after.Version, len(before.Peers), len(after.Peers))
	}
}

func TestUIServed(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/ui")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") ||
		!bytes.Contains(body, []byte("kai — панель управления")) {
		t.Fatalf("ui: %d %s (%d bytes)", resp.StatusCode, resp.Header.Get("Content-Type"), len(body))
	}
	// Root redirects to the UI.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	root, err := noRedirect.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	root.Body.Close()
	if root.StatusCode != 302 || root.Header.Get("Location") != "/ui" {
		t.Fatalf("root: %d → %q", root.StatusCode, root.Header.Get("Location"))
	}
}

func TestEnrollTokenSingleUse(t *testing.T) {
	ts := newTestServer(t)
	token := createToken(t, ts)
	enroll(t, ts, token, api.RoleHub)

	pair, _ := wgkeys.Generate()
	code := call(t, ts, "POST", "/v1/enroll", token,
		api.EnrollRequest{Hostname: "x", WGPublicKey: pair.Public.String()}, nil)
	if code != 401 {
		t.Fatalf("token reuse must be 401, got %d", code)
	}
}

func TestSecondHubRejected(t *testing.T) {
	ts := newTestServer(t)
	enroll(t, ts, createToken(t, ts), api.RoleHub)

	pair, _ := wgkeys.Generate()
	code := call(t, ts, "POST", "/v1/enroll", createToken(t, ts),
		api.EnrollRequest{Hostname: "hub2", Role: api.RoleHub, WGPublicKey: pair.Public.String()}, nil)
	if code != 409 {
		t.Fatalf("second hub must be 409, got %d", code)
	}
}

func TestAdminSession(t *testing.T) {
	ts := newTestServer(t)

	post := func(body string) *http.Response {
		req, _ := http.NewRequest("POST", ts.URL+"/v1/admin/session", strings.NewReader(body))
		req.Header.Set("X-Kai-UI", "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	bad := post(`{"token":"wrong"}`)
	bad.Body.Close()
	if bad.StatusCode != 401 || len(bad.Cookies()) != 0 {
		t.Fatalf("bad login: %d, cookies=%v", bad.StatusCode, bad.Cookies())
	}

	good := post(`{"token":"` + adminToken + `"}`)
	good.Body.Close()
	if good.StatusCode != 204 {
		t.Fatalf("login: %d", good.StatusCode)
	}
	var sess *http.Cookie
	for _, c := range good.Cookies() {
		if c.Name == "kai_admin_session" {
			sess = c
		}
	}
	if sess == nil || sess.Value == "" || !sess.HttpOnly {
		t.Fatalf("session cookie: %+v", sess)
	}

	get := func(withHeader bool) int {
		req, _ := http.NewRequest("GET", ts.URL+"/v1/admin/nodes", nil)
		req.AddCookie(sess)
		if withHeader {
			req.Header.Set("X-Kai-UI", "1")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(true); code != 200 {
		t.Fatalf("cookie auth: %d", code)
	}
	// Cookie without the UI header must not authenticate (CSRF guard).
	if code := get(false); code != 401 {
		t.Fatalf("cookie without header must be 401, got %d", code)
	}

	req, _ := http.NewRequest("DELETE", ts.URL+"/v1/admin/session", nil)
	req.AddCookie(sess)
	req.Header.Set("X-Kai-UI", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if code := get(true); code != 401 {
		t.Fatalf("session must die after logout, got %d", code)
	}
}

func TestAdminAuthRequired(t *testing.T) {
	ts := newTestServer(t)
	if code := call(t, ts, "POST", "/v1/admin/tokens", "wrong", api.TokenCreateRequest{}, nil); code != 401 {
		t.Fatalf("bad admin token must be 401, got %d", code)
	}
}
