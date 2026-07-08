package coordinator

import (
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/wgkeys"
)

func TestLockFlow(t *testing.T) {
	ts := newTestServer(t)
	hub := enroll(t, ts, createToken(t, ts), api.RoleHub)
	node := enroll(t, ts, createToken(t, ts), api.RoleNode)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	// Arm the lock. Not active yet → netmaps stay lock-free.
	if code := call(t, ts, "POST", "/v1/admin/lock", adminToken, api.LockInitRequest{PublicKey: pubB64}, nil); code != 204 {
		t.Fatalf("lock init: %d", code)
	}
	var nm api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &nm)
	if nm.Self.LockPublicKey != "" {
		t.Fatal("lock key distributed while still arming")
	}

	var st api.LockStatus
	call(t, ts, "GET", "/v1/admin/lock", adminToken, nil, &st)
	if !st.Enabled || st.Active || len(st.Pending) != 2 {
		t.Fatalf("status: %+v", st)
	}

	// A bad signature is rejected.
	bad := api.LockSignRequest{Sigs: []api.LockSignature{{
		Kind: st.Pending[0].Kind, ID: st.Pending[0].ID,
		Sig: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}}}
	if code := call(t, ts, "POST", "/v1/admin/lock/sign", adminToken, bad, nil); code != 400 {
		t.Fatalf("bad signature accepted: %d", code)
	}

	// Sign everything → lock becomes active, netmaps carry key + sigs.
	req := api.LockSignRequest{}
	for _, b := range st.Pending {
		sig := ed25519.Sign(priv, api.LockMessage(b.WGPublicKey, b.OverlayIP))
		req.Sigs = append(req.Sigs, api.LockSignature{Kind: b.Kind, ID: b.ID, Sig: base64.StdEncoding.EncodeToString(sig)})
	}
	if code := call(t, ts, "POST", "/v1/admin/lock/sign", adminToken, req, nil); code != 200 {
		t.Fatal("sign failed")
	}
	var afterSign api.LockStatus
	call(t, ts, "GET", "/v1/admin/lock", adminToken, nil, &afterSign)
	if !afterSign.Active || len(afterSign.Pending) != 0 {
		t.Fatalf("after sign: %+v", afterSign)
	}
	var locked api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", node.AuthSecret, nil, &locked)
	if locked.Self.LockPublicKey != pubB64 || len(locked.Peers) == 0 || locked.Peers[0].LockSig == "" {
		t.Fatalf("locked netmap: self=%q peer0.sig=%q", locked.Self.LockPublicKey, locked.Peers[0].LockSig)
	}

	// A newly enrolled node is pending again (fail closed until signed).
	enroll(t, ts, createToken(t, ts), api.RoleNode)
	var afterEnroll api.LockStatus
	call(t, ts, "GET", "/v1/admin/lock", adminToken, nil, &afterEnroll)
	if len(afterEnroll.Pending) != 1 {
		t.Fatalf("new node must be pending: %+v", afterEnroll.Pending)
	}

	// Rekey clears the node's signature → pending again.
	req = api.LockSignRequest{}
	for _, b := range afterEnroll.Pending {
		sig := ed25519.Sign(priv, api.LockMessage(b.WGPublicKey, b.OverlayIP))
		req.Sigs = append(req.Sigs, api.LockSignature{Kind: b.Kind, ID: b.ID, Sig: base64.StdEncoding.EncodeToString(sig)})
	}
	call(t, ts, "POST", "/v1/admin/lock/sign", adminToken, req, nil)
	pair, _ := wgkeys.Generate()
	if code := call(t, ts, "POST", "/v1/rekey", node.AuthSecret, api.RekeyRequest{WGPublicKey: pair.Public.String()}, nil); code != 204 {
		t.Fatal("rekey failed")
	}
	var afterRekey api.LockStatus
	call(t, ts, "GET", "/v1/admin/lock", adminToken, nil, &afterRekey)
	if len(afterRekey.Pending) != 1 || afterRekey.Pending[0].ID != node.NodeID {
		t.Fatalf("rekeyed node must be pending: %+v", afterRekey.Pending)
	}

	// Disable: key gone from netmaps.
	if code := call(t, ts, "DELETE", "/v1/admin/lock", adminToken, nil, nil); code != 204 {
		t.Fatal("disable failed")
	}
	var unlocked api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &unlocked)
	if unlocked.Self.LockPublicKey != "" {
		t.Fatal("lock key still distributed after disable")
	}
}

func TestMetrics(t *testing.T) {
	ts := newTestServer(t)
	enroll(t, ts, createToken(t, ts), api.RoleHub)

	req, _ := http.NewRequest("GET", ts.URL+"/metrics", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("metrics without auth must be 401, got %d", resp.StatusCode)
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	out := string(body)
	if resp.StatusCode != 200 ||
		!strings.Contains(out, "kai_nodes_total 1") ||
		!strings.Contains(out, "kai_nodes_online 1") ||
		!strings.Contains(out, "kai_lock_active 0") {
		t.Fatalf("metrics:\n%s", out)
	}
}
