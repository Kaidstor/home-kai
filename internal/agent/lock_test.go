package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/kaidstor/home-kai/internal/api"
)

func TestEnforceLock(t *testing.T) {
	a, dev, base, peerPub := testAgent(t)
	a.statePath = filepath.Join(t.TempDir(), "state.json")

	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	// makeNM returns a fresh locked netmap (enforceLock filters in place, so
	// each phase needs its own copy). The hub is always properly signed.
	makeNM := func(peerSigned, peerTampered bool, lockKey string) *api.Netmap {
		nm := *base
		nm.Peers = append([]api.Peer{}, base.Peers...)
		nm.Self.LockPublicKey = lockKey
		nm.Peers[0].OverlayIP = "100.87.0.1"
		nm.Peers[1].OverlayIP = "100.87.0.3"
		sig := ed25519.Sign(priv, api.LockMessage(nm.Peers[0].WGPublicKey, nm.Peers[0].OverlayIP))
		nm.Peers[0].LockSig = base64.StdEncoding.EncodeToString(sig)
		if peerSigned {
			sig := ed25519.Sign(priv, api.LockMessage(nm.Peers[1].WGPublicKey, nm.Peers[1].OverlayIP))
			nm.Peers[1].LockSig = base64.StdEncoding.EncodeToString(sig)
			if peerTampered {
				nm.Peers[1].OverlayIP = "100.87.0.99" // binding no longer matches the signature
			}
		}
		return &nm
	}

	// First locked netmap: key pinned, unsigned peer dropped.
	if err := a.applyNetmap(makeNM(false, false, pubB64)); err != nil {
		t.Fatal(err)
	}
	if a.st.LockPublicKey != pubB64 {
		t.Fatal("lock key not pinned")
	}
	if len(dev.applied) != 1 || dev.applied[0].PublicKey.String() == peerPub {
		t.Fatalf("unsigned peer must be dropped: %+v", dev.applied)
	}

	// Properly signed peer passes.
	if err := a.applyNetmap(makeNM(true, false, pubB64)); err != nil {
		t.Fatal(err)
	}
	if len(dev.applied) != 2 {
		t.Fatalf("signed peer must be installed: %+v", dev.applied)
	}

	// Tampered binding → dropped.
	if err := a.applyNetmap(makeNM(true, true, pubB64)); err != nil {
		t.Fatal(err)
	}
	if len(dev.applied) != 1 {
		t.Fatalf("tampered peer must be dropped: %+v", dev.applied)
	}

	// A different lock key is a hard error (coordinator compromise signal).
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := a.applyNetmap(makeNM(true, false, base64.StdEncoding.EncodeToString(otherPub))); err == nil {
		t.Fatal("netmap with a different lock key must be rejected")
	}

	// Stripping the key entirely must NOT lift enforcement (pin wins): the
	// unsigned peer is still dropped.
	if err := a.applyNetmap(makeNM(false, false, "")); err != nil {
		t.Fatal(err)
	}
	if len(dev.applied) != 1 {
		t.Fatalf("enforcement must survive a stripped key: %+v", dev.applied)
	}
}
