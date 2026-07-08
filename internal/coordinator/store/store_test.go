package store

import (
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestEnrollTokenLifecycle(t *testing.T) {
	s := openTest(t)
	now := time.Now()
	if err := s.CreateEnrollToken("hash1", "srv", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	hint, err := s.ConsumeEnrollToken("hash1", now)
	if err != nil || hint != "srv" {
		t.Fatalf("consume: hint=%q err=%v", hint, err)
	}
	// Second consume must fail: one-time token.
	if _, err := s.ConsumeEnrollToken("hash1", now); err != ErrNotFound {
		t.Fatalf("reuse must fail, got %v", err)
	}
	// Expired token must fail.
	_ = s.CreateEnrollToken("hash2", "", now.Add(-time.Minute))
	if _, err := s.ConsumeEnrollToken("hash2", now); err != ErrNotFound {
		t.Fatalf("expired must fail, got %v", err)
	}
	// Unknown token must fail.
	if _, err := s.ConsumeEnrollToken("nope", now); err != ErrNotFound {
		t.Fatalf("unknown must fail, got %v", err)
	}
}

func TestNodeCRUDAndVersion(t *testing.T) {
	s := openTest(t)
	v0, err := s.NetmapVersion()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	n := Node{ID: "n_1", Name: "srv", Role: "node", WGPubKey: "PK", OverlayIP: "100.87.0.2",
		AuthSecretHash: "AH", CreatedAt: now, LastSeen: now}
	if err := s.CreateNode(n); err != nil {
		t.Fatal(err)
	}
	got, err := s.NodeByAuthHash("AH")
	if err != nil || got.ID != "n_1" {
		t.Fatalf("by auth hash: %+v err=%v", got, err)
	}
	v1, err := s.BumpNetmapVersion()
	if err != nil || v1 != v0+1 {
		t.Fatalf("bump: %d -> %d err=%v", v0, v1, err)
	}
	ips, err := s.AllocatedIPs()
	if err != nil || !ips["100.87.0.2"] {
		t.Fatalf("allocated ips: %v err=%v", ips, err)
	}
	if err := s.DeleteNode("n_1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteNode("n_1"); err != ErrNotFound {
		t.Fatalf("double delete must be ErrNotFound, got %v", err)
	}
}
