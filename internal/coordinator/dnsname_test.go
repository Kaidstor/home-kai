package coordinator

import (
	"context"
	"strings"
	"testing"

	"github.com/kaidstor/home-kai/internal/api"
)

// fakeDNS records EnsureA calls (the coordinator's DNS provider contract).
type fakeDNS struct {
	records map[string]string // fqdn → ip
}

func (f *fakeDNS) EnsureA(_ context.Context, fqdn, ip string) error {
	f.records[fqdn] = ip
	return nil
}
func (f *fakeDNS) DeleteA(_ context.Context, fqdn string) error {
	delete(f.records, fqdn)
	return nil
}

// Devices enrolled before a DNS provider was configured get names on start.
func TestBackfillDNS(t *testing.T) {
	ts, srv := newTestServerSrv(t)
	hub := enroll(t, ts, createToken(t, ts), api.RoleHub)
	enroll(t, ts, createToken(t, ts), api.RoleNode)
	var sp api.StaticPeerCreateResponse
	call(t, ts, "POST", "/v1/admin/static-peers", adminToken, api.StaticPeerCreateRequest{Name: "iphone"}, &sp)
	if sp.DNSName != "" {
		t.Fatalf("dns disabled, yet peer got a name: %q", sp.DNSName)
	}

	// The provider appears later (config change + restart).
	f := &fakeDNS{records: map[string]string{}}
	srv.dns = f
	srv.cfg.Domain = "kai.example.com"

	var before api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &before)

	srv.BackfillDNS(context.Background())

	var nodes []api.NodeInfo
	call(t, ts, "GET", "/v1/admin/nodes", adminToken, nil, &nodes)
	for _, n := range nodes {
		if !strings.HasSuffix(n.DNSName, ".kai.example.com") {
			t.Fatalf("node %s: dns name not backfilled: %q", n.Hostname, n.DNSName)
		}
		if f.records[n.DNSName] != n.OverlayIP {
			t.Fatalf("record %s → %s, want %s", n.DNSName, f.records[n.DNSName], n.OverlayIP)
		}
	}
	var peers []api.StaticPeerInfo
	call(t, ts, "GET", "/v1/admin/static-peers", adminToken, nil, &peers)
	if len(peers) != 1 || !strings.HasSuffix(peers[0].DNSName, ".kai.example.com") {
		t.Fatalf("static peer not backfilled: %+v", peers)
	}

	// Names changed → netmap bumped so agents pick them up.
	var after api.Netmap
	call(t, ts, "GET", "/v1/netmap?since=0", hub.AuthSecret, nil, &after)
	if after.Version <= before.Version {
		t.Fatalf("netmap not bumped: v%d → v%d", before.Version, after.Version)
	}

	// Second run is a no-op (idempotent).
	got := len(f.records)
	srv.BackfillDNS(context.Background())
	if len(f.records) != got {
		t.Fatalf("backfill is not idempotent: %d → %d records", got, len(f.records))
	}
}
