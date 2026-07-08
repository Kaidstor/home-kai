package agent

import (
	"strings"
	"testing"

	"github.com/kaidstor/home-kai/internal/api"
)

func TestHostsBlockRoundTrip(t *testing.T) {
	orig := "127.0.0.1 localhost\n255.255.255.255 broadcasthost\n"
	entries := []api.HostEntry{
		{Name: "vps-hub.kai", IP: "100.87.0.1"},
		{Name: "macbook.kai", IP: "100.87.0.2"},
	}

	withBlock := orig + renderHostsBlock(entries)
	if !strings.Contains(withBlock, "100.87.0.1") || !strings.Contains(withBlock, "macbook.kai") {
		t.Fatalf("block:\n%s", withBlock)
	}

	// Replacing the block must not duplicate it or eat unrelated lines.
	stripped := stripManagedBlock(withBlock)
	if stripped != orig {
		t.Fatalf("strip: %q != %q", stripped, orig)
	}
	if stripManagedBlock(orig) != orig {
		t.Fatal("strip on clean file must be a no-op")
	}

	// Missing end marker (manual edit) — truncate from the begin marker.
	broken := orig + hostsBegin + "\ngarbage\n"
	if got := stripManagedBlock(broken); got != orig {
		t.Fatalf("strip broken: %q", got)
	}

	if renderHostsBlock(nil) != "" {
		t.Fatal("empty entries must render nothing")
	}
}
