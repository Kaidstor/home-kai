//go:build !linux

package agent

import (
	"errors"
	"sync"

	"github.com/kaidstor/home-kai/internal/api"
)

// iptablesRule only exists on Linux; this stub keeps the Agent struct portable.
type iptablesRule struct{}

func (a *Agent) setupSubnetRouter() error {
	return errors.New("advertising subnet routes is only supported on linux")
}

func (a *Agent) setupHubNAT() error {
	return errors.New("hub role is only supported on linux")
}

func (a *Agent) teardownNATRules() {}

// applyFilter is a no-op on non-Linux: macOS has no iptables, so ACL
// enforcement is skipped (warned once). The overlay still works; the node
// just isn't firewalled locally.
var warnFilterOnce sync.Once

func (a *Agent) applyFilter(enabled bool, _ []api.FilterRule) error {
	if enabled {
		warnFilterOnce.Do(func() {
			a.log.Warn("ACL enforcement is only supported on linux — this node is not firewalling overlay traffic")
		})
	}
	return nil
}
