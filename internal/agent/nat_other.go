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

// applyFilter is a no-op on non-Linux: macOS has no iptables, so local ACL
// enforcement is skipped (warned once). The coordinator knows this and, while
// any policy is enabled, withholds this node's p2p candidates — its traffic
// is forced through the hub, whose forward filter enforces the ACL centrally.
var warnFilterOnce sync.Once

func (a *Agent) applyFilter(enabled bool, _ []api.FilterRule, _ []api.ForwardRule) error {
	if enabled {
		warnFilterOnce.Do(func() {
			a.log.Warn("ACL enforcement is only supported on linux — overlay traffic to this node is filtered on the hub instead (relay only, no direct paths)")
		})
	}
	return nil
}
