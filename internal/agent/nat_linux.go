//go:build linux

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/kaidstor/home-kai/internal/api"
)

// iptablesRule is one rule managed idempotently: -C before insert, -D on
// shutdown. Inserted (-I) rather than appended so it precedes docker's
// FORWARD machinery (which otherwise drops traffic into bridge networks).
type iptablesRule struct {
	table string
	chain string
	spec  []string
}

func (r iptablesRule) run(op string) error {
	return iptExec(append([]string{"-t", r.table, op, r.chain}, r.spec...)...)
}

func iptExec(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r iptablesRule) ensure() error {
	if r.run("-C") == nil {
		return nil
	}
	return r.run("-I")
}

func (r iptablesRule) remove() {
	if r.run("-C") == nil {
		_ = r.run("-D")
	}
}

// forwardChain picks where to put ACCEPT rules: DOCKER-USER is evaluated
// before all docker-generated FORWARD rules and is the designated place for
// user rules on docker hosts; plain FORWARD elsewhere.
func forwardChain() string {
	if exec.Command("iptables", "-t", "filter", "-nL", "DOCKER-USER").Run() == nil {
		return "DOCKER-USER"
	}
	return "FORWARD"
}

// subnetRouterRules opens forwarding overlay↔subnet and SNATs overlay sources
// into the subnet, so LAN/bridge devices reply to this node without needing a
// route back to the overlay.
func subnetRouterRules(iface, overlayCIDR string, routes []string) []iptablesRule {
	fwd := forwardChain()
	var rules []iptablesRule
	for _, rt := range routes {
		rules = append(rules,
			iptablesRule{"filter", fwd, []string{"-i", iface, "-d", rt, "-m", "comment", "--comment", "kai-subnet", "-j", "ACCEPT"}},
			iptablesRule{"filter", fwd, []string{"-o", iface, "-s", rt, "-m", "comment", "--comment", "kai-subnet", "-j", "ACCEPT"}},
			iptablesRule{"nat", "POSTROUTING", []string{"-s", overlayCIDR, "-d", rt, "-m", "comment", "--comment", "kai-subnet", "-j", "MASQUERADE"}},
		)
	}
	return rules
}

func enableIPForward() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644)
}

// hubNATRules let the hub relay between spokes (FORWARD on the wg interface)
// and act as an exit node: overlay sources heading outside the overlay are
// masqueraded out via the default route.
func hubNATRules(iface, overlayCIDR string) []iptablesRule {
	fwd := forwardChain()
	return []iptablesRule{
		{"filter", fwd, []string{"-i", iface, "-m", "comment", "--comment", "kai-hub", "-j", "ACCEPT"}},
		{"filter", fwd, []string{"-o", iface, "-m", "comment", "--comment", "kai-hub", "-j", "ACCEPT"}},
		{"nat", "POSTROUTING", []string{"-s", overlayCIDR, "!", "-d", overlayCIDR,
			"-m", "comment", "--comment", "kai-hub", "-j", "MASQUERADE"}},
	}
}

func (a *Agent) setupHubNAT() error {
	if err := enableIPForward(); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	rules := hubNATRules(a.dev.Name(), a.st.OverlayCIDR)
	for _, r := range rules {
		if err := r.ensure(); err != nil {
			return err
		}
	}
	a.natRules = append(a.natRules, rules...)
	return nil
}

// setupSubnetRouter is called on Run when the node advertises routes; the
// rules are removed again on graceful shutdown.
func (a *Agent) setupSubnetRouter() error {
	if err := enableIPForward(); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	rules := subnetRouterRules(a.dev.Name(), a.st.OverlayCIDR, a.st.AdvertiseRoutes)
	for _, r := range rules {
		if err := r.ensure(); err != nil {
			return err
		}
	}
	a.natRules = append(a.natRules, rules...)
	return nil
}

func (a *Agent) teardownNATRules() {
	for _, r := range a.natRules {
		r.remove()
	}
	a.natRules = nil
}

// ACL enforcement, two legs:
//
//   - KAI-FILTER off INPUT (`-i <iface>`): inbound overlay traffic addressed
//     to this node. Physical SSH and the control plane never traverse the
//     overlay interface and are untouched.
//   - KAI-FORWARD: traffic this node forwards for other devices — the hub
//     relaying between peers (`-i <iface> -o <iface>`, which also covers
//     static peers and, deliberately, leaves exit-node traffic to the
//     internet alone) and a subnet router forwarding into its advertised
//     LANs (`-i <iface> -d <route>`). The hooks are inserted at the top of
//     the forward chain, ahead of the unconditional kai-hub/kai-subnet
//     ACCEPTs — without this leg those ACCEPTs would bypass the ACL for any
//     destination that cannot filter for itself.
//
// Called on every netmap apply; a full rebuild keeps it idempotent.
const (
	filterChain        = "KAI-FILTER"
	forwardFilterChain = "KAI-FORWARD"
)

// chainHook is one jump into an ACL chain from a parent chain.
type chainHook struct {
	parent string
	spec   []string
}

// rebuildFilterChain (re)creates chain with the given rule bodies and makes
// sure every hook exists (inserted on top of its parent). Disabled: hooks are
// detached and the chain removed (open network).
func rebuildFilterChain(chain string, hooks []chainHook, enabled bool, specs [][]string) error {
	if !enabled {
		for _, h := range hooks {
			iptablesRule{"filter", h.parent, h.spec}.remove()
		}
		_ = exec.Command("iptables", "-t", "filter", "-F", chain).Run()
		_ = exec.Command("iptables", "-t", "filter", "-X", chain).Run()
		return nil
	}
	_ = exec.Command("iptables", "-t", "filter", "-N", chain).Run() // ignore "exists"
	if err := iptExec("-t", "filter", "-F", chain); err != nil {
		return err
	}
	for _, spec := range specs {
		if err := iptExec(append([]string{"-t", "filter", "-A", chain}, spec...)...); err != nil {
			return err
		}
	}
	for _, h := range hooks {
		if err := (iptablesRule{"filter", h.parent, h.spec}).ensure(); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) applyFilter(enabled bool, input []api.FilterRule, forward []api.ForwardRule) error {
	iface := a.dev.Name()
	err := rebuildFilterChain(filterChain,
		[]chainHook{{"INPUT", []string{"-i", iface, "-j", filterChain}}},
		enabled, filterChainSpecs(input))
	if err != nil {
		return err
	}
	// The forward leg exists only where this node forwards for others. A
	// subnet router hooks every *advertised* route, while allow-rules are
	// compiled for enabled ones only — an advertised-but-not-enabled route is
	// then default-deny instead of open via the kai-subnet ACCEPT.
	fwd := forwardChain()
	var hooks []chainHook
	if a.st.Role == api.RoleHub {
		hooks = append(hooks, chainHook{fwd, []string{"-i", iface, "-o", iface, "-j", forwardFilterChain}})
	}
	for _, rt := range a.st.AdvertiseRoutes {
		hooks = append(hooks, chainHook{fwd, []string{"-i", iface, "-d", rt, "-j", forwardFilterChain}})
	}
	if len(hooks) == 0 {
		return nil
	}
	return rebuildFilterChain(forwardFilterChain, hooks, enabled, forwardChainSpecs(forward))
}
