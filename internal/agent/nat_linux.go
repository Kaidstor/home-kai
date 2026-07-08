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
	args := append([]string{"-t", r.table, op, r.chain}, r.spec...)
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

// ACL enforcement. All inbound overlay traffic (arriving on the wg interface)
// is funnelled through a dedicated KAI-FILTER chain: established flows and the
// compiled allow-rules pass, everything else is dropped. The chain lives off
// INPUT with an `-i <iface>` match, so physical SSH and the control plane
// (which never traverse the overlay interface) are untouched. Called on every
// netmap apply; a full rebuild keeps it idempotent and simple.
const filterChain = "KAI-FILTER"

func (a *Agent) applyFilter(enabled bool, rules []api.FilterRule) error {
	iface := a.dev.Name()
	ipt := func(args ...string) error {
		out, err := exec.Command("iptables", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	hookExists := func() bool {
		return exec.Command("iptables", "-t", "filter", "-C", "INPUT", "-i", iface, "-j", filterChain).Run() == nil
	}

	if !enabled {
		// Detach and remove the chain (open network).
		if hookExists() {
			_ = ipt("-t", "filter", "-D", "INPUT", "-i", iface, "-j", filterChain)
		}
		_ = exec.Command("iptables", "-t", "filter", "-F", filterChain).Run()
		_ = exec.Command("iptables", "-t", "filter", "-X", filterChain).Run()
		return nil
	}

	// (Re)create and flush the chain, then fill it.
	_ = exec.Command("iptables", "-t", "filter", "-N", filterChain).Run() // ignore "exists"
	if err := ipt("-t", "filter", "-F", filterChain); err != nil {
		return err
	}
	if err := ipt("-t", "filter", "-A", filterChain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	for _, rule := range rules {
		for _, cidr := range rule.SrcCIDRs {
			base := []string{"-t", "filter", "-A", filterChain, "-s", cidr}
			switch rule.Protocol {
			case "", "any":
				if err := ipt(append(base, "-j", "ACCEPT")...); err != nil {
					return err
				}
			case "icmp":
				if err := ipt(append(base, "-p", "icmp", "-j", "ACCEPT")...); err != nil {
					return err
				}
			case "tcp", "udp":
				if len(rule.Ports) == 0 {
					if err := ipt(append(base, "-p", rule.Protocol, "-j", "ACCEPT")...); err != nil {
						return err
					}
				} else {
					// multiport takes a comma list (max 15) — chunk to be safe.
					for _, chunk := range chunkPorts(rule.Ports, 15) {
						args := append(append([]string{}, base...), "-p", rule.Protocol,
							"-m", "multiport", "--dports", strings.Join(chunk, ","), "-j", "ACCEPT")
						if err := ipt(args...); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	if err := ipt("-t", "filter", "-A", filterChain, "-j", "DROP"); err != nil {
		return err
	}
	// Attach the hook exactly once.
	if !hookExists() {
		if err := ipt("-t", "filter", "-I", "INPUT", "-i", iface, "-j", filterChain); err != nil {
			return err
		}
	}
	return nil
}

func chunkPorts(ports []string, n int) [][]string {
	var out [][]string
	for i := 0; i < len(ports); i += n {
		end := i + n
		if end > len(ports) {
			end = len(ports)
		}
		out = append(out, ports[i:end])
	}
	return out
}
