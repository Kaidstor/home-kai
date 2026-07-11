// kai-agent is the node daemon: it enrolls the machine into the kai overlay
// and keeps the local WireGuard device in sync with the coordinator.
//
//	sudo kai-agent up --coordinator https://... --token ... --fingerprint ...
//	sudo kai-agent up                # already enrolled: state file is enough
//	kai-agent status --state ...
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/kaidstor/home-kai/internal/agent"
	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/text"
)

const defaultStatePath = "/var/lib/kai-agent/state.json"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "up":
		cmdUp(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "rekey":
		cmdRekey(os.Args[2:])
	case "version":
		fmt.Println(agent.Version)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  kai-agent up [--coordinator URL --token T --fingerprint FP] [--hub] [--listen-port N] [--state PATH]
               [--advertise-routes CIDR,CIDR] [--no-hosts] [--rekey-days N]
  kai-agent status [--state PATH]
  kai-agent rekey [--state PATH]    # rotate the WG key now (agent must be stopped)
  kai-agent version`)
	os.Exit(2)
}

func cmdUp(args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	coordinatorURL := fs.String("coordinator", "", "coordinator URL (first run only)")
	token := fs.String("token", "", "one-time enroll token (first run only)")
	fingerprint := fs.String("fingerprint", "", "coordinator TLS cert sha256 (first run only)")
	hub := fs.Bool("hub", false, "enroll as the relay hub (first run only)")
	listenPort := fs.Int("listen-port", 51820, "fixed WireGuard listen port (0 = ephemeral)")
	statePath := fs.String("state", defaultStatePath, "agent state file")
	advertiseRoutes := fs.String("advertise-routes", "",
		"comma-separated subnets this node offers to route (subnet router), e.g. 192.168.1.0/24; empty string clears")
	noHosts := fs.Bool("no-hosts", false, "do not manage the kai block in /etc/hosts")
	rekeyDays := fs.Int("rekey-days", 0, "auto-rotate the WireGuard key when older than N days (0 = never)")
	_ = fs.Parse(args)
	routesFlagSet, noHostsFlagSet, rekeyFlagSet := false, false, false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "advertise-routes":
			routesFlagSet = true
		case "no-hosts":
			noHostsFlagSet = true
		case "rekey-days":
			rekeyFlagSet = true
		}
	})

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := agent.LoadState(*statePath)
	switch {
	case err == nil:
		if *coordinatorURL != "" || *token != "" {
			log.Warn("already enrolled — ignoring --coordinator/--token", "state", *statePath)
		}
	case errors.Is(err, os.ErrNotExist):
		if *coordinatorURL == "" || *token == "" || *fingerprint == "" {
			fatal(fmt.Errorf("not enrolled: --coordinator, --token and --fingerprint are required (see `home-kai token create`)"))
		}
		role := api.RoleNode
		if *hub {
			role = api.RoleHub
		}
		st, err = agent.Enroll(ctx, *coordinatorURL, *fingerprint, *token, role, *listenPort, *statePath)
		if err != nil {
			fatal(fmt.Errorf("enroll: %w", err))
		}
		log.Info("enrolled", "node_id", st.NodeID, "ip", st.OverlayIP, "role", role)
	default:
		fatal(err)
	}

	// Behaviour flags may change on any restart, not only at enroll.
	if routesFlagSet || noHostsFlagSet || rekeyFlagSet {
		if routesFlagSet {
			st.AdvertiseRoutes = parseRoutesFlag(*advertiseRoutes)
		}
		if noHostsFlagSet {
			st.NoHosts = *noHosts
		}
		if rekeyFlagSet {
			st.RekeyDays = *rekeyDays
		}
		if err := st.Save(*statePath); err != nil {
			fatal(err)
		}
	}

	a, err := agent.New(st, *statePath, log)
	if err != nil {
		fatal(err)
	}
	if err := a.Run(ctx); err != nil {
		fatal(err)
	}
}

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	statePath := fs.String("state", defaultStatePath, "agent state file")
	_ = fs.Parse(args)

	st, err := agent.LoadState(*statePath)
	if err != nil {
		fatal(err)
	}
	out := map[string]any{
		"node_id":     st.NodeID,
		"role":        st.Role,
		"overlay_ip":  st.OverlayIP,
		"coordinator": st.CoordinatorURL,
	}
	if st.Netmap != nil {
		out["netmap_version"] = st.Netmap.Version
		out["peers"] = len(st.Netmap.Peers)
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
}

// cmdRekey is the offline rotation path: with the daemon stopped, swap the
// key in the state file and register it with the coordinator. The running
// daemon rotates on its own via --rekey-days; doing it here while the daemon
// is up would leave the live device on the old key.
func cmdRekey(args []string) {
	fs := flag.NewFlagSet("rekey", flag.ExitOnError)
	statePath := fs.String("state", defaultStatePath, "agent state file")
	_ = fs.Parse(args)

	if c, err := net.Dial("unix", api.LocalSocketPath); err == nil {
		c.Close()
		fatal(fmt.Errorf("kai-agent is running — stop it first (or use --rekey-days for live rotation)"))
	}
	st, err := agent.LoadState(*statePath)
	if err != nil {
		fatal(err)
	}
	if st.LockPublicKey != "" {
		fatal(fmt.Errorf("network lock is enabled: rotate, then run `home-kai lock sign` before starting the agent"))
	}
	if err := agent.RotateStateKey(context.Background(), st, *statePath); err != nil {
		fatal(err)
	}
	fmt.Println("key rotated and registered with the coordinator")
}

func parseRoutesFlag(s string) []string {
	var out []string
	for _, part := range text.Fields(s) {
		pfx, err := netip.ParsePrefix(part)
		if err != nil {
			fatal(fmt.Errorf("--advertise-routes: bad subnet %q: %w", part, err))
		}
		out = append(out, pfx.Masked().String())
	}
	return out
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "kai-agent:", err)
	os.Exit(1)
}
