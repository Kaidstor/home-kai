package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
)

// localClient talks to the agent's unix socket — no env/tokens needed.
func localClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", api.LocalSocketPath)
			},
		},
	}
}

func localStatus(ctx context.Context) (api.LocalStatus, error) {
	var st api.LocalStatus
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://kai-agent/v1/local/status", nil)
	if err != nil {
		return st, err
	}
	resp, err := localClient().Do(req)
	if err != nil {
		return st, fmt.Errorf("is kai-agent running? %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("agent local api: %s", resp.Status)
	}
	return st, json.NewDecoder(resp.Body).Decode(&st)
}

func cmdStatus(ctx context.Context) {
	st, err := localStatus(ctx)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("%s (%s), role %s, agent %s, netmap v%d\ncoordinator: %s\n\n",
		st.Hostname, st.OverlayIP, st.Role, st.AgentVersion, st.NetmapVersion, st.CoordinatorURL)
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PEER\tIP\tPATH\tENDPOINT\tHANDSHAKE\tRX\tTX")
	for _, p := range st.Peers {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			p.Hostname, p.OverlayIP, p.Path, p.Endpoint,
			handshakeAge(p.LastHandshakeAgeSec), fmtBytes(p.RxBytes), fmtBytes(p.TxBytes))
	}
	w.Flush()
}

// cmdPing resolves a device name via the agent's host list, runs the system
// ping and reports which path the traffic takes.
func cmdPing(ctx context.Context, args []string) {
	if len(args) < 1 {
		usage()
	}
	target := args[0]
	st, err := localStatus(ctx)
	if err != nil {
		fatal(err)
	}

	ip := target
	if _, err := netip.ParseAddr(target); err != nil {
		ip = ""
		for _, h := range st.Hosts {
			if h.Name == target || strings.TrimSuffix(h.Name, api.HostsSuffix) == target {
				ip = h.IP
				break
			}
		}
		if ip == "" {
			for _, p := range st.Peers {
				if p.Hostname == target {
					ip = p.OverlayIP
					break
				}
			}
		}
		if ip == "" {
			fatal(fmt.Errorf("unknown device %q (try `home-kai status`)", target))
		}
	}

	for _, p := range st.Peers {
		if p.OverlayIP == ip {
			path := p.Path
			if p.Endpoint != "" {
				path += " via " + p.Endpoint
			}
			fmt.Printf("%s (%s): path %s\n", p.Hostname, ip, path)
		}
	}
	cmd := exec.CommandContext(ctx, "ping", "-c", "3", ip)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}

func handshakeAge(sec int64) string {
	if sec < 0 {
		return "never"
	}
	d := time.Duration(sec) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", sec)
	case d < time.Hour:
		return fmt.Sprintf("%dm%ds", sec/60, sec%60)
	default:
		return d.Truncate(time.Minute).String()
	}
}

func fmtBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
