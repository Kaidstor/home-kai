package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/exit"
	"github.com/kaidstor/home-kai/internal/output"
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
		return st, localErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("локальный API агента: %s", resp.Status)
	}
	return st, json.NewDecoder(resp.Body).Decode(&st)
}

func cmdStatus(ctx context.Context, p *output.Printer, args []string) int {
	if _, code, ok := parse(p, "status", "status", newFlagSet("status"), args, 0); !ok {
		return code
	}
	st, err := localStatus(ctx)
	if err != nil {
		return fail(p, "status", err)
	}
	return p.Result("status", exit.OK, st, func(w io.Writer) {
		fmt.Fprintf(w, "%s (%s), роль %s, агент %s, netmap v%d\nкоординатор: %s\n\n",
			st.Hostname, st.OverlayIP, st.Role, st.AgentVersion, st.NetmapVersion, st.CoordinatorURL)
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "PEER\tIP\tPATH\tENDPOINT\tHANDSHAKE\tRX\tTX")
		for _, peer := range st.Peers {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				peer.Hostname, peer.OverlayIP, peer.Path, peer.Endpoint,
				handshakeAge(peer.LastHandshakeAgeSec), fmtBytes(peer.RxBytes), fmtBytes(peer.TxBytes))
		}
		tw.Flush()
	})
}

type pingData struct {
	Target   string `json:"target"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	Path     string `json:"path,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	OK       bool   `json:"ok"`
	Output   string `json:"output,omitempty"`
}

// resolveDevice maps a device name to its overlay IP via the agent's host
// list, then its peers; an IP is returned as-is.
func resolveDevice(st api.LocalStatus, target string) string {
	if _, err := netip.ParseAddr(target); err == nil {
		return target
	}
	for _, h := range st.Hosts {
		if h.Name == target || strings.TrimSuffix(h.Name, api.HostsSuffix) == target {
			return h.IP
		}
	}
	for _, peer := range st.Peers {
		if peer.Hostname == target {
			return peer.OverlayIP
		}
	}
	return ""
}

// cmdPing resolves a device name via the agent's host list, runs the system
// ping and reports which path the traffic takes.
func cmdPing(ctx context.Context, p *output.Printer, args []string) int {
	pos, code, ok := parse(p, "ping", "ping <имя|ip>", newFlagSet("ping"), args, 1)
	if !ok {
		return code
	}
	target := pos[0]
	st, err := localStatus(ctx)
	if err != nil {
		return fail(p, "ping", err)
	}
	ip := resolveDevice(st, target)
	if ip == "" {
		return p.Fail("ping", exit.NotFound, "not_found",
			"устройство %q не найдено среди пиров агента (список: home-kai status)", target)
	}

	data := pingData{Target: target, IP: ip}
	for _, peer := range st.Peers {
		if peer.OverlayIP == ip {
			data.Hostname, data.Path, data.Endpoint = peer.Hostname, peer.Path, peer.Endpoint
			break
		}
	}
	if !p.JSON && data.Path != "" {
		path := data.Path
		if data.Endpoint != "" {
			path += " через " + data.Endpoint
		}
		fmt.Fprintf(p.Out, "%s (%s): путь %s\n", data.Hostname, ip, path)
	}

	cmd := exec.CommandContext(ctx, "ping", "-c", "3", ip)
	var buf bytes.Buffer
	if p.JSON {
		cmd.Stdout, cmd.Stderr = &buf, &buf
	} else {
		cmd.Stdout, cmd.Stderr = p.Out, p.Err
	}
	runErr := cmd.Run()
	data.OK = runErr == nil
	data.Output = strings.TrimSpace(buf.String())
	if runErr != nil {
		if ctx.Err() != nil {
			return fail(p, "ping", ctx.Err())
		}
		if _, isExit := runErr.(*exec.ExitError); !isExit {
			return p.Fail("ping", exit.Tool, "usage", "ping: %s", runErr)
		}
		if p.JSON {
			return p.Result("ping", exit.NotApplied, data, nil)
		}
		return p.Fail("ping", exit.NotApplied, "unreachable", "%s (%s) не ответил на ping", target, ip)
	}
	return p.Result("ping", exit.OK, data, nil)
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
