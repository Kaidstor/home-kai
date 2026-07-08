package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kaidstor/home-kai/internal/api"
)

// The agent mirrors netmap host entries into a managed block in /etc/hosts —
// MagicDNS on the cheap: works offline, no resolver of our own, and macOS's
// mDNSResponder picks it up immediately.
const (
	hostsPath  = "/etc/hosts"
	hostsBegin = "# kai overlay begin — managed by kai-agent, do not edit"
	hostsEnd   = "# kai overlay end"
)

func renderHostsBlock(entries []api.HostEntry) string {
	if len(entries) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(hostsBegin + "\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "%-15s %s\n", e.IP, e.Name)
	}
	b.WriteString(hostsEnd + "\n")
	return b.String()
}

// stripManagedBlock removes a previous kai block, tolerating a missing end
// marker (truncates from the begin marker in that case).
func stripManagedBlock(s string) string {
	start := strings.Index(s, hostsBegin)
	if start == -1 {
		return s
	}
	end := strings.Index(s, hostsEnd)
	if end == -1 {
		return s[:start]
	}
	rest := strings.TrimPrefix(s[end+len(hostsEnd):], "\n")
	return s[:start] + rest
}

// updateHostsFile rewrites the managed block (nil entries removes it).
// Written via temp file + rename in the same directory so a crash can never
// leave a half-written /etc/hosts.
func updateHostsFile(entries []api.HostEntry) error {
	path := hostsPath
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	cur, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	next := stripManagedBlock(string(cur))
	if block := renderHostsBlock(entries); block != "" {
		if next != "" && !strings.HasSuffix(next, "\n") {
			next += "\n"
		}
		next += block
	}
	if next == string(cur) {
		return nil
	}
	tmp := path + ".kai-tmp"
	if err := os.WriteFile(tmp, []byte(next), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (a *Agent) syncHosts(entries []api.HostEntry) {
	if a.st.NoHosts {
		return
	}
	if err := updateHostsFile(entries); err != nil {
		a.log.Error("updating /etc/hosts failed", "err", err)
	}
}
