package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// `home-kai agent up|down|status` drives the local kai-agent service so the
// overlay can be switched off without remembering the launchd/systemd
// incantation — e.g. to route the machine through another tunnel that
// carries 100.87/16 itself. Down/up need root: the command re-executes
// itself under sudo when it is not.
func cmdAgent(ctx context.Context, args []string) {
	if len(args) == 0 {
		usage()
	}
	svc, err := detectAgentService()
	if err != nil {
		fatal(err)
	}
	switch args[0] {
	case "status":
		cmdAgentStatus(ctx, svc)
	case "down", "stop":
		requireRoot()
		if err := svc.stop(); err != nil {
			fatal(err)
		}
		fmt.Println("kai-agent stopped; `home-kai agent up` brings it back")
	case "up", "start":
		requireRoot()
		if err := svc.start(); err != nil {
			fatal(err)
		}
		fmt.Println("kai-agent started")
	default:
		usage()
	}
}

func cmdAgentStatus(ctx context.Context, svc agentService) {
	loaded, err := svc.running()
	if err != nil {
		fatal(err)
	}
	if !loaded {
		fmt.Printf("service: stopped (%s)\n", svc.describe())
		return
	}
	fmt.Printf("service: running (%s)\n", svc.describe())
	st, err := localStatus(ctx)
	if err != nil {
		fmt.Printf("agent: %v\n", err)
		return
	}
	fmt.Printf("agent: %s %s, %d peers, netmap v%d\n", st.Hostname, st.OverlayIP, len(st.Peers), st.NetmapVersion)
}

// requireRoot re-runs the current command under sudo. launchctl bootout /
// systemctl stop refuse silently or with a cryptic error otherwise.
func requireRoot() {
	if os.Geteuid() == 0 {
		return
	}
	self, err := os.Executable()
	if err != nil {
		fatal(err)
	}
	cmd := exec.Command("sudo", append([]string{self}, os.Args[1:]...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		os.Exit(exit.ExitCode())
	}
	if err != nil {
		fatal(err)
	}
	os.Exit(0)
}

type agentService interface {
	running() (bool, error)
	stop() error
	start() error
	describe() string
}

func detectAgentService() (agentService, error) {
	switch runtime.GOOS {
	case "darwin":
		return detectLaunchd()
	case "linux":
		return systemdService{unit: "kai-agent"}, nil
	default:
		return nil, fmt.Errorf("agent service control is not supported on %s", runtime.GOOS)
	}
}

// --- systemd ---------------------------------------------------------------

type systemdService struct{ unit string }

func (s systemdService) describe() string { return "systemd unit " + s.unit }

func (s systemdService) running() (bool, error) {
	out, _ := exec.Command("systemctl", "is-active", s.unit).Output()
	return strings.TrimSpace(string(out)) == "active", nil
}

func (s systemdService) stop() error  { return run("systemctl", "stop", s.unit) }
func (s systemdService) start() error { return run("systemctl", "start", s.unit) }

// --- launchd ---------------------------------------------------------------

type launchdService struct {
	label string
	plist string
}

func (s launchdService) describe() string { return "launchd " + s.label }

// Bootout removes the job from launchd entirely (KeepAlive would otherwise
// respawn it), so "loaded" is the right notion of running here.
func (s launchdService) running() (bool, error) {
	err := exec.Command("launchctl", "print", "system/"+s.label).Run()
	return err == nil, nil
}

func (s launchdService) stop() error {
	return run("launchctl", "bootout", "system/"+s.label)
}

func (s launchdService) start() error {
	return run("launchctl", "bootstrap", "system", s.plist)
}

var plistLabelRe = regexp.MustCompile(`(?s)<key>\s*Label\s*</key>\s*<string>\s*([^<]+?)\s*</string>`)

// The daemon's plist is whichever one in /Library/LaunchDaemons launches
// kai-agent — the label differs between installs (dev.kai.agent in deploy/,
// com.<user>.kai-agent on hand-installed machines).
func detectLaunchd() (agentService, error) {
	matches, _ := filepath.Glob("/Library/LaunchDaemons/*.plist")
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(raw), "kai-agent") {
			continue
		}
		m := plistLabelRe.FindStringSubmatch(string(raw))
		if m == nil {
			continue
		}
		return launchdService{label: m[1], plist: path}, nil
	}
	return nil, errors.New("no kai-agent plist found in /Library/LaunchDaemons")
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
