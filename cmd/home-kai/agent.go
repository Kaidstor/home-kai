package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/exit"
	"github.com/kaidstor/home-kai/internal/output"
)

// `home-kai agent up|down|status` drives the local kai-agent service so the
// overlay can be switched off without remembering the launchd/systemd
// incantation — e.g. to route the machine through another tunnel that
// carries 100.87/16 itself. Down/up need root: the command re-executes
// itself under sudo when it is not.
func cmdAgent(ctx context.Context, p *output.Printer, args []string) int {
	const synopsis = "agent up|down|status"
	pos, code, ok := parse(p, "agent", synopsis, newFlagSet("agent"), args, 1)
	if !ok {
		return code
	}
	command := "agent " + pos[0]
	switch pos[0] {
	case "status", "down", "stop", "up", "start":
	default:
		return p.Fail("agent", exit.Tool, "usage", "использование: home-kai %s", synopsis)
	}
	svc, err := detectAgentService()
	if err != nil {
		return p.Fail(command, err.code, err.kind, "%s", err.msg)
	}
	switch pos[0] {
	case "status":
		return cmdAgentStatus(ctx, p, svc)
	case "down", "stop":
		if code, reexeced := requireRoot(p, command); reexeced {
			return code
		}
		if err := svc.stop(); err != nil {
			return p.Fail(command, exit.Tool, "service", "%s", err)
		}
		// bootout / systemctl stop return before the job is gone; without the
		// wait a chained `agent status` still sees the service loaded.
		if !waitFor(10*time.Second, func() bool { r, _ := svc.running(); return !r }) {
			return p.Fail(command, exit.NotApplied, "not_applied", "kai-agent всё ещё загружен спустя 10 с")
		}
		return p.Result(command, exit.OK, agentData{Service: svc.describe(), Running: false}, func(w io.Writer) {
			fmt.Fprintln(w, "kai-agent остановлен; вернуть — home-kai agent up")
		})
	default:
		if code, reexeced := requireRoot(p, command); reexeced {
			return code
		}
		if err := svc.start(); err != nil {
			return p.Fail(command, exit.Tool, "service", "%s", err)
		}
		if !waitFor(10*time.Second, func() bool { _, err := localStatus(ctx); return err == nil }) {
			return p.Fail(command, exit.NotApplied, "not_applied", "kai-agent запущен, но его локальный сокет не поднялся за 10 с")
		}
		return p.Result(command, exit.OK, agentData{Service: svc.describe(), Running: true}, func(w io.Writer) {
			fmt.Fprintln(w, "kai-agent запущен")
		})
	}
}

type agentData struct {
	Service    string           `json:"service"`
	Running    bool             `json:"running"`
	Agent      *api.LocalStatus `json:"agent,omitempty"`
	AgentError string           `json:"agent_error,omitempty"`
}

func cmdAgentStatus(ctx context.Context, p *output.Printer, svc agentService) int {
	loaded, _ := svc.running()
	data := agentData{Service: svc.describe(), Running: loaded}
	if loaded {
		if st, err := localStatus(ctx); err != nil {
			data.AgentError = err.Error()
		} else {
			data.Agent = &st
		}
	}
	return p.Result("agent status", exit.OK, data, func(w io.Writer) {
		if !data.Running {
			fmt.Fprintf(w, "служба: остановлена (%s)\n", data.Service)
			return
		}
		fmt.Fprintf(w, "служба: запущена (%s)\n", data.Service)
		if data.Agent == nil {
			fmt.Fprintf(w, "агент: %s\n", data.AgentError)
			return
		}
		st := data.Agent
		fmt.Fprintf(w, "агент: %s %s, пиров %d, netmap v%d\n", st.Hostname, st.OverlayIP, len(st.Peers), st.NetmapVersion)
	})
}

// requireRoot re-runs the current command under sudo and reports the child's
// exit code; launchctl bootout / systemctl stop refuse silently or with a
// cryptic error otherwise. Without a terminal sudo cannot ask for the
// password, so that case fails up front instead of hanging or exiting 1.
func requireRoot(p *output.Printer, command string) (int, bool) {
	if os.Geteuid() == 0 {
		return 0, false
	}
	self, err := os.Executable()
	if err != nil {
		return p.Fail(command, exit.Tool, "service", "%s", err), true
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) && exec.Command("sudo", "-n", "true").Run() != nil {
		return p.Fail(command, exit.Tool, "auth",
			"нужен root, а sudo без терминала пароль не спросит: запусти в терминале или через sudo home-kai %s", command), true
	}
	cmd := exec.Command("sudo", append([]string{self}, os.Args[1:]...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), true
	}
	if err != nil {
		return p.Fail(command, exit.Tool, "service", "sudo: %s", err), true
	}
	return exit.OK, true
}

type agentService interface {
	running() (bool, error)
	stop() error
	start() error
	describe() string
}

type detectError struct {
	code int
	kind string
	msg  string
}

func detectAgentService() (agentService, *detectError) {
	switch runtime.GOOS {
	case "darwin":
		return detectLaunchd()
	case "linux":
		return systemdService{unit: "kai-agent"}, nil
	default:
		return nil, &detectError{exit.Tool, "unsupported", "управление службой kai-agent на " + runtime.GOOS + " не поддерживается"}
	}
}

// --- systemd ---------------------------------------------------------------

type systemdService struct{ unit string }

func (s systemdService) describe() string { return "systemd unit " + s.unit }

func (s systemdService) running() (bool, error) {
	out, _ := exec.Command("systemctl", "is-active", s.unit).Output()
	return strings.TrimSpace(string(out)) == "active", nil
}

func (s systemdService) stop() error  { return runCmd("systemctl", "stop", s.unit) }
func (s systemdService) start() error { return runCmd("systemctl", "start", s.unit) }

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
	return runCmd("launchctl", "bootout", "system/"+s.label)
}

func (s launchdService) start() error {
	return runCmd("launchctl", "bootstrap", "system", s.plist)
}

var plistLabelRe = regexp.MustCompile(`(?s)<key>\s*Label\s*</key>\s*<string>\s*([^<]+?)\s*</string>`)

// The daemon's plist is whichever one in /Library/LaunchDaemons launches
// kai-agent — the label differs between installs (dev.kai.agent in deploy/,
// com.<user>.kai-agent on hand-installed machines).
func detectLaunchd() (agentService, *detectError) {
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
	return nil, &detectError{exit.NotFound, "not_found", "в /Library/LaunchDaemons нет plist с kai-agent"}
}

func waitFor(timeout time.Duration, ok func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if ok() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
