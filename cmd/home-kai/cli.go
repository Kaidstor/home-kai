package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"

	"github.com/kaidstor/home-kai/internal/apiclient"
	"github.com/kaidstor/home-kai/internal/exit"
	"github.com/kaidstor/home-kai/internal/output"
)

// splitGlobalFlags pulls --json/--human out of any position in argv: the
// subcommands parse the rest with their own FlagSet, which fails on unknown
// flags.
func splitGlobalFlags(args []string) (jsonMode bool, rest []string) {
	for _, a := range args {
		switch a {
		case "--json":
			jsonMode = true
		case "--human":
			jsonMode = false
		default:
			rest = append(rest, a)
		}
	}
	return jsonMode, rest
}

// parseArgs parses flags that also follow positional arguments. The stock
// flag.Parse stops at the first non-flag, and `node tag <id> --tags a` would
// silently drop --tags.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parse runs parseArgs and checks the positional count; on failure it has
// already printed the usage error and returns the exit code.
func parse(p *output.Printer, command, synopsis string, fs *flag.FlagSet, args []string, want int) ([]string, int, bool) {
	pos, err := parseArgs(fs, args)
	if err != nil {
		return nil, p.Fail(command, exit.Tool, "usage", "%s; использование: home-kai %s", err, synopsis), false
	}
	if len(pos) != want {
		return nil, p.Fail(command, exit.Tool, "usage", "использование: home-kai %s", synopsis), false
	}
	for _, a := range pos {
		if a == "" {
			return nil, p.Fail(command, exit.Tool, "usage", "пустой аргумент; использование: home-kai %s", synopsis), false
		}
	}
	return pos, 0, true
}

// admin wraps the coordinator client so every error carries the HTTP status
// for classify.
type admin struct{ c *apiclient.Client }

type apiError struct {
	Status int
	Err    error
}

func (e *apiError) Error() string { return e.Err.Error() }
func (e *apiError) Unwrap() error { return e.Err }

func (a admin) do(ctx context.Context, method, path string, in, out any) error {
	status, err := a.c.Do(ctx, method, path, in, out)
	if err != nil {
		return &apiError{Status: status, Err: err}
	}
	return nil
}

func (a admin) get(ctx context.Context, path string, out any) error {
	return a.do(ctx, http.MethodGet, path, nil, out)
}

// adminClient builds the coordinator client from settings and token; on
// failure it has already printed the error.
func adminClient(p *output.Printer, command string) (admin, int, bool) {
	s, err := loadSettings()
	if err != nil {
		return admin{}, p.Fail(command, exit.Tool, "config", "%s", err), false
	}
	if s.URL == "" || s.Fingerprint == "" {
		return admin{}, p.Fail(command, exit.Tool, "config",
			"нет адреса или отпечатка координатора: home-kai login --url URL --fingerprint HEX --token-ref <проект>/<KEY> "+
				"или переменные KAI_URL и KAI_FINGERPRINT (отпечаток: journalctl -u kai-coordinator | grep fingerprint)"), false
	}
	tok, err := s.token()
	if err != nil {
		return admin{}, p.Fail(command, exit.Tool, "auth", "%s", err), false
	}
	c, err := apiclient.New(s.URL, s.Fingerprint, tok.Value)
	if err != nil {
		return admin{}, p.Fail(command, exit.Tool, "config", "%s", err), false
	}
	return admin{c: c}, 0, true
}

// Local agent socket failures — the agent is down, or the socket is
// root:kai 0660 and we are neither.
var (
	errAgentDown   = errors.New("kai-agent не отвечает на локальном сокете — служба запущена? (home-kai agent status)")
	errAgentAccess = errors.New("нет доступа к сокету kai-agent: запусти через sudo или добавь себя в группу kai (groupadd kai && usermod -aG kai $USER)")
)

// classify maps an error to the exit code and envelope kind.
func classify(err error) (int, string) {
	var ae *apiError
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return exit.Timeout, "timeout"
	case errors.Is(err, context.Canceled):
		return exit.Tool, "interrupted"
	case errors.Is(err, errAgentAccess):
		return exit.Tool, "auth"
	case errors.Is(err, errAgentDown):
		return exit.Tool, "agent_down"
	case errors.As(err, &ae):
		switch {
		case ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden:
			return exit.Tool, "auth"
		case ae.Status == http.StatusNotFound:
			return exit.NotFound, "not_found"
		case ae.Status >= 400:
			return exit.Tool, "api"
		case strings.Contains(ae.Err.Error(), "fingerprint mismatch"):
			return exit.Tool, "config"
		default:
			return exit.Tool, "network"
		}
	}
	return exit.Tool, "api"
}

// fail prints err classified by classify.
func fail(p *output.Printer, command string, err error) int {
	code, kind := classify(err)
	msg := err.Error()
	switch kind {
	case "auth":
		if !errors.Is(err, errAgentAccess) {
			msg += " — координатор отверг токен: home-kai doctor"
		}
	case "config":
		msg += " — отпечаток в настройках не совпал с сертификатом координатора"
	}
	return p.Fail(command, code, kind, "%s", msg)
}

// localErr turns a dial error on the agent socket into errAgentDown or
// errAgentAccess.
func localErr(err error) error {
	switch {
	case errors.Is(err, os.ErrPermission), errors.Is(err, syscall.EACCES):
		return errAgentAccess
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return err
	default:
		return fmt.Errorf("%w: %v", errAgentDown, err)
	}
}
