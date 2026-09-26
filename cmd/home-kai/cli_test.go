package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/exit"
	"github.com/kaidstor/home-kai/internal/output"
)

func TestSplitGlobalFlags(t *testing.T) {
	jsonMode, rest := splitGlobalFlags([]string{"node", "--json", "list"})
	if !jsonMode || !reflect.DeepEqual(rest, []string{"node", "list"}) {
		t.Fatalf("got %v %v", jsonMode, rest)
	}
	jsonMode, _ = splitGlobalFlags([]string{"--json", "status", "--human"})
	if jsonMode {
		t.Fatal("the last of --json/--human must win")
	}
}

func TestParseArgsFlagsAfterPositional(t *testing.T) {
	fs := newFlagSet("node tag")
	tags := fs.String("tags", "", "")
	pos, err := parseArgs(fs, []string{"n-1", "--tags", "a,b"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pos, []string{"n-1"}) || *tags != "a,b" {
		t.Fatalf("pos=%v tags=%q", pos, *tags)
	}
}

func TestParseArgsEmptyFlagValue(t *testing.T) {
	fs := newFlagSet("node routes")
	enable := fs.String("enable", "x", "")
	pos, err := parseArgs(fs, []string{"n-1", "--enable", ""})
	if err != nil || len(pos) != 1 || *enable != "" {
		t.Fatalf("pos=%v enable=%q err=%v", pos, *enable, err)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{&apiError{Status: 401, Err: errors.New("x")}, exit.Tool, "auth"},
		{&apiError{Status: 404, Err: errors.New("x")}, exit.NotFound, "not_found"},
		{&apiError{Status: 409, Err: errors.New("x")}, exit.Tool, "api"},
		{&apiError{Status: 0, Err: errors.New("coordinator cert fingerprint mismatch: got ab")}, exit.Tool, "config"},
		{&apiError{Status: 0, Err: errors.New("dial tcp: connection refused")}, exit.Tool, "network"},
		{&apiError{Status: 0, Err: fmt.Errorf("wrap: %w", context.DeadlineExceeded)}, exit.Timeout, "timeout"},
		{localErr(errors.New("dial unix: no such file")), exit.Tool, "agent_down"},
		{localErr(os.ErrPermission), exit.Tool, "auth"},
	}
	for _, c := range cases {
		code, kind := classify(c.err)
		if code != c.code || kind != c.kind {
			t.Errorf("%v: got %d/%s, want %d/%s", c.err, code, kind, c.code, c.kind)
		}
	}
}

// writeFakeSec puts a `sec` stub first in PATH that prints value for `get`.
func writeFakeSec(t *testing.T, value string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n[ \"$1\" = get ] && printf '%s\\n' '" + value + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "sec"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func writeConfig(t *testing.T, cfg adminConfig) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin.json")
	if err := saveAdminConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME_KAI_CONFIG", path)
	for _, k := range []string{"KAI_URL", "KAI_FINGERPRINT", "KAI_TOKEN_REF", "KAI_ADMIN_TOKEN"} {
		t.Setenv(k, "")
	}
	return path
}

func TestTokenSources(t *testing.T) {
	path := writeConfig(t, adminConfig{URL: "https://h:8443", Fingerprint: "ab", TokenRef: "proj/KEY", Token: "from-file"})
	writeFakeSec(t, "from-sec")

	s, err := loadSettings()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.token()
	if err != nil || tok.Value != "from-sec" || tok.Source != "sec:proj/KEY" {
		t.Fatalf("token_ref must win over the file: %+v %v", tok, err)
	}

	t.Setenv("KAI_ADMIN_TOKEN", "from-env")
	tok, _ = s.token()
	if tok.Value != "from-env" || tok.Source != "env:KAI_ADMIN_TOKEN" {
		t.Fatalf("env must win: %+v", tok)
	}

	t.Setenv("KAI_ADMIN_TOKEN", "")
	if err := saveAdminConfig(path, adminConfig{URL: "https://h:8443", Fingerprint: "ab", Token: "from-file"}); err != nil {
		t.Fatal(err)
	}
	s, _ = loadSettings()
	tok, _ = s.token()
	if tok.Value != "from-file" || !strings.HasPrefix(tok.Source, "file:") {
		t.Fatalf("legacy plaintext is the last source: %+v", tok)
	}
}

func TestSettingsEnvOverlay(t *testing.T) {
	path := writeConfig(t, adminConfig{URL: "https://file:8443", Fingerprint: "ff"})
	t.Setenv("KAI_URL", "https://env:8443")
	s, err := loadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if s.URL != "https://env:8443" || s.URLSource != "env:KAI_URL" {
		t.Fatalf("url: %q from %q", s.URL, s.URLSource)
	}
	if s.Fingerprint != "ff" || s.FingerprintSource != "file:"+path {
		t.Fatalf("fingerprint: %q from %q", s.Fingerprint, s.FingerprintSource)
	}
}

func TestLoginWithRefDoesNotStoreToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	if err := saveAdminConfig(path, adminConfig{URL: "u", Fingerprint: "f", TokenRef: "p/K"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), `"token"`) {
		t.Fatalf("empty token must be omitted: %s", raw)
	}
}

func TestMask(t *testing.T) {
	if got := mask("abcdefghij"); got != "ab…ij (10 символов)" {
		t.Fatal(got)
	}
	if got := mask("abc"); got != "(3 символов)" {
		t.Fatal(got)
	}
}

func TestResolveDevice(t *testing.T) {
	st := api.LocalStatus{
		Hosts: []api.HostEntry{{Name: "nas" + api.HostsSuffix, IP: "100.87.0.5"}},
		Peers: []api.LocalPeer{{Hostname: "mac", OverlayIP: "100.87.0.7"}},
	}
	for target, want := range map[string]string{
		"nas": "100.87.0.5", "nas" + api.HostsSuffix: "100.87.0.5",
		"mac": "100.87.0.7", "100.87.0.9": "100.87.0.9", "nope": "",
	} {
		if got := resolveDevice(st, target); got != want {
			t.Errorf("%s: got %q want %q", target, got, want)
		}
	}
}

func TestUsageErrorIsEnvelopeInJSON(t *testing.T) {
	var out bytes.Buffer
	p := output.New(true)
	p.Out = &out
	code := cmdNodeDelete(context.Background(), p, nil)
	if code != exit.Tool {
		t.Fatalf("code %d", code)
	}
	var env output.Envelope
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("stdout is not an envelope: %v\n%s", err, out.String())
	}
	if env.Exit != exit.Tool || env.Error == nil || env.Error.Kind != "usage" || env.Command != "node delete" {
		t.Fatalf("envelope: %+v", env)
	}
}
