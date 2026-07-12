package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/kaidstor/home-kai/internal/apiclient"
)

// adminConfig is the saved admin session (`home-kai login`). The token is
// stored in plaintext, so the file lives next to lock.key with 0600 perms —
// same trust level as the network-lock private key.
type adminConfig struct {
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint"`
	Token       string `json:"token"`
}

func adminConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "kai-admin.json"
	}
	return filepath.Join(home, ".config", "kai", "admin.json")
}

func loadAdminConfig() (adminConfig, bool) {
	var cfg adminConfig
	b, err := os.ReadFile(adminConfigPath())
	if err != nil || json.Unmarshal(b, &cfg) != nil {
		return adminConfig{}, false
	}
	return cfg, cfg.URL != "" && cfg.Fingerprint != "" && cfg.Token != ""
}

// cmdLogin verifies the credentials against the coordinator and only then
// saves them, so a typo'd token or fingerprint never ends up on disk.
func cmdLogin(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	url := fs.String("url", "", "coordinator url (https://host:8443)")
	fp := fs.String("fingerprint", "", "coordinator TLS cert sha256 (64 hex chars)")
	_ = fs.Parse(args)
	if *url == "" || *fp == "" {
		fatal(fmt.Errorf("login needs --url and --fingerprint (fingerprint: journalctl -u kai-coordinator | grep fingerprint)"))
	}
	token, err := readTokenStdin()
	if err != nil {
		fatal(err)
	}
	c, err := apiclient.New(*url, *fp, token)
	if err != nil {
		fatal(err)
	}
	if _, err := c.Do(ctx, http.MethodGet, "/v1/admin/nodes", nil, nil); err != nil {
		fatal(fmt.Errorf("credentials check failed: %w", err))
	}
	path := adminConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		fatal(err)
	}
	b, _ := json.MarshalIndent(adminConfig{URL: *url, Fingerprint: *fp, Token: token}, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		fatal(err)
	}
	fmt.Println("logged in, credentials saved to", path, "(0600; KAI_* env still overrides)")
}

func cmdLogout() {
	path := adminConfigPath()
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("not logged in (no", path+")")
			return
		}
		fatal(err)
	}
	fmt.Println("removed", path)
}

// readTokenStdin asks for the admin token without echoing it on a terminal;
// a piped stdin (e.g. `ssh vps 'awk ...' | home-kai login ...`) is read as-is.
func readTokenStdin() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "admin token: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if len(b) == 0 {
			return "", fmt.Errorf("empty token")
		}
		return strings.TrimSpace(string(b)), nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("reading token from stdin: %w", err)
	}
	token := strings.TrimSpace(line)
	if token == "" {
		return "", fmt.Errorf("empty token")
	}
	return token, nil
}
