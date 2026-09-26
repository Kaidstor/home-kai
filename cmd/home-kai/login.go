package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/kaidstor/home-kai/internal/apiclient"
	"github.com/kaidstor/home-kai/internal/exit"
	"github.com/kaidstor/home-kai/internal/output"
)

const loginSynopsis = "login --url URL --fingerprint HEX [--token-ref <проект>/<KEY>]"

type loginData struct {
	Path        string `json:"path"`
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint"`
	TokenSource string `json:"token_source"`
	TokenMask   string `json:"token_mask"`
}

// cmdLogin verifies the credentials against the coordinator and only then
// saves them, so a typo'd token or fingerprint never ends up on disk.
func cmdLogin(ctx context.Context, p *output.Printer, args []string) int {
	const command = "login"
	fs := newFlagSet(command)
	url := fs.String("url", "", "")
	fp := fs.String("fingerprint", "", "")
	ref := fs.String("token-ref", "", "")
	if _, code, ok := parse(p, command, loginSynopsis, fs, args, 0); !ok {
		return code
	}
	if *url == "" || *fp == "" {
		return p.Fail(command, exit.Tool, "usage",
			"нужны --url и --fingerprint (отпечаток: journalctl -u kai-coordinator | grep fingerprint); использование: home-kai %s", loginSynopsis)
	}

	var tok token
	if *ref != "" {
		v, err := secGet(*ref)
		if err != nil {
			return p.Fail(command, exit.Tool, "auth", "sec get %s: %s", *ref, err)
		}
		if v == "" {
			return p.Fail(command, exit.Tool, "auth", "sec get %s: пустое значение", *ref)
		}
		tok = token{Value: v, Source: "sec:" + *ref}
	} else {
		v, err := readTokenStdin()
		if err != nil {
			return p.Fail(command, exit.Tool, "usage", "%s", err)
		}
		tok = token{Value: v, Source: "stdin"}
	}

	c, err := apiclient.New(*url, *fp, tok.Value)
	if err != nil {
		return p.Fail(command, exit.Tool, "config", "%s", err)
	}
	if err := (admin{c: c}).get(ctx, "/v1/admin/nodes", nil); err != nil {
		return fail(p, command, fmt.Errorf("проверка доступа не прошла: %w", err))
	}

	path := adminConfigPath()
	cfg := adminConfig{URL: *url, Fingerprint: *fp, TokenRef: *ref}
	if *ref == "" {
		cfg.Token = tok.Value
		p.Warn("токен сохранён в %s открытым текстом; лучше положить его в sec и перелогиниться с --token-ref", path)
	}
	if err := saveAdminConfig(path, cfg); err != nil {
		return p.Fail(command, exit.Tool, "config", "%s", err)
	}
	source := tok.Source
	if *ref == "" {
		source = "file:" + path
	}
	data := loginData{Path: path, URL: *url, Fingerprint: *fp, TokenSource: source, TokenMask: mask(tok.Value)}
	return p.Result(command, exit.OK, data, func(w io.Writer) {
		fmt.Fprintf(w, "доступ проверен, настройки сохранены в %s (0600); токен: %s; переменные KAI_* главнее файла\n",
			path, data.TokenSource)
	})
}

func cmdLogout(p *output.Printer, args []string) int {
	const command = "logout"
	if _, code, ok := parse(p, command, command, newFlagSet(command), args, 0); !ok {
		return code
	}
	path := adminConfigPath()
	err := os.Remove(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return p.Result(command, exit.OK, map[string]any{"path": path, "removed": false}, func(w io.Writer) {
			fmt.Fprintf(w, "не залогинен (нет %s)\n", path)
		})
	case err != nil:
		return p.Fail(command, exit.Tool, "config", "%s", err)
	}
	return p.Result(command, exit.OK, map[string]any{"path": path, "removed": true}, func(w io.Writer) {
		fmt.Fprintln(w, "удалён", path)
	})
}

// readTokenStdin asks for the admin token without echoing it on a terminal;
// a piped stdin (e.g. `ssh vps 'awk ...' | home-kai login ...`) is read as-is.
func readTokenStdin() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "admin-токен: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if len(b) == 0 {
			return "", fmt.Errorf("пустой токен")
		}
		return strings.TrimSpace(string(b)), nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("токен из stdin не прочитан: %w", err)
	}
	token := strings.TrimSpace(line)
	if token == "" {
		return "", fmt.Errorf("пустой токен")
	}
	return token, nil
}
