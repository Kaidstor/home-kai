package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/apiclient"
	"github.com/kaidstor/home-kai/internal/exit"
	"github.com/kaidstor/home-kai/internal/output"
)

type check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Details string `json:"details"`
}

// cmdDoctor answers "why doesn't it work": where the settings come from,
// which token was picked up, and whether the coordinator accepts it. Every
// check is reported even after a failure; the exit code is the first failure.
func cmdDoctor(ctx context.Context, p *output.Printer, args []string) int {
	const command = "doctor"
	if _, code, ok := parse(p, command, command, newFlagSet(command), args, 0); !ok {
		return code
	}
	var checks []check
	code := exit.OK
	failed := func(c int) {
		if code == exit.OK {
			code = c
		}
	}

	s, err := loadSettings()
	if err != nil {
		checks = append(checks, check{Name: "config", Details: err.Error()})
		failed(exit.Tool)
		return doctorResult(p, code, checks)
	}
	checks = append(checks, configCheck(s))
	if !checks[0].OK {
		failed(exit.Tool)
	}

	if s.File.Token != "" {
		if s.TokenRef != "" {
			p.Warn("в %s лежит токен открытым текстом, хотя задан token_ref — удали поле token", s.Path)
		} else {
			p.Warn("токен открытым текстом в %s — перенеси его в sec и задай token_ref: "+
				"home-kai login --url URL --fingerprint HEX --token-ref <проект>/<KEY>", s.Path)
		}
	}

	tok, err := s.token()
	if err != nil {
		checks = append(checks, check{Name: "token", Details: err.Error()})
		failed(exit.Tool)
	} else {
		checks = append(checks, check{Name: "token", OK: true, Details: tok.Source + ", " + mask(tok.Value)})
	}

	switch {
	case !checks[0].OK || err != nil:
		checks = append(checks, check{Name: "coordinator", Details: "не проверен: нет настроек или токена"})
	default:
		c, err := apiclient.New(s.URL, s.Fingerprint, tok.Value)
		if err != nil {
			checks = append(checks, check{Name: "coordinator", Details: err.Error()})
			failed(exit.Tool)
			break
		}
		var nodes []api.NodeInfo
		start := time.Now()
		if err := (admin{c: c}).get(ctx, "/v1/admin/nodes", &nodes); err != nil {
			ec, kind := classify(err)
			checks = append(checks, check{Name: "coordinator", Details: kind + ": " + err.Error()})
			failed(ec)
			break
		}
		online := 0
		for _, n := range nodes {
			if n.Online {
				online++
			}
		}
		checks = append(checks, check{Name: "coordinator", OK: true, Details: fmt.Sprintf(
			"%s отвечает за %d мс, узлов %d (онлайн %d)", s.URL, time.Since(start).Milliseconds(), len(nodes), online)})
	}
	return doctorResult(p, code, checks)
}

func configCheck(s settings) check {
	file := s.Path + " (нет файла)"
	if s.Exists {
		file = s.Path
	}
	if s.URL == "" || s.Fingerprint == "" {
		return check{Name: "config", Details: file + ": нет url или fingerprint — home-kai login или KAI_URL и KAI_FINGERPRINT"}
	}
	details := fmt.Sprintf("%s; url из %s, fingerprint из %s", file, s.URLSource, s.FingerprintSource)
	if s.TokenRef != "" {
		details += fmt.Sprintf(", token_ref %s из %s", s.TokenRef, s.TokenRefSource)
	}
	return check{Name: "config", OK: true, Details: details}
}

func doctorResult(p *output.Printer, code int, checks []check) int {
	return p.Result("doctor", code, map[string]any{"checks": checks}, func(w io.Writer) {
		for _, ch := range checks {
			mark := "fail"
			if ch.OK {
				mark = "ok  "
			}
			fmt.Fprintf(w, "%s  %-12s %s\n", mark, ch.Name, ch.Details)
		}
	})
}
