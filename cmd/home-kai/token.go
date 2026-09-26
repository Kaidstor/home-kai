package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/exit"
	"github.com/kaidstor/home-kai/internal/output"
)

func cmdTokenCreate(ctx context.Context, p *output.Printer, args []string) int {
	const command = "token create"
	fs := newFlagSet(command)
	name := fs.String("name", "", "")
	ttl := fs.Int("ttl", 3600, "")
	if _, code, ok := parse(p, command, "token create [--name HINT] [--ttl SECONDS]", fs, args, 0); !ok {
		return code
	}
	a, code, ok := adminClient(p, command)
	if !ok {
		return code
	}
	var resp api.TokenCreateResponse
	if err := a.do(ctx, http.MethodPost, "/v1/admin/tokens",
		api.TokenCreateRequest{NameHint: *name, TTLSec: *ttl}, &resp); err != nil {
		return fail(p, command, err)
	}
	return p.Result(command, exit.OK, resp, func(w io.Writer) {
		fmt.Fprintf(w, "token:       %s\nexpires_at:  %s\nfingerprint: %s\n\njoin-команда:\n  %s\n",
			resp.Token, resp.ExpiresAt.Format(time.RFC3339), resp.Fingerprint, resp.JoinCommand)
	})
}
