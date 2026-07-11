package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
)

func cmdTokenCreate(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("token create", flag.ExitOnError)
	name := fs.String("name", "", "name hint (overrides node hostname)")
	ttl := fs.Int("ttl", 3600, "token lifetime in seconds")
	_ = fs.Parse(args)

	var resp api.TokenCreateResponse
	_, err := client().Do(ctx, http.MethodPost, "/v1/admin/tokens",
		api.TokenCreateRequest{NameHint: *name, TTLSec: *ttl}, &resp)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("token:       %s\nexpires_at:  %s\nfingerprint: %s\n\njoin command:\n  %s\n",
		resp.Token, resp.ExpiresAt.Format(time.RFC3339), resp.Fingerprint, resp.JoinCommand)
}
