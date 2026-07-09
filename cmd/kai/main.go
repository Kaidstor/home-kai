// kai is the admin CLI for the coordinator.
//
// Admin commands read the connection settings from env:
//
//	KAI_URL, KAI_ADMIN_TOKEN, KAI_FINGERPRINT
//
// `kai status` / `kai ping` talk to the local kai-agent unix socket instead
// and need no credentials. Run kai without arguments for the command list.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/kaidstor/home-kai/internal/apiclient"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx := context.Background()
	switch {
	case os.Args[1] == "token" && arg(2) == "create":
		cmdTokenCreate(ctx, os.Args[3:])
	case os.Args[1] == "node" && arg(2) == "list":
		cmdNodeList(ctx)
	case os.Args[1] == "node" && arg(2) == "delete":
		cmdNodeDelete(ctx, os.Args[3:])
	case os.Args[1] == "node" && arg(2) == "routes":
		cmdNodeRoutes(ctx, os.Args[3:])
	case os.Args[1] == "node" && arg(2) == "approve":
		cmdNodeApprove(ctx, os.Args[3:])
	case os.Args[1] == "node" && arg(2) == "tag":
		cmdNodeTag(ctx, os.Args[3:])
	case os.Args[1] == "policy":
		cmdPolicy(ctx, os.Args[2:])
	case os.Args[1] == "events":
		cmdEvents(ctx, os.Args[2:])
	case os.Args[1] == "peer" && arg(2) == "create":
		cmdPeerCreate(ctx, os.Args[3:])
	case os.Args[1] == "peer" && arg(2) == "list":
		cmdPeerList(ctx)
	case os.Args[1] == "peer" && arg(2) == "tag":
		cmdPeerTag(ctx, os.Args[3:])
	case os.Args[1] == "status":
		cmdStatus(ctx)
	case os.Args[1] == "ping":
		cmdPing(ctx, os.Args[2:])
	case os.Args[1] == "lock":
		cmdLock(ctx, os.Args[2:])
	default:
		usage()
	}
}

func arg(i int) string {
	if len(os.Args) > i {
		return os.Args[i]
	}
	return ""
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  kai token create [--name HINT] [--ttl SECONDS]
  kai node list
  kai node delete <node_id>
  kai node routes <node_id> --enable CIDR,CIDR
  kai node approve <node_id>
  kai node tag <node_id> --tags a,b
  kai policy list|create|delete ...
  kai events [--limit N]
  kai peer create <name> [--png FILE] [--full]
  kai peer list
  kai peer tag <peer_id> --tags a,b
  kai status                # local agent view: peers, direct/relay, traffic
  kai ping <name|ip>        # resolve device name, ping, show path
  kai lock init|sign|status|disable [--key FILE]   # network lock (signed peer bindings)

admin commands need env: KAI_URL, KAI_ADMIN_TOKEN, KAI_FINGERPRINT;
status/ping talk to the local kai-agent socket instead.`)
	os.Exit(2)
}

func client() *apiclient.Client {
	url := os.Getenv("KAI_URL")
	token := os.Getenv("KAI_ADMIN_TOKEN")
	fp := os.Getenv("KAI_FINGERPRINT")
	if url == "" || token == "" {
		fatal(fmt.Errorf("KAI_URL and KAI_ADMIN_TOKEN must be set"))
	}
	if fp == "" {
		fmt.Fprintln(os.Stderr, "warning: KAI_FINGERPRINT is not set — TLS is NOT verified")
	}
	c, err := apiclient.New(url, fp, token)
	if err != nil {
		fatal(err)
	}
	return c
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "kai:", err)
	os.Exit(1)
}
