// kai is the admin CLI for the coordinator.
//
// Connection settings come from flags or env:
//
//	KAI_URL, KAI_ADMIN_TOKEN, KAI_FINGERPRINT
//
// Commands:
//
//	kai token create [--name HINT] [--ttl SECONDS]
//	kai node list
//	kai node delete <node_id>
//	kai peer add-static <name> [--png FILE]
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mdp/qrterminal/v3"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/kaidstor/home-kai/internal/agent"
	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/text"
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
	case os.Args[1] == "peer" && arg(2) == "add-static":
		cmdPeerAddStatic(ctx, os.Args[3:])
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
  kai policy list|add|delete ...
  kai events [--limit N]
  kai peer add-static <name> [--png FILE] [--full]
  kai status                # local agent view: peers, direct/relay, traffic
  kai ping <name|ip>        # resolve device name, ping, show path
  kai lock init|sign|status|disable [--key FILE]   # network lock (signed peer bindings)

admin commands need env: KAI_URL, KAI_ADMIN_TOKEN, KAI_FINGERPRINT;
status/ping talk to the local kai-agent socket instead.`)
	os.Exit(2)
}

func client() *agent.Client {
	url := os.Getenv("KAI_URL")
	token := os.Getenv("KAI_ADMIN_TOKEN")
	fp := os.Getenv("KAI_FINGERPRINT")
	if url == "" || token == "" {
		fatal(fmt.Errorf("KAI_URL and KAI_ADMIN_TOKEN must be set"))
	}
	if fp == "" {
		fmt.Fprintln(os.Stderr, "warning: KAI_FINGERPRINT is not set — TLS is NOT verified")
	}
	c, err := agent.NewClient(url, fp, token)
	if err != nil {
		fatal(err)
	}
	return c
}

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

func cmdNodeList(ctx context.Context) {
	var nodes []api.NodeInfo
	_, err := client().Do(ctx, http.MethodGet, "/v1/admin/nodes", nil, &nodes)
	if err != nil {
		fatal(err)
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tROLE\tOS\tIP\tDNS\tLAST SEEN")
	for _, n := range nodes {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			n.NodeID, n.Hostname, n.Role, n.OS, n.OverlayIP, n.DNSName, n.LastSeen.Local().Format("2006-01-02 15:04:05"))
	}
	w.Flush()
}

func cmdNodeDelete(ctx context.Context, args []string) {
	if len(args) < 1 {
		usage()
	}
	_, err := client().Do(ctx, http.MethodDelete, "/v1/admin/nodes/"+args[0], nil, nil)
	if err != nil {
		fatal(err)
	}
	fmt.Println("deleted", args[0])
}

// cmdNodeRoutes enables subnet routes advertised by a node:
//
//	kai node routes <node_id> --enable 192.168.1.0/24,172.18.0.0/16
//	kai node routes <node_id> --enable ""        # disable all
func cmdNodeRoutes(ctx context.Context, args []string) {
	if len(args) < 1 || args[0] == "" || args[0][0] == '-' {
		usage()
	}
	id := args[0]
	fs := flag.NewFlagSet("node routes", flag.ExitOnError)
	enable := fs.String("enable", "", "comma-separated subset of the node's advertised routes to enable")
	_ = fs.Parse(args[1:])

	enabled := text.Fields(*enable)
	_, err := client().Do(ctx, http.MethodPost, "/v1/admin/nodes/"+id+"/routes",
		api.NodeRoutesRequest{Enabled: enabled}, nil)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("enabled routes for %s: %s\n", id, strings.Join(enabled, ", "))
}

func cmdPeerAddStatic(ctx context.Context, args []string) {
	if len(args) < 1 || args[0] == "" || args[0][0] == '-' {
		usage()
	}
	name := args[0]
	fs := flag.NewFlagSet("peer add-static", flag.ExitOnError)
	pngPath := fs.String("png", "", "also write the QR code as a PNG file")
	full := fs.Bool("full", false, "full tunnel: route ALL traffic through the hub (exit node)")
	_ = fs.Parse(args[1:])

	var resp api.StaticPeerCreateResponse
	_, err := client().Do(ctx, http.MethodPost, "/v1/admin/static-peers",
		api.StaticPeerCreateRequest{Name: name, Full: *full}, &resp)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("static peer %q: %s", resp.Name, resp.OverlayIP)
	if resp.DNSName != "" {
		fmt.Printf(" (%s)", resp.DNSName)
	}
	fmt.Printf("\n\n%s\n", resp.ConfINI)
	qrterminal.GenerateWithConfig(resp.ConfINI, qrterminal.Config{
		Level: qrterminal.L, Writer: os.Stdout,
		BlackChar: qrterminal.BLACK, WhiteChar: qrterminal.WHITE, QuietZone: 1,
	})
	if *pngPath != "" {
		if err := qrcode.WriteFile(resp.ConfINI, qrcode.Medium, 512, *pngPath); err != nil {
			fatal(err)
		}
		fmt.Println("QR PNG written to", *pngPath)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "kai:", err)
	os.Exit(1)
}
