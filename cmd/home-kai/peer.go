package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/mdp/qrterminal/v3"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/text"
)

// cmdPeerCreate registers a static peer (WireGuard-app device: phone, router)
// and prints its config as text and a terminal QR code.
func cmdPeerCreate(ctx context.Context, args []string) {
	if len(args) < 1 || args[0] == "" || args[0][0] == '-' {
		usage()
	}
	name := args[0]
	fs := flag.NewFlagSet("peer create", flag.ExitOnError)
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

func cmdPeerList(ctx context.Context) {
	var peers []api.StaticPeerInfo
	if _, err := client().Do(ctx, http.MethodGet, "/v1/admin/static-peers", nil, &peers); err != nil {
		fatal(err)
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tIP\tDNS\tTAGS\tCREATED")
	for _, p := range peers {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			p.ID, p.Name, p.OverlayIP, p.DNSName, text.JoinOr(p.Tags, "—"),
			p.CreatedAt.Local().Format("2006-01-02 15:04:05"))
	}
	w.Flush()
}

func cmdPeerTag(ctx context.Context, args []string) {
	if len(args) < 1 {
		usage()
	}
	id := args[0]
	fs := flag.NewFlagSet("peer tag", flag.ExitOnError)
	tags := fs.String("tags", "", "comma-separated group tags (empty clears)")
	_ = fs.Parse(args[1:])
	if _, err := client().Do(ctx, http.MethodPost, "/v1/admin/static-peers/"+id+"/tags",
		api.TagsRequest{Tags: text.Fields(*tags)}, nil); err != nil {
		fatal(err)
	}
	fmt.Printf("tags for %s: %s\n", id, *tags)
}
