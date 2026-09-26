package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"text/tabwriter"

	"github.com/mdp/qrterminal/v3"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/exit"
	"github.com/kaidstor/home-kai/internal/output"
	"github.com/kaidstor/home-kai/internal/text"
)

type peerCreateData struct {
	api.StaticPeerCreateResponse
	PNG string `json:"png,omitempty"`
}

// cmdPeerCreate registers a static peer (WireGuard-app device: phone, router)
// and prints its config as text and a terminal QR code.
func cmdPeerCreate(ctx context.Context, p *output.Printer, args []string) int {
	const command = "peer create"
	fs := newFlagSet(command)
	pngPath := fs.String("png", "", "")
	full := fs.Bool("full", false, "")
	pos, code, ok := parse(p, command, "peer create <name> [--png FILE] [--full]", fs, args, 1)
	if !ok {
		return code
	}
	a, code, ok := adminClient(p, command)
	if !ok {
		return code
	}
	var resp api.StaticPeerCreateResponse
	if err := a.do(ctx, http.MethodPost, "/v1/admin/static-peers",
		api.StaticPeerCreateRequest{Name: pos[0], Full: *full}, &resp); err != nil {
		return fail(p, command, err)
	}
	data := peerCreateData{StaticPeerCreateResponse: resp}
	if *pngPath != "" {
		if err := qrcode.WriteFile(resp.ConfINI, qrcode.Medium, 512, *pngPath); err != nil {
			p.Warn("пир создан, но PNG с QR не записан: %s (конфиг — в conf_ini)", err)
		} else {
			data.PNG = *pngPath
		}
	}
	return p.Result(command, exit.OK, data, func(w io.Writer) {
		fmt.Fprintf(w, "static peer %q: %s", resp.Name, resp.OverlayIP)
		if resp.DNSName != "" {
			fmt.Fprintf(w, " (%s)", resp.DNSName)
		}
		fmt.Fprintf(w, "\n\n%s\n", resp.ConfINI)
		qrterminal.GenerateWithConfig(resp.ConfINI, qrterminal.Config{
			Level: qrterminal.L, Writer: w,
			BlackChar: qrterminal.BLACK, WhiteChar: qrterminal.WHITE, QuietZone: 1,
		})
		if data.PNG != "" {
			fmt.Fprintln(w, "QR в PNG:", data.PNG)
		}
	})
}

func cmdPeerList(ctx context.Context, p *output.Printer, args []string) int {
	const command = "peer list"
	if _, code, ok := parse(p, command, command, newFlagSet(command), args, 0); !ok {
		return code
	}
	a, code, ok := adminClient(p, command)
	if !ok {
		return code
	}
	peers := []api.StaticPeerInfo{}
	if err := a.get(ctx, "/v1/admin/static-peers", &peers); err != nil {
		return fail(p, command, err)
	}
	return p.Result(command, exit.OK, map[string]any{"peers": peers}, func(w io.Writer) {
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tIP\tDNS\tTAGS\tCREATED")
		for _, peer := range peers {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
				peer.ID, peer.Name, peer.OverlayIP, peer.DNSName, text.JoinOr(peer.Tags, "—"),
				peer.CreatedAt.Local().Format("2006-01-02 15:04:05"))
		}
		tw.Flush()
	})
}

func cmdPeerTag(ctx context.Context, p *output.Printer, args []string) int {
	return setTags(ctx, p, args, "peer tag", "peer tag <peer_id> --tags a,b", "/v1/admin/static-peers/")
}
