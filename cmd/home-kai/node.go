package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/tabwriter"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/exit"
	"github.com/kaidstor/home-kai/internal/output"
	"github.com/kaidstor/home-kai/internal/text"
)

func cmdNodeList(ctx context.Context, p *output.Printer, args []string) int {
	const command = "node list"
	if _, code, ok := parse(p, command, command, newFlagSet(command), args, 0); !ok {
		return code
	}
	a, code, ok := adminClient(p, command)
	if !ok {
		return code
	}
	nodes := []api.NodeInfo{}
	if err := a.get(ctx, "/v1/admin/nodes", &nodes); err != nil {
		return fail(p, command, err)
	}
	return p.Result(command, exit.OK, map[string]any{"nodes": nodes}, func(w io.Writer) {
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tROLE\tOS\tIP\tDNS\tLAST SEEN")
		for _, n := range nodes {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				n.NodeID, n.Hostname, n.Role, n.OS, n.OverlayIP, n.DNSName, n.LastSeen.Local().Format("2006-01-02 15:04:05"))
		}
		tw.Flush()
	})
}

func cmdNodeDelete(ctx context.Context, p *output.Printer, args []string) int {
	const command = "node delete"
	pos, code, ok := parse(p, command, "node delete <node_id>", newFlagSet(command), args, 1)
	if !ok {
		return code
	}
	a, code, ok := adminClient(p, command)
	if !ok {
		return code
	}
	id := pos[0]
	if err := a.do(ctx, http.MethodDelete, "/v1/admin/nodes/"+id, nil, nil); err != nil {
		return fail(p, command, err)
	}
	return p.Result(command, exit.OK, map[string]any{"node_id": id, "deleted": true}, func(w io.Writer) {
		fmt.Fprintln(w, "удалён", id)
	})
}

// cmdNodeRoutes enables subnet routes advertised by a node:
//
//	home-kai node routes <node_id> --enable 192.168.1.0/24,172.18.0.0/16
//	home-kai node routes <node_id> --enable ""        # disable all
func cmdNodeRoutes(ctx context.Context, p *output.Printer, args []string) int {
	const command = "node routes"
	fs := newFlagSet(command)
	enable := fs.String("enable", "", "")
	pos, code, ok := parse(p, command, "node routes <node_id> --enable CIDR,CIDR", fs, args, 1)
	if !ok {
		return code
	}
	a, code, ok := adminClient(p, command)
	if !ok {
		return code
	}
	id := pos[0]
	enabled := text.Fields(*enable)
	if err := a.do(ctx, http.MethodPost, "/v1/admin/nodes/"+id+"/routes",
		api.NodeRoutesRequest{Enabled: enabled}, nil); err != nil {
		return fail(p, command, err)
	}
	if enabled == nil {
		enabled = []string{}
	}
	return p.Result(command, exit.OK, map[string]any{"node_id": id, "enabled": enabled}, func(w io.Writer) {
		fmt.Fprintf(w, "включённые маршруты %s: %s\n", id, text.JoinOr(enabled, "—"))
	})
}

func cmdNodeApprove(ctx context.Context, p *output.Printer, args []string) int {
	const command = "node approve"
	pos, code, ok := parse(p, command, "node approve <node_id>", newFlagSet(command), args, 1)
	if !ok {
		return code
	}
	a, code, ok := adminClient(p, command)
	if !ok {
		return code
	}
	id := pos[0]
	if err := a.do(ctx, http.MethodPost, "/v1/admin/nodes/"+id+"/approve", nil, nil); err != nil {
		return fail(p, command, err)
	}
	return p.Result(command, exit.OK, map[string]any{"node_id": id, "approved": true}, func(w io.Writer) {
		fmt.Fprintln(w, "одобрен", id)
	})
}

func cmdNodeTag(ctx context.Context, p *output.Printer, args []string) int {
	return setTags(ctx, p, args, "node tag", "node tag <node_id> --tags a,b", "/v1/admin/nodes/")
}

// setTags is the shared body of `node tag` and `peer tag`.
func setTags(ctx context.Context, p *output.Printer, args []string, command, synopsis, prefix string) int {
	fs := newFlagSet(command)
	tagsFlag := fs.String("tags", "", "")
	pos, code, ok := parse(p, command, synopsis, fs, args, 1)
	if !ok {
		return code
	}
	a, code, ok := adminClient(p, command)
	if !ok {
		return code
	}
	id := pos[0]
	tags := text.Fields(*tagsFlag)
	if err := a.do(ctx, http.MethodPost, prefix+id+"/tags", api.TagsRequest{Tags: tags}, nil); err != nil {
		return fail(p, command, err)
	}
	if tags == nil {
		tags = []string{}
	}
	return p.Result(command, exit.OK, map[string]any{"id": id, "tags": tags}, func(w io.Writer) {
		fmt.Fprintf(w, "теги %s: %s\n", id, strings.Join(tags, ","))
	})
}
