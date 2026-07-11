package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/text"
)

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
//	home-kai node routes <node_id> --enable 192.168.1.0/24,172.18.0.0/16
//	home-kai node routes <node_id> --enable ""        # disable all
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

func cmdNodeApprove(ctx context.Context, args []string) {
	if len(args) < 1 {
		usage()
	}
	if _, err := client().Do(ctx, http.MethodPost, "/v1/admin/nodes/"+args[0]+"/approve", nil, nil); err != nil {
		fatal(err)
	}
	fmt.Println("approved", args[0])
}

func cmdNodeTag(ctx context.Context, args []string) {
	if len(args) < 1 {
		usage()
	}
	id := args[0]
	fs := flag.NewFlagSet("node tag", flag.ExitOnError)
	tags := fs.String("tags", "", "comma-separated group tags (empty clears)")
	_ = fs.Parse(args[1:])
	if _, err := client().Do(ctx, http.MethodPost, "/v1/admin/nodes/"+id+"/tags",
		api.TagsRequest{Tags: text.Fields(*tags)}, nil); err != nil {
		fatal(err)
	}
	fmt.Printf("tags for %s: %s\n", id, *tags)
}
