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

// cmdPolicy manages ACL policies:
//
//	kai policy list
//	kai policy create <name> --from tagA,tagB --to tagC --proto tcp --ports 22,443 [--disabled]
//	kai policy delete <id>
func cmdPolicy(ctx context.Context, args []string) {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "list":
		var pols []api.Policy
		if _, err := client().Do(ctx, http.MethodGet, "/v1/admin/policies", nil, &pols); err != nil {
			fatal(err)
		}
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tFROM\tTO\tPROTO\tPORTS\tENABLED")
		for _, p := range pols {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%v\n",
				p.ID, p.Name, text.JoinOr(p.SrcTags, "*"), text.JoinOr(p.DstTags, "*"), p.Protocol, strings.Join(p.Ports, ","), p.Enabled)
		}
		w.Flush()
	case "create":
		if len(args) < 2 || args[1] == "" || args[1][0] == '-' {
			fatal(fmt.Errorf("usage: kai policy create <name> --from ... --to ... [--proto tcp] [--ports 22,443] [--disabled]"))
		}
		name := args[1]
		fs := flag.NewFlagSet("policy create", flag.ExitOnError)
		from := fs.String("from", "", "source tags (empty = any)")
		to := fs.String("to", "", "destination tags (empty = any)")
		proto := fs.String("proto", "any", "any|tcp|udp|icmp")
		ports := fs.String("ports", "", "comma-separated ports (tcp/udp only)")
		disabled := fs.Bool("disabled", false, "create the policy disabled")
		_ = fs.Parse(args[2:])
		var out api.Policy
		if _, err := client().Do(ctx, http.MethodPost, "/v1/admin/policies", api.PolicyCreateRequest{
			Name: name, SrcTags: text.Fields(*from), DstTags: text.Fields(*to),
			Protocol: *proto, Ports: text.Fields(*ports), Enabled: !*disabled,
		}, &out); err != nil {
			fatal(err)
		}
		fmt.Printf("policy %s created (%s)\n", out.Name, out.ID)
	case "delete":
		if len(args) < 2 {
			usage()
		}
		if _, err := client().Do(ctx, http.MethodDelete, "/v1/admin/policies/"+args[1], nil, nil); err != nil {
			fatal(err)
		}
		fmt.Println("deleted", args[1])
	default:
		fatal(fmt.Errorf("usage: kai policy list|create|delete"))
	}
}
