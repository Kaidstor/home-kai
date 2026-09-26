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

const policyCreateSynopsis = "policy create <name> [--from TAGS] [--to TAGS] [--proto any|tcp|udp|icmp] [--ports 22,443] [--disabled]"

// cmdPolicy manages ACL policies:
//
//	home-kai policy list
//	home-kai policy create <name> --from tagA,tagB --to tagC --proto tcp --ports 22,443 [--disabled]
//	home-kai policy delete <id>
func cmdPolicy(ctx context.Context, p *output.Printer, args []string) int {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "list":
		return cmdPolicyList(ctx, p, args)
	case "create":
		return cmdPolicyCreate(ctx, p, args)
	case "delete":
		return cmdPolicyDelete(ctx, p, args)
	default:
		return p.Fail("policy", exit.Tool, "usage", "использование: home-kai policy list|create|delete")
	}
}

func cmdPolicyList(ctx context.Context, p *output.Printer, args []string) int {
	const command = "policy list"
	if _, code, ok := parse(p, command, command, newFlagSet(command), args, 0); !ok {
		return code
	}
	a, code, ok := adminClient(p, command)
	if !ok {
		return code
	}
	pols := []api.Policy{}
	if err := a.get(ctx, "/v1/admin/policies", &pols); err != nil {
		return fail(p, command, err)
	}
	return p.Result(command, exit.OK, map[string]any{"policies": pols}, func(w io.Writer) {
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tFROM\tTO\tPROTO\tPORTS\tENABLED")
		for _, pol := range pols {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%v\n",
				pol.ID, pol.Name, text.JoinOr(pol.SrcTags, "*"), text.JoinOr(pol.DstTags, "*"), pol.Protocol, strings.Join(pol.Ports, ","), pol.Enabled)
		}
		tw.Flush()
	})
}

func cmdPolicyCreate(ctx context.Context, p *output.Printer, args []string) int {
	const command = "policy create"
	fs := newFlagSet(command)
	from := fs.String("from", "", "")
	to := fs.String("to", "", "")
	proto := fs.String("proto", "any", "")
	ports := fs.String("ports", "", "")
	disabled := fs.Bool("disabled", false, "")
	pos, code, ok := parse(p, command, policyCreateSynopsis, fs, args, 1)
	if !ok {
		return code
	}
	a, code, ok := adminClient(p, command)
	if !ok {
		return code
	}
	var out api.Policy
	if err := a.do(ctx, http.MethodPost, "/v1/admin/policies", api.PolicyCreateRequest{
		Name: pos[0], SrcTags: text.Fields(*from), DstTags: text.Fields(*to),
		Protocol: *proto, Ports: text.Fields(*ports), Enabled: !*disabled,
	}, &out); err != nil {
		return fail(p, command, err)
	}
	return p.Result(command, exit.OK, out, func(w io.Writer) {
		fmt.Fprintf(w, "политика %s создана (%s)\n", out.Name, out.ID)
	})
}

func cmdPolicyDelete(ctx context.Context, p *output.Printer, args []string) int {
	const command = "policy delete"
	pos, code, ok := parse(p, command, "policy delete <id>", newFlagSet(command), args, 1)
	if !ok {
		return code
	}
	a, code, ok := adminClient(p, command)
	if !ok {
		return code
	}
	id := pos[0]
	if err := a.do(ctx, http.MethodDelete, "/v1/admin/policies/"+id, nil, nil); err != nil {
		return fail(p, command, err)
	}
	return p.Result(command, exit.OK, map[string]any{"id": id, "deleted": true}, func(w io.Writer) {
		fmt.Fprintln(w, "удалена", id)
	})
}
