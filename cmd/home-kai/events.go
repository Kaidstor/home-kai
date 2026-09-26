package main

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/exit"
	"github.com/kaidstor/home-kai/internal/output"
)

func cmdEvents(ctx context.Context, p *output.Printer, args []string) int {
	fs := newFlagSet("events")
	limit := fs.Int("limit", 50, "")
	if _, code, ok := parse(p, "events", "events [--limit N]", fs, args, 0); !ok {
		return code
	}
	a, code, ok := adminClient(p, "events")
	if !ok {
		return code
	}
	evs := []api.Event{}
	if err := a.get(ctx, fmt.Sprintf("/v1/admin/events?limit=%d", *limit), &evs); err != nil {
		return fail(p, "events", err)
	}
	return p.Result("events", exit.OK, map[string]any{"events": evs}, func(w io.Writer) {
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "TIME\tKIND\tACTOR\tMESSAGE")
		for _, e := range evs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
				e.TS.Local().Format("2006-01-02 15:04:05"), e.Kind, e.Actor, e.Message)
		}
		tw.Flush()
	})
}
