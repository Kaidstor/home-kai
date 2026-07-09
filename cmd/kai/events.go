package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/kaidstor/home-kai/internal/api"
)

func cmdEvents(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("events", flag.ExitOnError)
	limit := fs.Int("limit", 50, "how many recent events to show")
	_ = fs.Parse(args)
	var evs []api.Event
	if _, err := client().Do(ctx, http.MethodGet, fmt.Sprintf("/v1/admin/events?limit=%d", *limit), nil, &evs); err != nil {
		fatal(err)
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tKIND\tACTOR\tMESSAGE")
	for _, e := range evs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			e.TS.Local().Format("2006-01-02 15:04:05"), e.Kind, e.Actor, e.Message)
	}
	w.Flush()
}
