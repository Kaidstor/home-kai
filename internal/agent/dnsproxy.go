package agent

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/kaidstor/home-kai/internal/api"
)

// dnsProxy is the hub's overlay DNS responder: it answers *.kai names from
// the netmap host list and forwards everything else to public resolvers.
// Static peers (phones, routers) get the hub's overlay IP as their DNS server
// in the generated WireGuard config — that is what makes `ssh nas.kai` work
// on a device that has no managed /etc/hosts block. It listens only on the
// overlay address, so nothing is exposed publicly.
type dnsProxy struct {
	log *slog.Logger

	mu      sync.RWMutex
	records map[string]netip.Addr // "nas.kai." → overlay IP
}

// dnsUpstreams answer everything outside .kai, tried in order.
var dnsUpstreams = []string{"1.1.1.1:53", "8.8.8.8:53"}

func newDNSProxy(log *slog.Logger) *dnsProxy {
	return &dnsProxy{log: log, records: map[string]netip.Addr{}}
}

// setHosts replaces the *.kai record set (called on every netmap apply).
func (p *dnsProxy) setHosts(hosts []api.HostEntry) {
	recs := make(map[string]netip.Addr, len(hosts))
	for _, h := range hosts {
		ip, err := netip.ParseAddr(h.IP)
		if err != nil {
			continue
		}
		recs[strings.ToLower(h.Name)+"."] = ip
	}
	p.mu.Lock()
	p.records = recs
	p.mu.Unlock()
}

// serve runs UDP and TCP listeners on the hub's overlay address until ctx is
// done. Best-effort: a bind failure (port 53 taken) logs and gives up — names
// stop resolving for static peers, the overlay itself keeps working.
func (p *dnsProxy) serve(ctx context.Context, addr netip.Addr) {
	laddr := net.JoinHostPort(addr.String(), "53")
	mux := dns.NewServeMux()
	mux.HandleFunc(".", p.handle)
	servers := []*dns.Server{
		{Addr: laddr, Net: "udp", Handler: mux},
		{Addr: laddr, Net: "tcp", Handler: mux},
	}
	for _, srv := range servers {
		go func() {
			if err := srv.ListenAndServe(); err != nil && ctx.Err() == nil {
				p.log.Error("dns: listener failed — *.kai names unavailable for static peers",
					"addr", laddr, "net", srv.Net, "err", err)
			}
		}()
	}
	p.log.Info("overlay dns responder up", "addr", laddr)
	<-ctx.Done()
	for _, srv := range servers {
		_ = srv.Shutdown()
	}
}

func (p *dnsProxy) handle(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		return
	}
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	if strings.HasSuffix(name, api.HostsSuffix+".") {
		p.answerKai(w, req, q, name)
		return
	}
	p.forward(w, req)
}

// answerKai serves the authoritative overlay zone.
func (p *dnsProxy) answerKai(w dns.ResponseWriter, req *dns.Msg, q dns.Question, name string) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	p.mu.RLock()
	ip, ok := p.records[name]
	p.mu.RUnlock()
	switch {
	case !ok:
		m.Rcode = dns.RcodeNameError
	case q.Qtype == dns.TypeA:
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   ip.AsSlice(),
		})
	default:
		// Known name, non-A query (AAAA, HTTPS, …): NOERROR with no answers —
		// the overlay is v4-only.
	}
	_ = w.WriteMsg(m)
}

// forward proxies everything outside .kai to the public resolvers.
func (p *dnsProxy) forward(w dns.ResponseWriter, req *dns.Msg) {
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		c.Net = "tcp"
	}
	for _, up := range dnsUpstreams {
		resp, _, err := c.Exchange(req, up)
		if err != nil {
			continue
		}
		_ = w.WriteMsg(resp)
		return
	}
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	_ = w.WriteMsg(m)
}
