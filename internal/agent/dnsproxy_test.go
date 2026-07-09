package agent

import (
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/kaidstor/home-kai/internal/api"
)

// fakeDNSWriter captures the response instead of writing to a socket.
type fakeDNSWriter struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (w *fakeDNSWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *fakeDNSWriter) RemoteAddr() net.Addr      { return &net.UDPAddr{IP: net.IPv4(100, 87, 0, 9)} }

func query(p *dnsProxy, name string, qtype uint16) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	w := &fakeDNSWriter{}
	p.handle(w, req)
	return w.msg
}

func TestDNSProxyKaiZone(t *testing.T) {
	p := newDNSProxy(slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.setHosts([]api.HostEntry{
		{Name: "nas.kai", IP: "100.87.0.3"},
		{Name: "bad-ip.kai", IP: "not-an-ip"},
	})

	// Known name, A query → authoritative answer (case-insensitive).
	resp := query(p, "NAS.kai", dns.TypeA)
	if resp == nil || !resp.Authoritative || len(resp.Answer) != 1 {
		t.Fatalf("nas.kai: %+v", resp)
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "100.87.0.3" {
		t.Fatalf("nas.kai answer: %+v", resp.Answer[0])
	}

	// Known name, AAAA → NOERROR with no answers (v4-only overlay).
	resp = query(p, "nas.kai", dns.TypeAAAA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("AAAA: %+v", resp)
	}

	// Unknown *.kai name → NXDOMAIN, never forwarded upstream.
	resp = query(p, "ghost.kai", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("ghost.kai: %+v", resp)
	}

	// Unparseable IP entries are skipped, not served.
	resp = query(p, "bad-ip.kai", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("bad-ip.kai: %+v", resp)
	}
}
