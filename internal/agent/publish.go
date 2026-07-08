package agent

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
)

// The hub exposes overlay services publicly by plain TCP forwarding (funnel):
// public :port → overlay ip:port. TLS/auth stay the service's business — the
// hub never terminates anything.
type forwarder struct {
	ln     net.Listener
	target string
}

func (f *forwarder) serve(log *slog.Logger) {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return // listener closed on netmap change or shutdown
		}
		go func() {
			defer c.Close()
			up, err := net.DialTimeout("tcp", f.target, 10*time.Second)
			if err != nil {
				log.Warn("publish: dial target failed", "target", f.target, "err", err)
				return
			}
			defer up.Close()
			done := make(chan struct{}, 2)
			pipe := func(dst, src net.Conn) {
				_, _ = io.Copy(dst, src)
				if t, ok := dst.(*net.TCPConn); ok {
					_ = t.CloseWrite()
				}
				done <- struct{}{}
			}
			go pipe(up, c)
			go pipe(c, up)
			<-done
			<-done
		}()
	}
}

// syncPublishes makes running forwarders match the netmap: changed targets
// restart the listener, removed publishes close it (in-flight connections
// finish on their own).
func (a *Agent) syncPublishes(pubs []api.Publish) {
	a.pubMu.Lock()
	defer a.pubMu.Unlock()
	if a.forwarders == nil {
		a.forwarders = map[int]*forwarder{}
	}
	want := map[int]string{}
	for _, p := range pubs {
		want[p.ListenPort] = p.Target
	}
	for port, f := range a.forwarders {
		if target, ok := want[port]; !ok || target != f.target {
			_ = f.ln.Close()
			delete(a.forwarders, port)
			a.log.Info("publish stopped", "port", port, "target", f.target)
		}
	}
	for port, target := range want {
		if _, ok := a.forwarders[port]; ok {
			continue
		}
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			a.log.Error("publish: listen failed", "port", port, "err", err)
			continue
		}
		f := &forwarder{ln: ln, target: target}
		a.forwarders[port] = f
		go f.serve(a.log)
		a.log.Info("publish started", "port", port, "target", target)
	}
}

func (a *Agent) teardownPublishes() {
	a.syncPublishes(nil)
}
