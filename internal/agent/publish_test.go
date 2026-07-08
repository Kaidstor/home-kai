package agent

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
)

func TestForwarderRoundTrip(t *testing.T) {
	// Echo "backend" standing in for an overlay service.
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()

	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	port := freePort(t)
	a.syncPublishes([]api.Publish{{Name: "echo", ListenPort: port, Target: backend.Addr().String()}})
	defer a.teardownPublishes()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping through funnel")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "ping through funnel" {
		t.Fatalf("echo: %q, %v", buf[:n], err)
	}

	// Removing the publish closes the public port.
	a.syncPublishes(nil)
	if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond); err == nil {
		t.Fatal("port still open after publish removal")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
