//go:build darwin

package wgdev

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// darwinDevice embeds wireguard-go: macOS has no kernel WireGuard, so the
// protocol runs in-process over a utun interface (root required). Config goes
// through the in-process UAPI (IpcSet/IpcGet), addresses/routes through
// ifconfig/route — same as wg-quick does.
type darwinDevice struct {
	name   string
	dev    *device.Device
	routes map[string]bool // extra subnet routes currently installed
}

func platformUp(cfg Config) (Device, error) {
	tunDev, err := tun.CreateTUN("utun", cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create utun (need root): %w", err)
	}
	name, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, err
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", name))
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", hex.EncodeToString(cfg.PrivateKey[:]))
	if cfg.ListenPort > 0 {
		fmt.Fprintf(&uapi, "listen_port=%d\n", cfg.ListenPort)
	}
	if err := dev.IpcSet(uapi.String()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("uapi set: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("device up: %w", err)
	}

	// Point-to-point self address + overlay route, wg-quick style.
	addr := cfg.Address.String()
	cmds := [][]string{
		{"ifconfig", name, "inet", addr, addr, "netmask", "255.255.255.255", "up"},
		{"route", "-q", "-n", "add", "-inet", cfg.OverlayNet.Masked().String(), "-interface", name},
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			dev.Close()
			return nil, fmt.Errorf("%s: %w: %s", strings.Join(c, " "), err, out)
		}
	}
	return &darwinDevice{name: name, dev: dev, routes: map[string]bool{}}, nil
}

func (d *darwinDevice) Name() string { return d.name }

func (d *darwinDevice) SyncRoutes(prefixes []netip.Prefix) error {
	want := map[string]bool{}
	for _, p := range prefixes {
		want[p.Masked().String()] = true
	}
	run := func(verb, cidr string) error {
		out, err := exec.Command("route", "-q", "-n", verb, "-inet", cidr, "-interface", d.name).CombinedOutput()
		if err != nil {
			return fmt.Errorf("route %s %s: %w: %s", verb, cidr, err, out)
		}
		return nil
	}
	for s := range d.routes {
		if want[s] {
			continue
		}
		if err := run("delete", s); err != nil {
			return err
		}
		delete(d.routes, s)
	}
	for s := range want {
		if d.routes[s] {
			continue
		}
		if err := run("add", s); err != nil {
			return err
		}
		d.routes[s] = true
	}
	return nil
}

func (d *darwinDevice) ApplyPeers(peers []PeerConfig) error {
	var b strings.Builder
	b.WriteString("replace_peers=true\n")
	for _, p := range peers {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
		if p.Endpoint != "" {
			// UAPI wants a resolved ip:port.
			ua, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return fmt.Errorf("resolve endpoint %q: %w", p.Endpoint, err)
			}
			fmt.Fprintf(&b, "endpoint=%s\n", ua.String())
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(p.Keepalive.Seconds()))
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, pfx := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", pfx.Masked().String())
		}
	}
	return d.dev.IpcSet(b.String())
}

func (d *darwinDevice) SetPrivateKey(key wgtypes.Key) error {
	return d.dev.IpcSet(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(key[:])))
}

func (d *darwinDevice) Peers() ([]PeerStatus, error) {
	raw, err := d.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	return parseUAPIPeers(raw)
}

func (d *darwinDevice) Close() error {
	// Closing the device tears down the utun; its routes die with it.
	d.dev.Close()
	return nil
}

// parseUAPIPeers extracts peer state from wireguard-go's UAPI "get" output.
func parseUAPIPeers(raw string) ([]PeerStatus, error) {
	var out []PeerStatus
	var cur *PeerStatus
	var hsSec, hsNsec int64
	flush := func() {
		if cur != nil {
			if hsSec > 0 || hsNsec > 0 {
				cur.LastHandshake = time.Unix(hsSec, hsNsec)
			}
			out = append(out, *cur)
		}
		cur, hsSec, hsNsec = nil, 0, 0
	}
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			kb, err := hex.DecodeString(v)
			if err != nil || len(kb) != wgtypes.KeyLen {
				return nil, fmt.Errorf("bad public_key in uapi output: %q", v)
			}
			cur = &PeerStatus{PublicKey: wgtypes.Key(kb)}
		case "endpoint":
			if cur != nil {
				cur.Endpoint = v
			}
		case "last_handshake_time_sec":
			hsSec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			hsNsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	flush()
	return out, sc.Err()
}
