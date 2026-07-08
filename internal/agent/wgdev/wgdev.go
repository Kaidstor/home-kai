// Package wgdev abstracts the platform WireGuard data plane: kernel WireGuard
// on Linux, embedded wireguard-go (userspace, utun) on macOS. Both paths are
// configured through wgctrl; interface/address/route setup is per-OS.
package wgdev

import (
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerConfig is one peer to install. Zero Endpoint means the peer dials us.
type PeerConfig struct {
	PublicKey  wgtypes.Key
	Endpoint   string // "host:port" or ""
	AllowedIPs []netip.Prefix
	Keepalive  time.Duration
}

// PeerStatus is runtime state read back from the device (feeds hub status
// reports and M3 probing).
type PeerStatus struct {
	PublicKey     wgtypes.Key
	Endpoint      string
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// Device is a live WireGuard interface with an overlay address assigned and a
// route to the overlay CIDR installed.
type Device interface {
	// Name of the OS interface (kai0 on Linux, utunN on macOS).
	Name() string
	// ApplyPeers replaces the full peer set (idempotent, ReplacePeers).
	ApplyPeers(peers []PeerConfig) error
	// Peers returns runtime peer state.
	Peers() ([]PeerStatus, error)
	// SyncRoutes makes the set of extra OS routes through this interface
	// (subnet routes beyond the overlay CIDR) match exactly the given
	// prefixes, adding and removing as needed. Idempotent.
	SyncRoutes(prefixes []netip.Prefix) error
	// SetPrivateKey swaps the device identity in place (key rotation).
	SetPrivateKey(key wgtypes.Key) error
	Close() error
}

// Config for bringing a device up.
type Config struct {
	PrivateKey wgtypes.Key
	ListenPort int // fixed port for a stable NAT mapping; 0 = ephemeral
	Address    netip.Addr
	OverlayNet netip.Prefix
	MTU        int
}

// Up creates and configures the platform device (requires root).
func Up(cfg Config) (Device, error) { return platformUp(cfg) }
