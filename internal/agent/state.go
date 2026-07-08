package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
)

// State is the agent's persisted identity plus the last applied netmap; the
// cache lets the data plane come up after reboot even if the coordinator is
// unreachable. Contains the WG private key and auth secret → written 0600.
type State struct {
	CoordinatorURL string       `json:"coordinator_url"`
	Fingerprint    string       `json:"fingerprint"`
	NodeID         string       `json:"node_id"`
	AuthSecret     string       `json:"auth_secret"`
	WGPrivateKey   string       `json:"wg_private_key"`
	Role           api.NodeRole `json:"role"`
	OverlayIP      string       `json:"overlay_ip"`
	OverlayCIDR    string       `json:"overlay_cidr"`
	MTU            int          `json:"mtu"`
	ListenPort     int          `json:"listen_port"`
	// AdvertiseRoutes are subnets this node offers to route (subnet router);
	// set via `kai-agent up --advertise-routes`, reported in every status.
	AdvertiseRoutes []string `json:"advertise_routes,omitempty"`
	// NoHosts disables the managed /etc/hosts block (--no-hosts).
	NoHosts bool `json:"no_hosts,omitempty"`
	// KeyCreatedAt + RekeyDays drive automatic WireGuard key rotation
	// (--rekey-days; 0 = never rotate).
	KeyCreatedAt time.Time `json:"key_created_at,omitempty"`
	RekeyDays    int       `json:"rekey_days,omitempty"`
	// LockPublicKey is the pinned network-lock key (TOFU from the first
	// netmap that carries one); once set, peers must arrive signed.
	LockPublicKey string      `json:"lock_public_key,omitempty"`
	Netmap        *api.Netmap `json:"netmap,omitempty"`
}

func LoadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &st, nil
}

func (s *State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
