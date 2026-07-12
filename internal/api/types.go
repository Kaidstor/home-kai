// Package api defines the control-protocol messages exchanged between
// kai-coordinator, kai-agent and the kai CLI. All endpoints speak JSON over
// HTTPS; authentication is a bearer token (enroll token, node auth secret or
// admin token depending on the endpoint).
package api

import "time"

// NodeRole distinguishes the relay hub from ordinary spoke nodes.
type NodeRole string

const (
	RoleHub  NodeRole = "hub"
	RoleNode NodeRole = "node"
)

// HostsSuffix is the pseudo-TLD for device names (`nas.kai`): used in the
// managed /etc/hosts block, publish targets and the hub DNS responder.
const HostsSuffix = ".kai"

// LocalSocketPath is where the agent exposes its read-only status API for the
// admin CLI (`home-kai status`, `home-kai ping`). Mode 0660 root:kai — it
// never reveals keys, but topology (IPs, endpoints, tunnel state) is not for
// every local account either; add users to the kai group for sudo-less
// status.
const LocalSocketPath = "/var/run/kai-agent.sock"

// EnrollRequest is sent by an agent once, authenticated by a one-time enroll
// token. The WireGuard private key never leaves the node.
type EnrollRequest struct {
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	Role         NodeRole `json:"role"`
	WGPublicKey  string   `json:"wg_public_key"`
	WGListenPort int      `json:"wg_listen_port"`
	AgentVersion string   `json:"agent_version"`
}

type EnrollResponse struct {
	NodeID        string `json:"node_id"`
	AuthSecret    string `json:"auth_secret"`
	OverlayIP     string `json:"overlay_ip"`
	OverlayCIDR   string `json:"overlay_cidr"`
	DNSName       string `json:"dns_name,omitempty"`
	MTU           int    `json:"mtu"`
	NetmapVersion int64  `json:"netmap_version"`
}

// Netmap is the full desired WireGuard state for one node. It is always
// complete (never a diff) so applying it is idempotent.
type Netmap struct {
	Version int64       `json:"version"`
	Self    NetmapSelf  `json:"self"`
	Peers   []Peer      `json:"peers"`
	Hosts   []HostEntry `json:"hosts,omitempty"`
	// Publishes are TCP forwarders the hub must run: public port → overlay
	// service (funnel). Present only in the hub's netmap.
	Publishes []Publish `json:"publishes,omitempty"`
	// FilterRules are the inbound overlay allow-rules for this node (ACL).
	FilterRules []FilterRule `json:"filter_rules,omitempty"`
	// ForwardRules are the allow-rules for traffic this node forwards for
	// others (hub relay, subnet router). Enforced in the FORWARD path so that
	// devices that cannot filter for themselves (static peers, LAN hosts
	// behind a subnet router) are still covered by the ACL.
	ForwardRules []ForwardRule `json:"forward_rules,omitempty"`
}

// Publish exposes one overlay service on a public port of the hub.
type Publish struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	ListenPort int       `json:"listen_port"`
	Target     string    `json:"target"` // "100.87.0.3:8096" or "nas.kai:8096"
	CreatedAt  time.Time `json:"created_at,omitempty"`
}

// PublishCreateRequest (POST /v1/admin/publishes).
type PublishCreateRequest struct {
	Name       string `json:"name"`
	ListenPort int    `json:"listen_port"`
	Target     string `json:"target"`
}

// HostEntry maps a friendly device name (name.kai) to its overlay IP; agents
// mirror these into a managed /etc/hosts block.
type HostEntry struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

type NetmapSelf struct {
	NodeID      string   `json:"node_id"`
	Role        NodeRole `json:"role"`
	OverlayIP   string   `json:"overlay_ip"`
	OverlayCIDR string   `json:"overlay_cidr"`
	DNSName     string   `json:"dns_name,omitempty"`
	MTU         int      `json:"mtu"`
	// LockPublicKey (base64 ed25519) is present when the network lock is
	// active. Agents pin it on first sight and from then on refuse peers
	// whose (key, IP) binding is not signed by it — a compromised
	// coordinator cannot introduce peers on its own.
	LockPublicKey string `json:"lock_public_key,omitempty"`
	// FilterEnabled turns on the inbound overlay firewall on this node: once
	// set, only FilterRules are allowed and everything else is dropped. Unset
	// when no ACL policies exist (open network, backward compatible).
	FilterEnabled bool `json:"filter_enabled,omitempty"`
}

// Peer describes one WireGuard peer to install. Endpoint is empty for peers
// that dial in (spokes seen from the hub). Candidates are extra endpoints to
// probe for a direct path (M3).
type Peer struct {
	NodeID       string   `json:"node_id"`
	Hostname     string   `json:"hostname"`
	Role         NodeRole `json:"role"`
	DNSName      string   `json:"dns_name,omitempty"`
	OverlayIP    string   `json:"overlay_ip,omitempty"`
	WGPublicKey  string   `json:"wg_public_key"`
	Endpoint     string   `json:"endpoint,omitempty"`
	AllowedIPs   []string `json:"allowed_ips"`
	KeepaliveSec int      `json:"keepalive_sec,omitempty"`
	Candidates   []string `json:"candidates,omitempty"`
	// LockSig is the admin's ed25519 signature over LockMessage(key, ip);
	// empty means unsigned (locked agents skip such peers).
	LockSig string `json:"lock_sig,omitempty"`
}

// LockMessage is the canonical byte string the network-lock signature covers.
func LockMessage(wgPublicKey, overlayIP string) []byte {
	return []byte("kai-lock-v1|" + wgPublicKey + "|" + overlayIP)
}

// --- Network lock admin API ---

type LockBinding struct {
	Kind        string `json:"kind"` // "node" | "static"
	ID          string `json:"id"`
	Name        string `json:"name"`
	WGPublicKey string `json:"wg_public_key"`
	OverlayIP   string `json:"overlay_ip"`
}

type LockStatus struct {
	Enabled   bool          `json:"enabled"` // public key uploaded
	Active    bool          `json:"active"`  // everything signed once → enforced
	PublicKey string        `json:"public_key,omitempty"`
	Pending   []LockBinding `json:"pending,omitempty"`
}

type LockInitRequest struct {
	PublicKey string `json:"public_key"` // base64 ed25519
}

type LockSignature struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Sig  string `json:"sig"` // base64
}

type LockSignRequest struct {
	Sigs []LockSignature `json:"sigs"`
}

// StatusReport is the periodic heartbeat. Hub agents additionally report the
// reflexive endpoints they observe for each peer (feeds M3 discovery).
// AdvertisedRoutes are the subnets this node offers to route for the overlay
// (subnet router); an admin must enable them before they enter the netmap.
type StatusReport struct {
	EndpointsLocal   []string       `json:"endpoints_local,omitempty"`
	PeersObserved    []PeerObserved `json:"peers_observed,omitempty"`
	AdvertisedRoutes []string       `json:"advertised_routes"`
}

type PeerObserved struct {
	WGPublicKey         string `json:"wg_public_key"`
	Endpoint            string `json:"endpoint"`
	LastHandshakeAgeSec int64  `json:"last_handshake_age_sec"`
}

// RekeyRequest rotates (or re-asserts) the node's WireGuard public key
// (POST /v1/rekey, node auth). Sending the currently registered key is a
// no-op — agents do that on start to heal an interrupted rotation.
type RekeyRequest struct {
	WGPublicKey string `json:"wg_public_key"`
}

// --- Admin API (consumed by the kai CLI) ---

type TokenCreateRequest struct {
	NameHint string `json:"name_hint,omitempty"`
	TTLSec   int    `json:"ttl_sec,omitempty"` // default 3600
}

type TokenCreateResponse struct {
	Token       string    `json:"token"`
	ExpiresAt   time.Time `json:"expires_at"`
	Fingerprint string    `json:"fingerprint"` // sha256 of the coordinator TLS cert
	JoinCommand string    `json:"join_command"`
}

type NodeInfo struct {
	NodeID    string    `json:"node_id"`
	Hostname  string    `json:"hostname"`
	Role      NodeRole  `json:"role"`
	OS        string    `json:"os"`
	OverlayIP string    `json:"overlay_ip"`
	DNSName   string    `json:"dns_name,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	// Online is computed by the coordinator (LastSeen within the long-poll
	// window) so the UI and metrics share one definition.
	Online bool `json:"online"`
	// Subnet router: what the node offers vs what the admin has enabled.
	RoutesAdvertised []string `json:"routes_advertised,omitempty"`
	RoutesEnabled    []string `json:"routes_enabled,omitempty"`
	// Peer approval + ACL grouping.
	Approved bool     `json:"approved"`
	Tags     []string `json:"tags,omitempty"`
}

// NodeRoutesRequest enables a subset of a node's advertised routes
// (POST /v1/admin/nodes/{id}/routes).
type NodeRoutesRequest struct {
	Enabled []string `json:"enabled"`
}

// TagsRequest sets ACL group tags on a node or static peer.
type TagsRequest struct {
	Tags []string `json:"tags"`
}

type StaticPeerCreateRequest struct {
	Name string `json:"name"`
	// Full renders the issued config as a full tunnel (exit node via the hub:
	// AllowedIPs 0.0.0.0/0 + public DNS) instead of overlay-only.
	Full bool `json:"full,omitempty"`
}

type StaticPeerCreateResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	OverlayIP string `json:"overlay_ip"`
	DNSName   string `json:"dns_name,omitempty"`
	ConfINI   string `json:"conf_ini"`
}

type StaticPeerInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	OverlayIP string    `json:"overlay_ip"`
	DNSName   string    `json:"dns_name,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Tags      []string  `json:"tags,omitempty"`
}

// StaticPeerConfigResponse re-renders the WireGuard config of an existing
// static peer (the private key is stored server-side by design). QRPNGBase64
// is the same config encoded as a PNG QR code for the official WireGuard app.
type StaticPeerConfigResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	OverlayIP   string `json:"overlay_ip"`
	DNSName     string `json:"dns_name,omitempty"`
	ConfINI     string `json:"conf_ini"`
	QRPNGBase64 string `json:"qr_png_base64"`
}

// AdminLoginRequest exchanges the admin token for an HttpOnly session cookie
// (web UI login). The token itself is never stored in the browser.
type AdminLoginRequest struct {
	Token string `json:"token"`
}

// --- Local agent API (unix socket, consumed by `kai status` / `kai ping`) ---

// LocalStatus is the agent's live view of its tunnels.
type LocalStatus struct {
	NodeID         string      `json:"node_id"`
	Hostname       string      `json:"hostname"`
	Role           NodeRole    `json:"role"`
	OverlayIP      string      `json:"overlay_ip"`
	CoordinatorURL string      `json:"coordinator_url"`
	AgentVersion   string      `json:"agent_version"`
	NetmapVersion  int64       `json:"netmap_version"`
	Peers          []LocalPeer `json:"peers"`
	Hosts          []HostEntry `json:"hosts,omitempty"`
}

// LocalPeer describes one tunnel as the agent sees it. Path is "hub" for the
// relay itself, "direct" for an established p2p link, "relay" for traffic
// hairpinning through the hub, and "in" for peers that dial into this node
// (hub view).
type LocalPeer struct {
	Hostname            string   `json:"hostname"`
	OverlayIP           string   `json:"overlay_ip"`
	Role                NodeRole `json:"role"`
	Path                string   `json:"path"`
	Endpoint            string   `json:"endpoint,omitempty"`
	Candidates          []string `json:"candidates,omitempty"`
	LastHandshakeAgeSec int64    `json:"last_handshake_age_sec"` // -1 = never
	RxBytes             int64    `json:"rx_bytes"`
	TxBytes             int64    `json:"tx_bytes"`
}

// --- ACL policies ---

// Policy is one access rule: traffic from any node tagged with a SrcTag to any
// node tagged with a DstTag is allowed on the given protocol/ports. Empty
// SrcTags/DstTags mean "any"; empty Ports mean "all ports".
type Policy struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	SrcTags   []string  `json:"src_tags"`
	DstTags   []string  `json:"dst_tags"`
	Protocol  string    `json:"protocol"` // any | tcp | udp | icmp
	Ports     []string  `json:"ports,omitempty"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

type PolicyCreateRequest struct {
	Name     string   `json:"name"`
	SrcTags  []string `json:"src_tags"`
	DstTags  []string `json:"dst_tags"`
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports"`
	Enabled  bool     `json:"enabled"`
}

// FilterRule is one compiled inbound allow-rule delivered to a node. The agent
// permits traffic arriving on the overlay from SrcCIDRs to the given
// protocol/ports; everything else is dropped once FilterEnabled is set.
type FilterRule struct {
	SrcCIDRs []string `json:"src_cidrs"`
	Protocol string   `json:"protocol"` // any | tcp | udp | icmp
	Ports    []string `json:"ports,omitempty"`
}

// ForwardRule is one compiled allow-rule for traffic this node forwards on
// behalf of other devices: the hub relaying to static peers, other spokes and
// enabled subnets, and a subnet router forwarding into its LAN. Unlike
// FilterRule it names explicit destinations, because forwarded traffic is not
// addressed to the enforcing node itself.
type ForwardRule struct {
	SrcCIDRs []string `json:"src_cidrs"`
	DstCIDRs []string `json:"dst_cidrs"`
	Protocol string   `json:"protocol"` // any | tcp | udp | icmp
	Ports    []string `json:"ports,omitempty"`
}

// Event is one activity-log entry (GET /v1/admin/events).
type Event struct {
	ID      int64     `json:"id"`
	TS      time.Time `json:"ts"`
	Kind    string    `json:"kind"`
	Actor   string    `json:"actor,omitempty"`
	Message string    `json:"message"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
