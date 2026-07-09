// Package agent implements the kai node daemon: enroll once, then keep the
// local WireGuard device in sync with the coordinator's netmap. The data
// plane is independent of the coordinator: the last netmap is cached in the
// state file and re-applied on start, so tunnels survive coordinator outages.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/kaidstor/home-kai/internal/agent/wgdev"
	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/wgkeys"
)

const (
	statusInterval = 60 * time.Second
	backoffMax     = 60 * time.Second
)

// Enroll registers this machine with the coordinator and writes the state
// file. Called by `kai-agent up` on first run.
func Enroll(ctx context.Context, coordinatorURL, fingerprint, token string, role api.NodeRole, listenPort int, statePath string) (*State, error) {
	c, err := NewClient(coordinatorURL, fingerprint, token)
	if err != nil {
		return nil, err
	}
	pair, err := wgkeys.Generate()
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	resp, err := c.Enroll(ctx, api.EnrollRequest{
		Hostname:     hostname,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Role:         role,
		WGPublicKey:  pair.Public.String(),
		WGListenPort: listenPort,
		AgentVersion: Version,
	})
	if err != nil {
		return nil, err
	}
	st := &State{
		CoordinatorURL: coordinatorURL,
		Fingerprint:    fingerprint,
		NodeID:         resp.NodeID,
		AuthSecret:     resp.AuthSecret,
		WGPrivateKey:   pair.Private.String(),
		Role:           role,
		OverlayIP:      resp.OverlayIP,
		OverlayCIDR:    resp.OverlayCIDR,
		MTU:            resp.MTU,
		ListenPort:     listenPort,
		KeyCreatedAt:   time.Now(),
	}
	if err := st.Save(statePath); err != nil {
		return nil, err
	}
	return st, nil
}

// Version is stamped via -ldflags at build time.
var Version = "dev"

type Agent struct {
	st        *State
	statePath string
	client    *Client
	dev       wgdev.Device
	log       *slog.Logger
	overlay   netip.Prefix   // parsed st.OverlayCIDR, set in Run
	natRules  []iptablesRule // installed firewall rules, removed on shutdown

	// applyMu serializes applyNetmap end-to-end (device, routes, hosts,
	// filter) and every state-file write: the sync loop and the probe loop
	// both apply netmaps, and interleaved applies could install a stale peer
	// set or corrupt files written via the shared tmp-and-rename path.
	applyMu sync.Mutex
	// lastFilter is the fingerprint of the last applied ACL rule set; the
	// iptables chain is rebuilt only when it changes. Guarded by applyMu.
	lastFilter string

	// mu guards nm and probes: the sync loop applies netmaps while the probe
	// loop promotes/demotes direct paths, and both recompose the peer set.
	mu     sync.Mutex
	nm     *api.Netmap
	probes map[string]*probeState

	// pubMu guards the hub's public TCP forwarders (funnel).
	pubMu      sync.Mutex
	forwarders map[int]*forwarder
}

func New(st *State, statePath string, log *slog.Logger) (*Agent, error) {
	c, err := NewClient(st.CoordinatorURL, st.Fingerprint, st.AuthSecret)
	if err != nil {
		return nil, err
	}
	return &Agent{st: st, statePath: statePath, client: c, log: log}, nil
}

// Run brings the device up (applying the cached netmap immediately if there
// is one) and blocks, syncing until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	addr, err := netip.ParseAddr(a.st.OverlayIP)
	if err != nil {
		return fmt.Errorf("bad overlay ip in state: %w", err)
	}
	a.overlay, err = netip.ParsePrefix(a.st.OverlayCIDR)
	if err != nil {
		return fmt.Errorf("bad overlay cidr in state: %w", err)
	}
	priv, err := wgkeys.ParsePrivate(a.st.WGPrivateKey)
	if err != nil {
		return fmt.Errorf("bad private key in state: %w", err)
	}

	dev, err := wgdev.Up(wgdev.Config{
		PrivateKey: priv,
		ListenPort: a.st.ListenPort,
		Address:    addr,
		OverlayNet: a.overlay,
		MTU:        a.st.MTU,
	})
	if err != nil {
		return err
	}
	a.dev = dev
	defer a.dev.Close()
	a.log.Info("wireguard device up", "iface", dev.Name(), "ip", a.st.OverlayIP, "role", a.st.Role)

	if a.st.Role == api.RoleHub {
		// Relay between spokes + exit node for devices with a full-tunnel conf.
		if err := a.setupHubNAT(); err != nil {
			a.log.Error("hub NAT setup failed — relaying/exit may not work", "err", err)
		}
	}
	if len(a.st.AdvertiseRoutes) > 0 {
		if err := a.setupSubnetRouter(); err != nil {
			a.log.Error("subnet router setup failed — advertised subnets will not be reachable", "err", err)
		} else {
			a.log.Info("subnet router active", "routes", a.st.AdvertiseRoutes)
		}
	}
	defer a.teardownNATRules()
	if a.st.Netmap != nil {
		if err := a.applyNetmap(a.st.Netmap); err != nil {
			a.log.Warn("applying cached netmap failed", "err", err)
		} else {
			a.log.Info("cached netmap applied", "version", a.st.Netmap.Version, "peers", len(a.st.Netmap.Peers))
		}
	}

	statusTicker := time.NewTicker(statusInterval)
	defer statusTicker.Stop()
	go a.syncLoop(ctx)
	go a.serveLocalAPI(ctx)
	go a.rekeyLoop(ctx)
	if a.st.Role != api.RoleHub {
		go a.probeLoop(ctx) // M3: hunt for direct paths to other spokes
	}

	// First status right away: it carries advertised routes and LAN endpoints
	// (M3 candidates) — waiting a full statusInterval would delay both.
	go func() {
		select {
		case <-time.After(3 * time.Second):
			if err := a.reportStatus(ctx); err != nil && ctx.Err() == nil {
				a.log.Warn("initial status report failed", "err", err)
			}
		case <-ctx.Done():
		}
	}()

	for {
		select {
		case <-ctx.Done():
			a.log.Info("shutting down")
			a.syncHosts(nil) // leave no stale names behind
			a.teardownPublishes()
			_ = a.applyFilter(false, nil) // remove the ACL chain
			return nil
		case <-statusTicker.C:
			if err := a.reportStatus(ctx); err != nil && ctx.Err() == nil {
				a.log.Warn("status report failed", "err", err)
			}
		}
	}
}

// syncLoop long-polls the netmap with jittered backoff on failure.
func (a *Agent) syncLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		since := int64(0)
		if a.st.Netmap != nil {
			since = a.st.Netmap.Version
		}
		nm, err := a.client.Netmap(ctx, since)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Warn("netmap sync failed", "err", err, "retry_in", backoff)
			select {
			case <-time.After(backoff + time.Duration(rand.Int64N(int64(backoff/2+1)))):
			case <-ctx.Done():
				return
			}
			backoff = min(backoff*2, backoffMax)
			continue
		}
		backoff = time.Second
		if nm == nil {
			continue // 304, poll again
		}
		if err := a.applyNetmap(nm); err != nil {
			a.log.Error("netmap apply failed", "version", nm.Version, "err", err)
			continue
		}
		a.log.Info("netmap applied", "version", nm.Version, "peers", len(nm.Peers))
	}
}

// applyNetmap makes the whole node state match nm: WG peers, OS routes,
// /etc/hosts, publishes, ACL filter, DNS records and the state-file cache.
// Serialized by applyMu — it is called both from the sync loop and from the
// probe loop, and its side effects (device config, tmp-and-rename file
// writes, iptables) must never interleave.
func (a *Agent) applyNetmap(nm *api.Netmap) error {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()

	if !a.overlay.IsValid() { // Run sets it; direct construction (tests) may not
		var err error
		if a.overlay, err = netip.ParsePrefix(a.st.OverlayCIDR); err != nil {
			return err
		}
	}
	if err := a.enforceLock(nm); err != nil {
		return err
	}
	a.mu.Lock()
	a.nm = nm
	a.syncProbes(nm)
	peers, subnetRoutes, err := a.composePeers(nm, a.overlay)
	a.mu.Unlock()
	if err != nil {
		return err
	}
	if err := a.dev.ApplyPeers(peers); err != nil {
		return err
	}
	// Route trouble degrades subnet access but must not fail the whole apply.
	if err := a.dev.SyncRoutes(subnetRoutes); err != nil {
		a.log.Error("syncing subnet routes failed", "err", err)
	}
	a.syncHosts(nm.Hosts)
	if a.st.Role == api.RoleHub {
		a.syncPublishes(nm.Publishes)
	}
	a.syncFilter(nm)
	// Cache the netmap so the data plane comes back after a reboot even with
	// the coordinator down. Probe-triggered re-applies reuse the cached map.
	if a.st.Netmap != nm {
		a.st.Netmap = nm
		if err := a.st.Save(a.statePath); err != nil {
			a.log.Warn("state save failed", "err", err)
		}
	}
	return nil
}

// syncFilter applies the ACL rule set only when it differs from the last
// applied one — probe promotions re-apply netmaps every few seconds and must
// not trigger a full iptables rebuild each time. Filter failure must not
// abort the apply: degrade to the previous rules with a logged error.
func (a *Agent) syncFilter(nm *api.Netmap) {
	rules := nm.FilterRules
	key := fmt.Sprintf("%v|%+v", nm.Self.FilterEnabled, rules)
	if key == a.lastFilter {
		return
	}
	if err := a.applyFilter(nm.Self.FilterEnabled, rules); err != nil {
		a.log.Error("applying ACL filter failed", "err", err)
		return
	}
	a.lastFilter = key
}

// composePeers merges the netmap with prober decisions. Probe-managed peers
// (other spokes) get their /32 only once a direct path is confirmed — until
// then empty AllowedIPs keep their traffic on the hub while handshakes still
// punch. Callers hold a.mu.
func (a *Agent) composePeers(nm *api.Netmap, overlay netip.Prefix) ([]wgdev.PeerConfig, []netip.Prefix, error) {
	peers := make([]wgdev.PeerConfig, 0, len(nm.Peers))
	var subnetRoutes []netip.Prefix
	for _, p := range nm.Peers {
		key, err := wgkeys.ParsePublic(p.WGPublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("peer %s: bad key: %w", p.Hostname, err)
		}
		pc := wgdev.PeerConfig{
			PublicKey: key,
			Endpoint:  p.Endpoint,
			Keepalive: time.Duration(p.KeepaliveSec) * time.Second,
		}
		allowed := p.AllowedIPs
		if a.probeManaged(p) {
			ps := a.probes[p.WGPublicKey]
			switch {
			case ps == nil || ps.phase == phaseIdle:
				allowed, pc.Endpoint = nil, ""
			case ps.phase == phaseProbing:
				allowed, pc.Endpoint = nil, ps.endpoint()
			case ps.phase == phaseDirect:
				pc.Endpoint = ps.confirmedEndpoint
				if pc.Endpoint == "" {
					pc.Endpoint = ps.endpoint()
				}
			}
		}
		// Keepalive without an endpoint is meaningless: wireguard-go would log
		// "no known endpoint for peer" every interval. A probe-managed peer on
		// the relay path (empty endpoint) must therefore drop keepalive too —
		// the hub tunnel already keeps our NAT mapping warm.
		if pc.Endpoint == "" {
			pc.Keepalive = 0
		}
		for _, s := range allowed {
			pfx, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, nil, fmt.Errorf("peer %s: bad allowed_ip %q: %w", p.Hostname, s, err)
			}
			pc.AllowedIPs = append(pc.AllowedIPs, pfx)
			// Anything outside the overlay is a subnet route and needs an OS
			// route into the tunnel (the overlay CIDR route covers the rest).
			if !pfx.Overlaps(overlay) {
				subnetRoutes = append(subnetRoutes, pfx)
			}
		}
		peers = append(peers, pc)
	}
	return peers, subnetRoutes, nil
}

func (a *Agent) reportStatus(ctx context.Context) error {
	rep := api.StatusReport{
		EndpointsLocal:   a.localEndpoints(),
		AdvertisedRoutes: a.st.AdvertiseRoutes,
	}
	if a.st.Role == api.RoleHub {
		rep.PeersObserved = a.observedPeers()
	}
	return a.client.ReportStatus(ctx, rep)
}
