// Package coordinator implements the control plane: node enrollment, netmap
// distribution (HTTP long-poll) and the admin API consumed by the kai CLI.
package coordinator

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/coordinator/dns"
	"github.com/kaidstor/home-kai/internal/coordinator/store"
)

//go:embed webui/index.html
var uiHTML []byte

const (
	longPollTimeout = 55 * time.Second

	// Web-UI sessions: the admin token is exchanged for an HttpOnly cookie at
	// login and never stored in the browser. Sessions live in memory —
	// a coordinator restart logs everyone out, which is fine at homelab scale.
	sessionCookieName = "kai_admin_session"
	sessionTTL        = 30 * 24 * time.Hour
	// uiHeader must accompany cookie-authenticated requests. Cross-site forms
	// cannot set custom headers, so together with SameSite=Strict this blocks
	// CSRF even on browsers that ignore SameSite.
	uiHeader = "X-Kai-UI"
)

type Config struct {
	// PublicURL is how agents reach this coordinator, e.g. "https://hub.example.com:8443".
	PublicURL string
	// HubEndpoint is the WireGuard endpoint of the hub, e.g. "hub.example.com:51820".
	HubEndpoint string
	OverlayCIDR netip.Prefix
	MTU         int
	// AdminTokenHash is the hex SHA-256 of the admin bearer token.
	AdminTokenHash string
	// Domain for per-device DNS names ({label}.{Domain}); empty disables DNS.
	Domain string
	// Fingerprint of the TLS cert, embedded into join commands.
	Fingerprint string
	// EventWebhook, if set, receives a JSON POST for every logged event.
	EventWebhook string
	// RequireApproval holds new spoke nodes out of the network until an admin
	// approves them (the hub is always trusted implicitly).
	RequireApproval bool
}

type Server struct {
	cfg   Config
	store *store.Store
	dns   dns.Provider
	log   *slog.Logger

	mu     sync.Mutex
	wakeCh chan struct{} // closed and replaced on every netmap bump

	sessMu   sync.Mutex
	sessions map[string]time.Time // sha256(session id) → expiry
}

func NewServer(cfg Config, st *store.Store, dnsProvider dns.Provider, log *slog.Logger) *Server {
	if dnsProvider == nil {
		dnsProvider = dns.Noop{}
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1420
	}
	return &Server{
		cfg: cfg, store: st, dns: dnsProvider, log: log,
		wakeCh: make(chan struct{}), sessions: map[string]time.Time{},
	}
}

// notifyNetmapChanged wakes all pending long-polls.
func (s *Server) notifyNetmapChanged() {
	s.mu.Lock()
	close(s.wakeCh)
	s.wakeCh = make(chan struct{})
	s.mu.Unlock()
}

func (s *Server) wakeChan() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wakeCh
}

// bumpNetmap increments the netmap version and wakes every pending long-poll.
// Every mutating admin action ends with it, so keep the two steps together.
// Most callers ignore the returned version; enroll embeds it in its response.
func (s *Server) bumpNetmap() (int64, error) {
	version, err := s.store.BumpNetmapVersion()
	if err != nil {
		return 0, err
	}
	s.notifyNetmapChanged()
	return version, nil
}

// nodeOr404 loads the node named by the {id} path segment, writing the
// appropriate error response and returning ok=false when it is missing or
// unreadable.
func (s *Server) nodeOr404(w http.ResponseWriter, r *http.Request) (store.Node, bool) {
	n, err := s.store.NodeByID(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such node")
		return store.Node{}, false
	}
	if err != nil {
		s.errInternal(w, err)
		return store.Node{}, false
	}
	return n, true
}

// staticPeerOr404 is nodeOr404 for static peers.
func (s *Server) staticPeerOr404(w http.ResponseWriter, r *http.Request) (store.StaticPeer, bool) {
	p, err := s.store.StaticPeerByID(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such static peer")
		return store.StaticPeer{}, false
	}
	if err != nil {
		s.errInternal(w, err)
		return store.StaticPeer{}, false
	}
	return p, true
}

// --- store → api converters (kept next to their siblings toAPIPolicy/Publish) ---

func toAPINode(n store.Node, now time.Time) api.NodeInfo {
	return api.NodeInfo{
		NodeID: n.ID, Hostname: n.Name, Role: api.NodeRole(n.Role), OS: n.OS,
		OverlayIP: n.OverlayIP, DNSName: n.DNSName, CreatedAt: n.CreatedAt, LastSeen: n.LastSeen,
		Online:           now.Sub(n.LastSeen) < onlineWindow,
		RoutesAdvertised: n.RoutesAdvertised, RoutesEnabled: n.RoutesEnabled,
		Approved: n.Approved, Tags: n.Tags,
	}
}

func toAPIStaticPeer(p store.StaticPeer) api.StaticPeerInfo {
	return api.StaticPeerInfo{
		ID: p.ID, Name: p.Name, OverlayIP: p.OverlayIP, DNSName: p.DNSName,
		CreatedAt: p.CreatedAt, Tags: p.Tags,
	}
}

func toAPIEvent(e store.Event) api.Event {
	return api.Event{ID: e.ID, TS: e.TS, Kind: e.Kind, Actor: e.Actor, Message: e.Message}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	mux.HandleFunc("GET /v1/netmap", s.withNode(s.handleNetmap))
	mux.HandleFunc("POST /v1/status", s.withNode(s.handleStatus))
	mux.HandleFunc("POST /v1/rekey", s.withNode(s.handleRekey))
	mux.HandleFunc("POST /v1/admin/tokens", s.withAdmin(s.handleTokenCreate))
	mux.HandleFunc("GET /v1/admin/nodes", s.withAdmin(s.handleNodeList))
	mux.HandleFunc("DELETE /v1/admin/nodes/{id}", s.withAdmin(s.handleNodeDelete))
	mux.HandleFunc("POST /v1/admin/nodes/{id}/routes", s.withAdmin(s.handleNodeRoutes))
	mux.HandleFunc("POST /v1/admin/nodes/{id}/approve", s.withAdmin(s.handleNodeApprove))
	mux.HandleFunc("POST /v1/admin/nodes/{id}/tags", s.withAdmin(s.handleNodeTags))
	mux.HandleFunc("POST /v1/admin/session", s.handleAdminLogin)
	mux.HandleFunc("DELETE /v1/admin/session", s.handleAdminLogout)
	mux.HandleFunc("POST /v1/admin/static-peers", s.withAdmin(s.handleStaticPeerCreate))
	mux.HandleFunc("GET /v1/admin/static-peers", s.withAdmin(s.handleStaticPeerList))
	mux.HandleFunc("GET /v1/admin/static-peers/{id}/config", s.withAdmin(s.handleStaticPeerConfig))
	mux.HandleFunc("POST /v1/admin/static-peers/{id}/tags", s.withAdmin(s.handleStaticPeerTags))
	mux.HandleFunc("DELETE /v1/admin/static-peers/{id}", s.withAdmin(s.handleStaticPeerDelete))
	mux.HandleFunc("POST /v1/admin/publishes", s.withAdmin(s.handlePublishCreate))
	mux.HandleFunc("GET /v1/admin/publishes", s.withAdmin(s.handlePublishList))
	mux.HandleFunc("DELETE /v1/admin/publishes/{id}", s.withAdmin(s.handlePublishDelete))
	mux.HandleFunc("GET /metrics", s.withAdmin(s.handleMetrics))
	mux.HandleFunc("GET /v1/admin/events", s.withAdmin(s.handleEventList))
	mux.HandleFunc("POST /v1/admin/policies", s.withAdmin(s.handlePolicyCreate))
	mux.HandleFunc("GET /v1/admin/policies", s.withAdmin(s.handlePolicyList))
	mux.HandleFunc("DELETE /v1/admin/policies/{id}", s.withAdmin(s.handlePolicyDelete))
	mux.HandleFunc("GET /v1/admin/lock", s.withAdmin(s.handleLockStatus))
	mux.HandleFunc("POST /v1/admin/lock", s.withAdmin(s.handleLockInit))
	mux.HandleFunc("POST /v1/admin/lock/sign", s.withAdmin(s.handleLockSign))
	mux.HandleFunc("DELETE /v1/admin/lock", s.withAdmin(s.handleLockDisable))
	// The UI page itself is a static shell without secrets; its API calls are
	// authenticated by the HttpOnly session cookie + X-Kai-UI header.
	mux.HandleFunc("GET /ui", s.handleUI)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui", http.StatusFound)
	})
	return mux
}

// --- helpers ---

// logEvent records an activity-log entry and best-effort fires the webhook.
// Never fails the caller — logging must not block an admin action.
func (s *Server) logEvent(kind, actor, message string) {
	ev, err := s.store.AddEvent(kind, actor, message, time.Now())
	if err != nil {
		s.log.Warn("event log write failed", "err", err)
		return
	}
	if s.cfg.EventWebhook != "" {
		go s.fireWebhook(ev)
	}
}

func (s *Server) fireWebhook(ev store.Event) {
	body, _ := json.Marshal(toAPIEvent(ev))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.EventWebhook, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.log.Warn("event webhook failed", "err", err)
		return
	}
	resp.Body.Close()
}

func (s *Server) handleEventList(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	evs, err := s.store.Events(before, limit)
	if err != nil {
		s.errInternal(w, err)
		return
	}
	out := make([]api.Event, 0, len(evs))
	for _, e := range evs {
		out = append(out, toAPIEvent(e))
	}
	writeJSON(w, http.StatusOK, out)
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if strings.HasPrefix(h, p) {
		return h[len(p):]
	}
	return ""
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, api.ErrorResponse{Error: msg})
}

// errInternal logs the underlying error server-side and returns an opaque 500.
// Internal details (SQL, filesystem paths) never reach the client; operators
// read the full error via `journalctl -u kai-coordinator`.
func (s *Server) errInternal(w http.ResponseWriter, err error) {
	s.log.Error("request failed", "err", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

// ensureDNS publishes {random label}.{domain} → ip and returns the fqdn
// (empty if DNS is disabled or publishing failed — enrollment must not block
// on the DNS provider).
func (s *Server) ensureDNS(ctx context.Context, ip string) string {
	if s.cfg.Domain == "" {
		return ""
	}
	label, err := dns.RandomLabel()
	if err != nil {
		return ""
	}
	fqdn := label + "." + s.cfg.Domain
	if err := s.dns.EnsureA(ctx, fqdn, ip); err != nil {
		s.log.Warn("dns record creation failed", "fqdn", fqdn, "err", err)
		return ""
	}
	return fqdn
}

// BackfillDNS assigns DNS names to devices that lack one — those enrolled
// before a DNS provider was configured. Runs once per start; a failed device
// is retried on the next restart (ensureDNS never blocks the caller).
func (s *Server) BackfillDNS(ctx context.Context) {
	if s.cfg.Domain == "" {
		return
	}
	changed := false
	if nodes, err := s.store.Nodes(); err == nil {
		for _, n := range nodes {
			if n.DNSName != "" {
				continue
			}
			fqdn := s.ensureDNS(ctx, n.OverlayIP)
			if fqdn == "" {
				continue
			}
			if err := s.store.SetNodeDNSName(n.ID, fqdn); err != nil {
				s.log.Warn("dns backfill: store update failed", "node", n.Name, "err", err)
				continue
			}
			s.log.Info("dns name backfilled", "node", n.Name, "fqdn", fqdn)
			changed = true
		}
	}
	if statics, err := s.store.StaticPeers(); err == nil {
		for _, p := range statics {
			if p.DNSName != "" {
				continue
			}
			fqdn := s.ensureDNS(ctx, p.OverlayIP)
			if fqdn == "" {
				continue
			}
			if err := s.store.SetStaticPeerDNSName(p.ID, fqdn); err != nil {
				s.log.Warn("dns backfill: store update failed", "peer", p.Name, "err", err)
				continue
			}
			s.log.Info("dns name backfilled", "peer", p.Name, "fqdn", fqdn)
			changed = true
		}
	}
	if changed {
		if _, err := s.bumpNetmap(); err != nil {
			s.log.Warn("dns backfill: netmap bump failed", "err", err)
		}
	}
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(uiHTML)
}
