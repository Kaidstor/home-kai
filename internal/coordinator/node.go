package coordinator

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/coordinator/store"
	"github.com/kaidstor/home-kai/internal/text"
	"github.com/kaidstor/home-kai/internal/wgkeys"
)

// Node lifecycle API: enroll, netmap long-poll, status heartbeat, rekey,
// enroll-token issuance and admin node management.

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	tok := bearer(r)
	if tok == "" {
		writeErr(w, http.StatusUnauthorized, "missing enroll token")
		return
	}
	nameHint, err := s.store.ConsumeEnrollToken(sha256hex(tok), time.Now())
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusUnauthorized, "invalid, expired or already used enroll token")
		return
	}
	if err != nil {
		s.errInternal(w, err)
		return
	}

	var req api.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if _, err := wgkeys.ParsePublic(req.WGPublicKey); err != nil {
		writeErr(w, http.StatusBadRequest, "bad wg_public_key")
		return
	}
	if req.Role == "" {
		req.Role = api.RoleNode
	}
	if req.Role != api.RoleNode && req.Role != api.RoleHub {
		writeErr(w, http.StatusBadRequest, "role must be node or hub")
		return
	}

	nodes, err := s.store.Nodes()
	if err != nil {
		s.errInternal(w, err)
		return
	}

	var overlayIP netip.Addr
	if req.Role == api.RoleHub {
		for _, n := range nodes {
			if n.Role == string(api.RoleHub) {
				writeErr(w, http.StatusConflict, "a hub is already enrolled")
				return
			}
		}
		overlayIP = HubIP(s.cfg.OverlayCIDR)
	} else {
		overlayIP, err = s.allocateIP()
		if err != nil {
			s.errInternal(w, err)
			return
		}
	}

	name := req.Hostname
	if nameHint != "" {
		name = nameHint
	}
	nodeID, err := randomHex(8)
	if err != nil {
		s.errInternal(w, err)
		return
	}
	authSecret, err := randomHex(32)
	if err != nil {
		s.errInternal(w, err)
		return
	}

	dnsName := s.ensureDNS(r.Context(), overlayIP.String())

	now := time.Now()
	// The hub is trusted implicitly (it is the admin's own VPS); only spokes
	// wait for approval, and only when the mode is enabled.
	approved := !s.cfg.RequireApproval || req.Role == api.RoleHub
	node := store.Node{
		ID: "n_" + nodeID, Name: name, OS: req.OS, Arch: req.Arch, Role: string(req.Role),
		WGPubKey: req.WGPublicKey, WGListenPort: req.WGListenPort,
		OverlayIP: overlayIP.String(), DNSName: dnsName,
		AuthSecretHash: sha256hex(authSecret), CreatedAt: now, LastSeen: now,
		Approved: approved,
	}
	if err := s.store.CreateNode(node); err != nil {
		s.errInternal(w, err)
		return
	}
	version, err := s.bumpNetmap()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	s.log.Info("node enrolled", "id", node.ID, "name", name, "role", node.Role, "ip", node.OverlayIP, "dns", dnsName, "approved", approved)
	if approved {
		s.logEvent(evNodeEnroll, name, fmt.Sprintf("узел %s (%s) подключён с ролью %s", name, node.OverlayIP, node.Role))
	} else {
		s.logEvent(evNodePending, name, fmt.Sprintf("узел %s (%s) ожидает одобрения", name, node.OverlayIP))
	}

	writeJSON(w, http.StatusOK, api.EnrollResponse{
		NodeID: node.ID, AuthSecret: authSecret,
		OverlayIP: node.OverlayIP, OverlayCIDR: s.cfg.OverlayCIDR.String(),
		DNSName: dnsName, MTU: s.cfg.MTU, NetmapVersion: version,
	})
}

// endpointFreshness caps how old an endpoint may be to serve as an M3
// candidate: agents refresh local endpoints and the hub refreshes observed
// ones every status interval, so anything older belongs to a gone node.
const endpointFreshness = 15 * time.Minute

func (s *Server) buildNetmapFor(node store.Node, version int64) (api.Netmap, error) {
	allNodes, err := s.store.Nodes()
	if err != nil {
		return api.Netmap{}, err
	}
	// Unapproved nodes are invisible to everyone (and to the netmap builder).
	nodes := make([]store.Node, 0, len(allNodes))
	for _, n := range allNodes {
		if n.Approved {
			nodes = append(nodes, n)
		}
	}
	statics, err := s.store.StaticPeers()
	if err != nil {
		return api.Netmap{}, err
	}
	eps, err := s.store.EndpointsByNode()
	if err != nil {
		return api.Netmap{}, err
	}
	var publishes []store.Publish
	if node.Role == string(api.RoleHub) {
		if publishes, err = s.store.Publishes(); err != nil {
			return api.Netmap{}, err
		}
	}
	lockPub, lockActive, err := s.lockState()
	if err != nil {
		return api.Netmap{}, err
	}
	if !lockActive {
		lockPub = "" // arming phase: nothing distributed until everything is signed
	}
	now := time.Now()
	candidates := map[string][]string{}
	for id, list := range eps {
		var local, observed []string
		for _, e := range list {
			if now.Sub(e.UpdatedAt) > endpointFreshness {
				continue
			}
			if e.Kind == "local" {
				local = append(local, e.Addr)
			} else {
				observed = append(observed, e.Addr)
			}
		}
		// LAN candidates first: same-network pairs get the short path and
		// punching a reflexive address is the fallback.
		if all := append(local, observed...); len(all) > 0 {
			candidates[id] = all
		}
	}
	nm, err := BuildNetmap(node, nodes, statics, candidates, publishes, lockPub, s.cfg.OverlayCIDR, s.cfg.HubEndpoint, s.cfg.MTU, version)
	if err != nil {
		return api.Netmap{}, err
	}
	// ACL: compile this node's inbound allow-rules. The filter turns on only
	// once at least one *enabled* policy exists — otherwise the network stays
	// open (backward compatible).
	policies, err := s.store.Policies()
	if err != nil {
		return api.Netmap{}, err
	}
	anyEnabled := false
	for _, p := range policies {
		if p.Enabled {
			anyEnabled = true
			break
		}
	}
	if anyEnabled {
		nm.Self.FilterEnabled = true
		nm.FilterRules = computeFilterRules(node, nodes, statics, policies)
	}
	return nm, nil
}

func (s *Server) handleNetmap(w http.ResponseWriter, r *http.Request, node store.Node) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	deadline := time.After(longPollTimeout)
	for {
		wake := s.wakeChan()
		// An unapproved node sees nothing until the admin lets it in. Approval
		// bumps the netmap, so waiting on the wake channel picks it up at once.
		if !node.Approved {
			select {
			case <-wake:
				if fresh, err := s.store.NodeByID(node.ID); err == nil {
					node = fresh
				}
				continue
			case <-deadline:
				w.WriteHeader(http.StatusNotModified)
				return
			case <-r.Context().Done():
				return
			}
		}
		version, err := s.store.NetmapVersion()
		if err != nil {
			s.errInternal(w, err)
			return
		}
		if version > since {
			nm, err := s.buildNetmapFor(node, version)
			if err != nil {
				s.errInternal(w, err)
				return
			}
			writeJSON(w, http.StatusOK, nm)
			return
		}
		select {
		case <-wake:
		case <-deadline:
			w.WriteHeader(http.StatusNotModified)
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, node store.Node) {
	var rep api.StatusReport
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	now := time.Now()
	needBump := false

	epChanged, err := s.store.ReplaceEndpoints(node.ID, "local", rep.EndpointsLocal, now)
	if err != nil {
		s.errInternal(w, err)
		return
	}
	needBump = needBump || epChanged

	// Subnet router announcements. Advertising is remembered as-is; only the
	// admin-enabled subset reaches netmaps, so a change here bumps the netmap
	// only when it retracts a previously enabled route.
	routes, err := normalizeRoutes(rep.AdvertisedRoutes, s.cfg.OverlayCIDR)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	advChanged, enabledChanged, err := s.store.SetAdvertisedRoutes(node.ID, routes)
	if err != nil {
		s.errInternal(w, err)
		return
	}
	if advChanged {
		s.log.Info("advertised routes updated", "node", node.Name, "routes", routes)
	}
	needBump = needBump || enabledChanged

	// Observed endpoints come only from the hub (it terminates every tunnel).
	if node.Role == string(api.RoleHub) && len(rep.PeersObserved) > 0 {
		nodes, err := s.store.Nodes()
		if err != nil {
			s.errInternal(w, err)
			return
		}
		byKey := map[string]string{}
		for _, n := range nodes {
			byKey[n.WGPubKey] = n.ID
		}
		for _, po := range rep.PeersObserved {
			id, ok := byKey[po.WGPublicKey]
			if !ok || po.Endpoint == "" {
				continue
			}
			obsChanged, err := s.store.ReplaceEndpoints(id, "observed", []string{po.Endpoint}, now)
			if err != nil {
				s.errInternal(w, err)
				return
			}
			needBump = needBump || obsChanged
		}
	}

	// Endpoint/route changes alter M3 candidates or subnet routing — wake the
	// long-polls. Unchanged heartbeats (the common case) bump nothing.
	if needBump {
		if _, err := s.bumpNetmap(); err != nil {
			s.errInternal(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRekey(w http.ResponseWriter, r *http.Request, node store.Node) {
	var req api.RekeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if _, err := wgkeys.ParsePublic(req.WGPublicKey); err != nil {
		writeErr(w, http.StatusBadRequest, "bad wg_public_key")
		return
	}
	if req.WGPublicKey == node.WGPubKey {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := s.store.SetNodeKey(node.ID, req.WGPublicKey); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeErr(w, http.StatusConflict, "key already in use")
			return
		}
		s.errInternal(w, err)
		return
	}
	if _, err := s.bumpNetmap(); err != nil {
		s.errInternal(w, err)
		return
	}
	s.log.Info("node key rotated", "node", node.Name)
	s.logEvent(evNodeRekey, node.Name, fmt.Sprintf("узел %s сменил WireGuard-ключ", node.Name))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	var req api.TokenCreateRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
			return
		}
	}
	// Clamp: an enroll token is a bearer credential, "practically eternal"
	// must not be one typo away.
	const maxTokenTTL = 7 * 24 * time.Hour
	ttl := time.Hour
	if req.TTLSec > 0 {
		ttl = min(time.Duration(req.TTLSec)*time.Second, maxTokenTTL)
	}
	token, err := randomHex(24)
	if err != nil {
		s.errInternal(w, err)
		return
	}
	expires := time.Now().Add(ttl)
	if err := s.store.CreateEnrollToken(sha256hex(token), req.NameHint, expires); err != nil {
		s.errInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.TokenCreateResponse{
		Token:       token,
		ExpiresAt:   expires,
		Fingerprint: s.cfg.Fingerprint,
		JoinCommand: fmt.Sprintf("sudo kai-agent up --coordinator %s --token %s --fingerprint %s",
			s.cfg.PublicURL, token, s.cfg.Fingerprint),
	})
}

func (s *Server) handleNodeList(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.Nodes()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	now := time.Now()
	out := make([]api.NodeInfo, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, toAPINode(n, now))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleNodeRoutes enables a subset of a node's advertised routes. A route may
// be served by only one node at a time (identical prefixes on two peers would
// silently fight over cryptokey routing).
func (s *Server) handleNodeRoutes(w http.ResponseWriter, r *http.Request) {
	node, ok := s.nodeOr404(w, r)
	if !ok {
		return
	}
	var req api.NodeRoutesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	enabled, err := normalizeRoutes(req.Enabled, s.cfg.OverlayCIDR)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	advertised := map[string]bool{}
	for _, a := range node.RoutesAdvertised {
		advertised[a] = true
	}
	for _, e := range enabled {
		if !advertised[e] {
			writeErr(w, http.StatusConflict, fmt.Sprintf("route %s is not advertised by %s", e, node.Name))
			return
		}
	}
	nodes, err := s.store.Nodes()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	for _, other := range nodes {
		if other.ID == node.ID {
			continue
		}
		for _, oe := range other.RoutesEnabled {
			for _, e := range enabled {
				if oe == e {
					writeErr(w, http.StatusConflict,
						fmt.Sprintf("route %s is already served by %s", e, other.Name))
					return
				}
			}
		}
	}
	if err := s.store.SetEnabledRoutes(node.ID, enabled); err != nil {
		s.errInternal(w, err)
		return
	}
	if _, err := s.bumpNetmap(); err != nil {
		s.errInternal(w, err)
		return
	}
	s.log.Info("routes enabled", "node", node.Name, "routes", enabled)
	s.logEvent(evNodeRoutes, "admin", fmt.Sprintf("для узла %s включены подсети: %s", node.Name, text.JoinCSV(enabled)))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleNodeApprove(w http.ResponseWriter, r *http.Request) {
	node, ok := s.nodeOr404(w, r)
	if !ok {
		return
	}
	if node.Approved {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := s.store.SetNodeApproved(node.ID, true); err != nil {
		s.errInternal(w, err)
		return
	}
	if _, err := s.bumpNetmap(); err != nil {
		s.errInternal(w, err)
		return
	}
	s.log.Info("node approved", "name", node.Name)
	s.logEvent(evNodeApprove, "admin", fmt.Sprintf("узел %s одобрен", node.Name))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleNodeTags(w http.ResponseWriter, r *http.Request) {
	node, ok := s.nodeOr404(w, r)
	if !ok {
		return
	}
	var req api.TagsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	tags := normalizeTags(req.Tags)
	if err := s.store.SetNodeTags(node.ID, tags); err != nil {
		s.errInternal(w, err)
		return
	}
	if _, err := s.bumpNetmap(); err != nil {
		s.errInternal(w, err)
		return
	}
	s.logEvent(evNodeTags, "admin", fmt.Sprintf("узлу %s заданы теги: %s", node.Name, text.JoinCSV(tags)))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleNodeDelete(w http.ResponseWriter, r *http.Request) {
	node, ok := s.nodeOr404(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteNode(node.ID); err != nil {
		s.errInternal(w, err)
		return
	}
	if node.DNSName != "" {
		if err := s.dns.DeleteA(r.Context(), node.DNSName); err != nil {
			s.log.Warn("dns record deletion failed", "fqdn", node.DNSName, "err", err)
		}
	}
	if _, err := s.bumpNetmap(); err != nil {
		s.errInternal(w, err)
		return
	}
	s.log.Info("node deleted", "id", node.ID, "name", node.Name)
	s.logEvent(evNodeDelete, "admin", fmt.Sprintf("узел %s удалён", node.Name))
	w.WriteHeader(http.StatusNoContent)
}
