package coordinator

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/coordinator/store"
	"github.com/kaidstor/home-kai/internal/text"
	"github.com/kaidstor/home-kai/internal/wgkeys"
)

// Static-peer (WireGuard-app device) admin API and config rendering.

func (s *Server) handleStaticPeerCreate(w http.ResponseWriter, r *http.Request) {
	var req api.StaticPeerCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	hub, err := s.hubNode()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	if hub == nil {
		writeErr(w, http.StatusConflict, "enroll the hub before creating static peers")
		return
	}

	pair, err := wgkeys.Generate()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	ip, err := s.allocateIP()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	id, err := randomHex(8)
	if err != nil {
		s.errInternal(w, err)
		return
	}
	dnsName := s.ensureDNS(r.Context(), ip.String())

	sp := store.StaticPeer{
		ID: "sp_" + id, Name: req.Name,
		WGPubKey: pair.Public.String(), WGPrivKey: pair.Private.String(),
		OverlayIP: ip.String(), DNSName: dnsName, CreatedAt: time.Now(),
	}
	if err := s.store.CreateStaticPeer(sp); err != nil {
		s.errInternal(w, err)
		return
	}
	if _, err := s.bumpNetmap(); err != nil {
		s.errInternal(w, err)
		return
	}

	conf := renderStaticPeerConf(pair.Private.String(), sp.OverlayIP, hub.WGPubKey,
		s.cfg.HubEndpoint, s.cfg.OverlayCIDR.Masked().String(), req.Full)
	s.log.Info("static peer created", "name", sp.Name, "ip", sp.OverlayIP, "dns", dnsName, "full", req.Full)
	s.logEvent(evStaticPeerCreate, "admin", fmt.Sprintf("static peer %s (%s) создан", sp.Name, sp.OverlayIP))
	writeJSON(w, http.StatusOK, api.StaticPeerCreateResponse{
		ID: sp.ID, Name: sp.Name, OverlayIP: sp.OverlayIP, DNSName: dnsName, ConfINI: conf,
	})
}

func (s *Server) handleStaticPeerList(w http.ResponseWriter, r *http.Request) {
	peers, err := s.store.StaticPeers()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	out := make([]api.StaticPeerInfo, 0, len(peers))
	for _, p := range peers {
		out = append(out, toAPIStaticPeer(p))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleStaticPeerTags mirrors handleNodeTags: tags group devices for ACL
// policies, and static peers (phones) participate as sources/destinations.
func (s *Server) handleStaticPeerTags(w http.ResponseWriter, r *http.Request) {
	sp, ok := s.staticPeerOr404(w, r)
	if !ok {
		return
	}
	var req api.TagsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	tags := normalizeTags(req.Tags)
	if err := s.store.SetStaticPeerTags(sp.ID, tags); err != nil {
		s.errInternal(w, err)
		return
	}
	if _, err := s.bumpNetmap(); err != nil {
		s.errInternal(w, err)
		return
	}
	s.logEvent(evStaticPeerTags, "admin", fmt.Sprintf("static peer %s: заданы теги: %s", sp.Name, text.JoinCSV(tags)))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStaticPeerConfig(w http.ResponseWriter, r *http.Request) {
	sp, ok := s.staticPeerOr404(w, r)
	if !ok {
		return
	}
	hub, err := s.hubNode()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	if hub == nil {
		writeErr(w, http.StatusConflict, "no hub enrolled")
		return
	}
	full := r.URL.Query().Get("full") == "1"
	conf := renderStaticPeerConf(sp.WGPrivKey, sp.OverlayIP, hub.WGPubKey,
		s.cfg.HubEndpoint, s.cfg.OverlayCIDR.Masked().String(), full)
	png, err := qrcode.Encode(conf, qrcode.Medium, 320)
	if err != nil {
		s.errInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.StaticPeerConfigResponse{
		ID: sp.ID, Name: sp.Name, OverlayIP: sp.OverlayIP, DNSName: sp.DNSName,
		ConfINI: conf, QRPNGBase64: base64.StdEncoding.EncodeToString(png),
	})
}

func (s *Server) handleStaticPeerDelete(w http.ResponseWriter, r *http.Request) {
	sp, ok := s.staticPeerOr404(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteStaticPeer(sp.ID); err != nil {
		s.errInternal(w, err)
		return
	}
	if sp.DNSName != "" {
		if err := s.dns.DeleteA(r.Context(), sp.DNSName); err != nil {
			s.log.Warn("dns record deletion failed", "fqdn", sp.DNSName, "err", err)
		}
	}
	if _, err := s.bumpNetmap(); err != nil {
		s.errInternal(w, err)
		return
	}
	s.log.Info("static peer deleted", "id", sp.ID, "name", sp.Name)
	s.logEvent(evStaticPeerDelete, "admin", fmt.Sprintf("static peer %s удалён", sp.Name))
	w.WriteHeader(http.StatusNoContent)
}

// hubNode returns the enrolled hub or nil if there is none yet.
func (s *Server) hubNode() (*store.Node, error) {
	nodes, err := s.store.Nodes()
	if err != nil {
		return nil, err
	}
	for i := range nodes {
		if nodes[i].Role == string(api.RoleHub) {
			return &nodes[i], nil
		}
	}
	return nil, nil
}

// renderStaticPeerConf renders the WireGuard app config. full=true turns the
// hub into an exit node for this device: all IPv4 traffic enters the tunnel
// and the hub masquerades it out. IPv6 stays outside the tunnel on purpose —
// the overlay is v4-only and blackholing ::/0 would slow every dual-stack
// site down instead of failing over.
func renderStaticPeerConf(privKey, addr, hubPubKey, hubEndpoint, overlayCIDR string, full bool) string {
	allowed, dns := overlayCIDR, ""
	if full {
		allowed = "0.0.0.0/0"
		dns = "DNS = 1.1.1.1, 8.8.8.8\n"
	}
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
%s
[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = %d
`, privKey, addr, dns, hubPubKey, hubEndpoint, allowed, KeepaliveSec)
}
