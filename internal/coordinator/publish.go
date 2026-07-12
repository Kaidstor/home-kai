package coordinator

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/coordinator/store"
)

// reservedPorts can never be published: SSH, the coordinator listeners,
// WireGuard, 80/443 — certbot's http-01 needs them free for the UI
// certificate — and 53, the hub's overlay DNS responder. Ports of other
// services living on the same host go into the reserved_ports config list.
var reservedPorts = map[int]bool{
	22: true, 53: true, 80: true, 443: true, 8443: true, 8444: true, 51820: true,
}

func (s *Server) portReserved(p int) bool {
	if reservedPorts[p] {
		return true
	}
	for _, rp := range s.cfg.ReservedPorts {
		if rp == p {
			return true
		}
	}
	return false
}

func (s *Server) validatePublishTarget(target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("target must be host:port: %v", err)
	}
	if p, err := strconv.Atoi(portStr); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("bad target port %q", portStr)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !s.cfg.OverlayCIDR.Contains(ip) {
			return fmt.Errorf("target %s is outside the overlay %s", ip, s.cfg.OverlayCIDR)
		}
		return nil
	}
	if !strings.HasSuffix(host, api.HostsSuffix) {
		return fmt.Errorf("target host must be an overlay IP or a *%s name", api.HostsSuffix)
	}
	return nil
}

func (s *Server) handlePublishCreate(w http.ResponseWriter, r *http.Request) {
	var req api.PublishCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.ListenPort < 1 || req.ListenPort > 65535 {
		writeErr(w, http.StatusBadRequest, "listen_port must be 1-65535")
		return
	}
	if s.portReserved(req.ListenPort) {
		writeErr(w, http.StatusConflict, fmt.Sprintf("port %d is reserved", req.ListenPort))
		return
	}
	if err := s.validatePublishTarget(req.Target); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := randomHex(8)
	if err != nil {
		s.errInternal(w, err)
		return
	}
	p := store.Publish{
		ID: "pub_" + id, Name: req.Name, ListenPort: req.ListenPort,
		Target: req.Target, CreatedAt: time.Now(),
	}
	if err := s.store.CreatePublish(p); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeErr(w, http.StatusConflict, "name or port already used")
			return
		}
		s.errInternal(w, err)
		return
	}
	if _, err := s.bumpNetmap(); err != nil {
		s.errInternal(w, err)
		return
	}
	s.log.Info("publish created", "name", p.Name, "port", p.ListenPort, "target", p.Target)
	s.logEvent(evPublishCreate, "admin", fmt.Sprintf("публикация %s: порт %d → %s", p.Name, p.ListenPort, p.Target))
	writeJSON(w, http.StatusOK, toAPIPublish(p))
}

func toAPIPublish(p store.Publish) api.Publish {
	return api.Publish{ID: p.ID, Name: p.Name, ListenPort: p.ListenPort, Target: p.Target, CreatedAt: p.CreatedAt}
}

func (s *Server) handlePublishList(w http.ResponseWriter, r *http.Request) {
	pubs, err := s.store.Publishes()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	out := make([]api.Publish, 0, len(pubs))
	for _, p := range pubs {
		out = append(out, toAPIPublish(p))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePublishDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeletePublish(id); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such publish")
		return
	} else if err != nil {
		s.errInternal(w, err)
		return
	}
	if _, err := s.bumpNetmap(); err != nil {
		s.errInternal(w, err)
		return
	}
	s.log.Info("publish deleted", "id", id)
	s.logEvent(evPublishDelete, "admin", "публикация удалена")
	w.WriteHeader(http.StatusNoContent)
}
