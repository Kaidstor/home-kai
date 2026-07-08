package coordinator

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/coordinator/store"
)

// Web-UI session auth and the enroll/admin bearer middleware.

func (s *Server) withNode(h func(http.ResponseWriter, *http.Request, store.Node)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		node, err := s.store.NodeByAuthHash(sha256hex(tok))
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unknown node")
			return
		}
		_ = s.store.TouchNode(node.ID, time.Now())
		h(w, r, node)
	}
}

func (s *Server) adminTokenMatches(token string) bool {
	got := sha256hex(token)
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.AdminTokenHash)) == 1
}

// hasAdminSession reports whether the request carries a live session cookie.
// The custom UI header is required so that cookie auth never applies to
// cross-site requests (forms cannot set custom headers).
func (s *Server) hasAdminSession(r *http.Request) bool {
	if r.Header.Get(uiHeader) == "" {
		return false
	}
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	hash := sha256hex(c.Value)
	now := time.Now()
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	exp, ok := s.sessions[hash]
	if !ok {
		return false
	}
	if now.After(exp) {
		delete(s.sessions, hash)
		return false
	}
	return true
}

func (s *Server) withAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminTokenMatches(bearer(r)) && !s.hasAdminSession(r) {
			writeErr(w, http.StatusUnauthorized, "bad admin token")
			return
		}
		h(w, r)
	}
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	var req api.AdminLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if !s.adminTokenMatches(req.Token) {
		writeErr(w, http.StatusUnauthorized, "bad admin token")
		return
	}
	id, err := randomHex(32)
	if err != nil {
		s.errInternal(w, err)
		return
	}
	now := time.Now()
	s.sessMu.Lock()
	for h, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, h)
		}
	}
	s.sessions[sha256hex(id)] = now.Add(sessionTTL)
	s.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: id, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		MaxAge: int(sessionTTL.Seconds()),
	})
	s.log.Info("admin ui login")
	s.logEvent(evAdminLogin, "admin", "вход в панель управления")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		s.sessMu.Lock()
		delete(s.sessions, sha256hex(c.Value))
		s.sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		MaxAge: -1,
	})
	w.WriteHeader(http.StatusNoContent)
}
