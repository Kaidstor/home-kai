package coordinator

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kaidstor/home-kai/internal/api"
)

// Network lock (tailnet-lock style): the admin keeps an ed25519 key that
// never touches the coordinator; every (wg_pubkey, overlay_ip) binding must
// carry its signature before locked agents will install the peer. A
// compromised coordinator can therefore reshuffle or drop peers, but cannot
// introduce a key of its own.
//
// meta keys: lock_pubkey (base64), lock_active ("1" once every binding was
// signed — only then do netmaps start carrying the key and agents pin it).
const (
	metaLockPubKey = "lock_pubkey"
	metaLockActive = "lock_active"
)

func (s *Server) lockState() (pub string, active bool, err error) {
	pub, err = s.store.MetaGet(metaLockPubKey)
	if err != nil {
		return "", false, err
	}
	a, err := s.store.MetaGet(metaLockActive)
	return pub, a == "1", err
}

// pendingBindings lists everything not yet signed.
func (s *Server) pendingBindings() ([]api.LockBinding, error) {
	nodes, err := s.store.Nodes()
	if err != nil {
		return nil, err
	}
	statics, err := s.store.StaticPeers()
	if err != nil {
		return nil, err
	}
	var out []api.LockBinding
	for _, n := range nodes {
		if n.LockSig == "" {
			out = append(out, api.LockBinding{
				Kind: "node", ID: n.ID, Name: n.Name, WGPublicKey: n.WGPubKey, OverlayIP: n.OverlayIP,
			})
		}
	}
	for _, p := range statics {
		if p.LockSig == "" {
			out = append(out, api.LockBinding{
				Kind: "static", ID: p.ID, Name: p.Name, WGPublicKey: p.WGPubKey, OverlayIP: p.OverlayIP,
			})
		}
	}
	return out, nil
}

func (s *Server) handleLockStatus(w http.ResponseWriter, r *http.Request) {
	pub, active, err := s.lockState()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	st := api.LockStatus{Enabled: pub != "", Active: active, PublicKey: pub}
	if st.Enabled {
		if st.Pending, err = s.pendingBindings(); err != nil {
			s.errInternal(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleLockInit(w http.ResponseWriter, r *http.Request) {
	var req api.LockInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	key, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		writeErr(w, http.StatusBadRequest, "public_key must be a base64 ed25519 key")
		return
	}
	cur, active, err := s.lockState()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	if cur != "" && cur != req.PublicKey {
		if active {
			writeErr(w, http.StatusConflict, "lock is active with a different key — disable it first")
			return
		}
		// Arming with a new key invalidates signatures made with the old one.
		if err := s.store.ClearLockSigs(); err != nil {
			s.errInternal(w, err)
			return
		}
	}
	if err := s.store.MetaSet(metaLockPubKey, req.PublicKey); err != nil {
		s.errInternal(w, err)
		return
	}
	s.log.Info("network lock armed — sign all bindings to activate", "key", req.PublicKey)
	s.logEvent(evLockInit, "admin", "network lock инициализирован (ожидает подписи)")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLockSign(w http.ResponseWriter, r *http.Request) {
	pub, _, err := s.lockState()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	if pub == "" {
		writeErr(w, http.StatusConflict, "lock is not initialized")
		return
	}
	pubKey, _ := base64.StdEncoding.DecodeString(pub)

	var req api.LockSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	nodes, err := s.store.Nodes()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	statics, err := s.store.StaticPeers()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	bindings := map[string]api.LockBinding{} // kind/id → binding
	for _, n := range nodes {
		bindings["node/"+n.ID] = api.LockBinding{Kind: "node", ID: n.ID, WGPublicKey: n.WGPubKey, OverlayIP: n.OverlayIP}
	}
	for _, p := range statics {
		bindings["static/"+p.ID] = api.LockBinding{Kind: "static", ID: p.ID, WGPublicKey: p.WGPubKey, OverlayIP: p.OverlayIP}
	}

	for _, sig := range req.Sigs {
		b, ok := bindings[sig.Kind+"/"+sig.ID]
		if !ok {
			writeErr(w, http.StatusNotFound, fmt.Sprintf("no binding %s/%s", sig.Kind, sig.ID))
			return
		}
		raw, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(pubKey), api.LockMessage(b.WGPublicKey, b.OverlayIP), raw) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("bad signature for %s/%s", sig.Kind, sig.ID))
			return
		}
		if sig.Kind == "node" {
			err = s.store.SetNodeLockSig(sig.ID, sig.Sig)
		} else {
			err = s.store.SetStaticPeerLockSig(sig.ID, sig.Sig)
		}
		if err != nil {
			s.errInternal(w, err)
			return
		}
	}

	pending, err := s.pendingBindings()
	if err != nil {
		s.errInternal(w, err)
		return
	}
	if len(pending) == 0 {
		if err := s.store.MetaSet(metaLockActive, "1"); err != nil {
			s.errInternal(w, err)
			return
		}
		s.log.Info("network lock ACTIVE — all bindings signed")
		s.logEvent(evLockActive, "admin", "network lock активирован (все привязки подписаны)")
	}
	if err := s.bumpNetmap(); err != nil {
		s.errInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"signed": len(req.Sigs), "pending": len(pending)})
}

// handleLockDisable is the escape hatch: agents that already pinned the key
// keep enforcing it until their state is reset, but the coordinator stops
// distributing it (existing signatures are kept in case it is re-enabled).
func (s *Server) handleLockDisable(w http.ResponseWriter, r *http.Request) {
	if err := s.store.MetaDelete(metaLockPubKey); err != nil {
		s.errInternal(w, err)
		return
	}
	if err := s.store.MetaDelete(metaLockActive); err != nil {
		s.errInternal(w, err)
		return
	}
	if err := s.bumpNetmap(); err != nil {
		s.errInternal(w, err)
		return
	}
	s.log.Warn("network lock disabled")
	w.WriteHeader(http.StatusNoContent)
}
