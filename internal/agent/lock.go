package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/kaidstor/home-kai/internal/api"
)

// enforceLock implements the agent half of the network lock. The first
// netmap carrying a lock key pins it (TOFU) into the state file; from then
// on the pin — not the netmap — is authoritative: a different key is a hard
// error, and peers whose (key, IP) binding is not signed by the pinned key
// are stripped before the netmap is applied. A compromised coordinator can
// thus disturb connectivity but never splice its own peer into the mesh.
func (a *Agent) enforceLock(nm *api.Netmap) error {
	if a.st.LockPublicKey == "" {
		if nm.Self.LockPublicKey == "" {
			return nil
		}
		a.st.LockPublicKey = nm.Self.LockPublicKey
		if err := a.st.Save(a.statePath); err != nil {
			return fmt.Errorf("pinning lock key: %w", err)
		}
		a.log.Info("network lock key pinned", "key", a.st.LockPublicKey)
	} else if nm.Self.LockPublicKey != "" && nm.Self.LockPublicKey != a.st.LockPublicKey {
		return fmt.Errorf("netmap carries a DIFFERENT lock key (%s) than the pinned one — refusing; "+
			"if the lock was legitimately rotated, clear lock_public_key in the state file",
			nm.Self.LockPublicKey)
	}

	pub, err := base64.StdEncoding.DecodeString(a.st.LockPublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("pinned lock key is corrupt: %v", err)
	}
	verified := nm.Peers[:0]
	for _, p := range nm.Peers {
		sig, err := base64.StdEncoding.DecodeString(p.LockSig)
		if p.LockSig == "" || err != nil ||
			!ed25519.Verify(ed25519.PublicKey(pub), api.LockMessage(p.WGPublicKey, p.OverlayIP), sig) {
			a.log.Warn("lock: dropping peer without a valid signature", "peer", p.Hostname, "ip", p.OverlayIP)
			continue
		}
		verified = append(verified, p)
	}
	nm.Peers = verified
	return nil
}
