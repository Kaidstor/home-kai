package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/kaidstor/home-kai/internal/wgkeys"
)

const rekeyCheckInterval = 12 * time.Hour

// rekeyLoop re-asserts our registered public key on start (healing a rotation
// that crashed between the coordinator accepting the new key and the state
// file recording it) and then auto-rotates when the key is older than
// RekeyDays. Disabled with the lock enabled — a fresh key would be an
// unsigned binding and peers would drop us until the admin re-signs.
func (a *Agent) rekeyLoop(ctx context.Context) {
	priv, err := wgkeys.ParsePrivate(a.st.WGPrivateKey)
	if err != nil {
		return
	}
	if err := a.client.Rekey(ctx, priv.PublicKey().String()); err != nil && ctx.Err() == nil {
		a.log.Warn("re-asserting public key failed", "err", err)
	}

	if a.st.KeyCreatedAt.IsZero() { // states from before key rotation existed
		a.st.KeyCreatedAt = time.Now()
		if err := a.st.Save(a.statePath); err != nil {
			a.log.Warn("state save failed", "err", err)
		}
	}

	t := time.NewTicker(rekeyCheckInterval)
	defer t.Stop()
	for {
		if a.st.RekeyDays > 0 && time.Since(a.st.KeyCreatedAt) > time.Duration(a.st.RekeyDays)*24*time.Hour {
			if a.lockEnabled() {
				a.log.Warn("key is due for rotation but the network lock is enabled — rotate manually and re-sign")
			} else if err := a.rotateKey(ctx); err != nil {
				a.log.Error("key rotation failed", "err", err)
			} else {
				a.log.Info("wireguard key rotated", "age_days", a.st.RekeyDays)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// rotateKey: state first, then coordinator, then the live device. Whatever
// step dies, the start-time re-assert converges state and server again.
func (a *Agent) rotateKey(ctx context.Context) error {
	pair, err := wgkeys.Generate()
	if err != nil {
		return err
	}
	if err := a.client.Rekey(ctx, pair.Public.String()); err != nil {
		return fmt.Errorf("coordinator rejected new key: %w", err)
	}
	a.st.WGPrivateKey = pair.Private.String()
	a.st.KeyCreatedAt = time.Now()
	if err := a.st.Save(a.statePath); err != nil {
		return err
	}
	return a.dev.SetPrivateKey(pair.Private)
}

// lockEnabled reports whether this agent pinned a network-lock key.
func (a *Agent) lockEnabled() bool { return a.st.LockPublicKey != "" }

// RotateStateKey is the offline path (`kai-agent rekey`, daemon stopped):
// registers a fresh key with the coordinator and rewrites the state file.
func RotateStateKey(ctx context.Context, st *State, statePath string) error {
	c, err := NewClient(st.CoordinatorURL, st.Fingerprint, st.AuthSecret)
	if err != nil {
		return err
	}
	pair, err := wgkeys.Generate()
	if err != nil {
		return err
	}
	if err := c.Rekey(ctx, pair.Public.String()); err != nil {
		return fmt.Errorf("coordinator rejected new key: %w", err)
	}
	st.WGPrivateKey = pair.Private.String()
	st.KeyCreatedAt = time.Now()
	return st.Save(statePath)
}
