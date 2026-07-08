// Package dns abstracts the DNS provider that publishes per-device names
// ({16 random chars}.{domain} → overlay IP). Providers must be idempotent:
// EnsureA may be called again for an existing record.
package dns

import (
	"context"
	"crypto/rand"
	"math/big"
)

type Provider interface {
	// EnsureA creates or updates an A record fqdn → ip.
	EnsureA(ctx context.Context, fqdn string, ip string) error
	// DeleteA removes the A record for fqdn. Deleting a missing record is not an error.
	DeleteA(ctx context.Context, fqdn string) error
}

// Noop is used when no DNS provider is configured.
type Noop struct{}

func (Noop) EnsureA(context.Context, string, string) error { return nil }
func (Noop) DeleteA(context.Context, string) error         { return nil }

const labelAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// RandomLabel returns a 16-char random DNS label (lowercase alphanumeric).
func RandomLabel() (string, error) {
	b := make([]byte, 16)
	max := big.NewInt(int64(len(labelAlphabet)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = labelAlphabet[n.Int64()]
	}
	return string(b), nil
}
