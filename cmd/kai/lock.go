package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/kaidstor/home-kai/internal/api"
)

// The network-lock private key lives ONLY on the admin machine — that is the
// whole point: the coordinator can verify signatures but never produce them.
func defaultLockKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "kai-lock.key"
	}
	return filepath.Join(home, ".config", "kai", "lock.key")
}

func loadLockKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(string(b))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: expected %d hex-encoded bytes", path, ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func cmdLock(ctx context.Context, args []string) {
	if len(args) < 1 {
		usage()
	}
	sub := args[0]
	fs := flag.NewFlagSet("lock "+sub, flag.ExitOnError)
	keyPath := fs.String("key", defaultLockKeyPath(), "network-lock private key file")
	_ = fs.Parse(args[1:])

	switch sub {
	case "init":
		cmdLockInit(ctx, *keyPath)
	case "sign":
		cmdLockSign(ctx, *keyPath)
	case "status":
		cmdLockStatus(ctx)
	case "disable":
		if _, err := client().Do(ctx, http.MethodDelete, "/v1/admin/lock", nil, nil); err != nil {
			fatal(err)
		}
		fmt.Println("lock disabled on the coordinator; agents keep their pinned key until state reset")
	default:
		usage()
	}
}

func cmdLockInit(ctx context.Context, keyPath string) {
	var priv ed25519.PrivateKey
	if existing, err := loadLockKey(keyPath); err == nil {
		priv = existing
		fmt.Println("reusing existing key", keyPath)
	} else {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
			fatal(err)
		}
		if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
			fatal(err)
		}
		priv = ed25519.NewKeyFromSeed(seed)
		fmt.Println("new lock key written to", keyPath, "— BACK IT UP, it exists nowhere else")
	}
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if _, err := client().Do(ctx, http.MethodPost, "/v1/admin/lock", api.LockInitRequest{PublicKey: pub}, nil); err != nil {
		fatal(err)
	}
	fmt.Printf("lock armed with key %s\nnow run: kai lock sign\n", pub)
}

func cmdLockSign(ctx context.Context, keyPath string) {
	priv, err := loadLockKey(keyPath)
	if err != nil {
		fatal(fmt.Errorf("lock key: %w (run `kai lock init` first)", err))
	}
	var st api.LockStatus
	if _, err := client().Do(ctx, http.MethodGet, "/v1/admin/lock", nil, &st); err != nil {
		fatal(err)
	}
	if !st.Enabled {
		fatal(fmt.Errorf("lock is not initialized — run `kai lock init`"))
	}
	if len(st.Pending) == 0 {
		fmt.Println("nothing to sign")
		return
	}
	req := api.LockSignRequest{}
	for _, b := range st.Pending {
		sig := ed25519.Sign(priv, api.LockMessage(b.WGPublicKey, b.OverlayIP))
		req.Sigs = append(req.Sigs, api.LockSignature{
			Kind: b.Kind, ID: b.ID, Sig: base64.StdEncoding.EncodeToString(sig),
		})
		fmt.Printf("signed %-6s %-20s %s (%s)\n", b.Kind, b.Name, b.OverlayIP, b.ID)
	}
	var resp map[string]int
	if _, err := client().Do(ctx, http.MethodPost, "/v1/admin/lock/sign", req, &resp); err != nil {
		fatal(err)
	}
	fmt.Printf("signed %d binding(s), %d still pending\n", resp["signed"], resp["pending"])
	if resp["pending"] == 0 {
		fmt.Println("lock is ACTIVE")
	}
}

func cmdLockStatus(ctx context.Context) {
	var st api.LockStatus
	if _, err := client().Do(ctx, http.MethodGet, "/v1/admin/lock", nil, &st); err != nil {
		fatal(err)
	}
	switch {
	case !st.Enabled:
		fmt.Println("lock: disabled")
	case st.Active:
		fmt.Println("lock: ACTIVE, key", st.PublicKey)
	default:
		fmt.Println("lock: arming (not enforced yet), key", st.PublicKey)
	}
	for _, b := range st.Pending {
		fmt.Printf("  pending: %-6s %-20s %s (%s)\n", b.Kind, b.Name, b.OverlayIP, b.ID)
	}
	if st.Enabled && len(st.Pending) > 0 {
		fmt.Println("run `kai lock sign` to sign them")
	}
}
