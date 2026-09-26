package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/exit"
	"github.com/kaidstor/home-kai/internal/output"
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

func cmdLock(ctx context.Context, p *output.Printer, args []string) int {
	const synopsis = "lock init|sign|status|disable [--key FILE]"
	fs := newFlagSet("lock")
	keyPath := fs.String("key", defaultLockKeyPath(), "")
	pos, code, ok := parse(p, "lock", synopsis, fs, args, 1)
	if !ok {
		return code
	}
	command := "lock " + pos[0]
	switch pos[0] {
	case "init", "sign", "status", "disable":
	default:
		return p.Fail("lock", exit.Tool, "usage", "использование: home-kai %s", synopsis)
	}
	a, code, ok := adminClient(p, command)
	if !ok {
		return code
	}
	switch pos[0] {
	case "init":
		return cmdLockInit(ctx, p, a, *keyPath)
	case "sign":
		return cmdLockSign(ctx, p, a, *keyPath)
	case "status":
		return cmdLockStatus(ctx, p, a)
	default:
		if err := a.do(ctx, http.MethodDelete, "/v1/admin/lock", nil, nil); err != nil {
			return fail(p, command, err)
		}
		return p.Result(command, exit.OK, map[string]any{"enabled": false}, func(w io.Writer) {
			fmt.Fprintln(w, "lock выключен на координаторе; агенты держат закреплённый ключ до сброса состояния")
		})
	}
}

type lockInitData struct {
	KeyPath   string `json:"key_path"`
	NewKey    bool   `json:"new_key"`
	PublicKey string `json:"public_key"`
}

func cmdLockInit(ctx context.Context, p *output.Printer, a admin, keyPath string) int {
	const command = "lock init"
	data := lockInitData{KeyPath: keyPath}
	var priv ed25519.PrivateKey
	if existing, err := loadLockKey(keyPath); err == nil {
		priv = existing
	} else {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return p.Fail(command, exit.Tool, "config", "%s", err)
		}
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
			return p.Fail(command, exit.Tool, "config", "%s", err)
		}
		if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
			return p.Fail(command, exit.Tool, "config", "%s", err)
		}
		priv = ed25519.NewKeyFromSeed(seed)
		data.NewKey = true
		p.Warn("новый ключ lock записан в %s — СДЕЛАЙ БЭКАП, больше его нигде нет", keyPath)
	}
	data.PublicKey = base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if err := a.do(ctx, http.MethodPost, "/v1/admin/lock", api.LockInitRequest{PublicKey: data.PublicKey}, nil); err != nil {
		return fail(p, command, err)
	}
	return p.Result(command, exit.OK, data, func(w io.Writer) {
		if !data.NewKey {
			fmt.Fprintln(w, "взят существующий ключ", keyPath)
		}
		fmt.Fprintf(w, "lock взведён ключом %s\nдальше: home-kai lock sign\n", data.PublicKey)
	})
}

type lockSignData struct {
	Signed  []api.LockBinding `json:"signed"`
	Count   int               `json:"signed_count"`
	Pending int               `json:"pending"`
	Active  bool              `json:"active"`
}

func cmdLockSign(ctx context.Context, p *output.Printer, a admin, keyPath string) int {
	const command = "lock sign"
	priv, err := loadLockKey(keyPath)
	if err != nil {
		return p.Fail(command, exit.Tool, "config", "ключ lock: %s (сначала home-kai lock init)", err)
	}
	var st api.LockStatus
	if err := a.get(ctx, "/v1/admin/lock", &st); err != nil {
		return fail(p, command, err)
	}
	if !st.Enabled {
		return p.Fail(command, exit.NotApplied, "lock_disabled", "lock не инициализирован — сначала home-kai lock init")
	}
	data := lockSignData{Signed: []api.LockBinding{}, Active: st.Active}
	if len(st.Pending) == 0 {
		return p.Result(command, exit.OK, data, func(w io.Writer) { fmt.Fprintln(w, "подписывать нечего") })
	}
	req := api.LockSignRequest{}
	for _, b := range st.Pending {
		sig := ed25519.Sign(priv, api.LockMessage(b.WGPublicKey, b.OverlayIP))
		req.Sigs = append(req.Sigs, api.LockSignature{
			Kind: b.Kind, ID: b.ID, Sig: base64.StdEncoding.EncodeToString(sig),
		})
	}
	var resp map[string]int
	if err := a.do(ctx, http.MethodPost, "/v1/admin/lock/sign", req, &resp); err != nil {
		return fail(p, command, err)
	}
	data.Signed, data.Count, data.Pending = st.Pending, resp["signed"], resp["pending"]
	data.Active = data.Pending == 0
	return p.Result(command, exit.OK, data, func(w io.Writer) {
		for _, b := range data.Signed {
			fmt.Fprintf(w, "подписан %-6s %-20s %s (%s)\n", b.Kind, b.Name, b.OverlayIP, b.ID)
		}
		fmt.Fprintf(w, "подписано привязок: %d, ждут подписи: %d\n", data.Count, data.Pending)
		if data.Active {
			fmt.Fprintln(w, "lock АКТИВЕН")
		}
	})
}

func cmdLockStatus(ctx context.Context, p *output.Printer, a admin) int {
	const command = "lock status"
	var st api.LockStatus
	if err := a.get(ctx, "/v1/admin/lock", &st); err != nil {
		return fail(p, command, err)
	}
	return p.Result(command, exit.OK, st, func(w io.Writer) {
		switch {
		case !st.Enabled:
			fmt.Fprintln(w, "lock: выключен")
		case st.Active:
			fmt.Fprintln(w, "lock: АКТИВЕН, ключ", st.PublicKey)
		default:
			fmt.Fprintln(w, "lock: взводится (ещё не применяется), ключ", st.PublicKey)
		}
		for _, b := range st.Pending {
			fmt.Fprintf(w, "  ждёт подписи: %-6s %-20s %s (%s)\n", b.Kind, b.Name, b.OverlayIP, b.ID)
		}
		if st.Enabled && len(st.Pending) > 0 {
			fmt.Fprintln(w, "подписать: home-kai lock sign")
		}
	})
}
