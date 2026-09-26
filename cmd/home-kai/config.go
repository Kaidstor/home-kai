package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// adminConfig is ~/.config/kai/admin.json, written by `home-kai login`.
// Token is the legacy plaintext copy: it is still read as the last source,
// but new logins with --token-ref leave it empty.
type adminConfig struct {
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint"`
	TokenRef    string `json:"token_ref,omitempty"`
	Token       string `json:"token,omitempty"`
}

// settings is the admin config after env overrides, with the origin of every
// value so doctor can show which one was picked up.
type settings struct {
	Path   string // file location, whether it exists or not
	Exists bool
	File   adminConfig

	URL, URLSource                 string
	Fingerprint, FingerprintSource string
	TokenRef, TokenRefSource       string
}

type token struct {
	Value  string
	Source string
}

func adminConfigPath() string {
	if v := strings.TrimSpace(os.Getenv("HOME_KAI_CONFIG")); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".config", "kai", "admin.json")
	}
	return filepath.Join(home, ".config", "kai", "admin.json")
}

// loadSettings reads the file and lays KAI_URL, KAI_FINGERPRINT and
// KAI_TOKEN_REF over it. A missing file is not an error: env alone is enough.
func loadSettings() (settings, error) {
	s := settings{Path: adminConfigPath()}
	raw, err := os.ReadFile(s.Path)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &s.File); err != nil {
			return s, fmt.Errorf("%s: не разобрать JSON: %w", s.Path, err)
		}
		s.Exists = true
	case !errors.Is(err, os.ErrNotExist):
		return s, err
	}
	fileSrc := "file:" + s.Path
	s.URL, s.URLSource = pick("KAI_URL", s.File.URL, fileSrc)
	s.Fingerprint, s.FingerprintSource = pick("KAI_FINGERPRINT", s.File.Fingerprint, fileSrc)
	s.TokenRef, s.TokenRefSource = pick("KAI_TOKEN_REF", s.File.TokenRef, fileSrc)
	return s, nil
}

func pick(env, fileValue, fileSrc string) (string, string) {
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		return v, "env:" + env
	}
	if fileValue != "" {
		return fileValue, fileSrc
	}
	return "", ""
}

// token looks for the admin token: $KAI_ADMIN_TOKEN, then sec by token_ref,
// then the plaintext field of admin.json. The value is never printed — only
// the source and the mask.
func (s settings) token() (token, error) {
	if v := strings.TrimSpace(os.Getenv("KAI_ADMIN_TOKEN")); v != "" {
		return token{Value: v, Source: "env:KAI_ADMIN_TOKEN"}, nil
	}
	if s.TokenRef != "" {
		v, err := secGet(s.TokenRef)
		if err != nil {
			return token{}, fmt.Errorf("sec get %s: %w", s.TokenRef, err)
		}
		if v == "" {
			return token{}, fmt.Errorf("sec get %s: пустое значение", s.TokenRef)
		}
		return token{Value: v, Source: "sec:" + s.TokenRef}, nil
	}
	if s.File.Token != "" {
		return token{Value: s.File.Token, Source: "file:" + s.Path + " (открытым текстом)"}, nil
	}
	return token{}, fmt.Errorf("токен не найден: задай $KAI_ADMIN_TOKEN, token_ref в %s "+
		"(home-kai login --url URL --fingerprint HEX --token-ref <проект>/<KEY>) или KAI_TOKEN_REF", s.Path)
}

func secGet(ref string) (string, error) {
	bin, err := exec.LookPath("sec")
	if err != nil {
		return "", fmt.Errorf("sec не найден в PATH: %w", err)
	}
	out, err := exec.Command(bin, "get", ref).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("%s", strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func saveAdminConfig(path string, cfg adminConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// mask is the chat- and log-safe view of a secret.
func mask(value string) string {
	r := []rune(value)
	if len(r) < 8 {
		return fmt.Sprintf("(%d символов)", len(r))
	}
	return fmt.Sprintf("%s…%s (%d символов)", string(r[:2]), string(r[len(r)-2:]), len(r))
}
