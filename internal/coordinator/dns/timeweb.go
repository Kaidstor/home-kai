package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const twBaseURL = "https://api.timeweb.cloud"

var errTwNotFound = errors.New("timeweb: not found")

// Timeweb manages A records in one DNS zone via the Timeweb Cloud API
// (token: panel → «API и Terraform»). The zone must be delegated to Timeweb NS.
//
// API model quirk: a record created with a `subdomain` field is NOT listed in
// the zone — it lives in a per-fqdn namespace and is read, updated and
// deleted via /domains/{fqdn}/dns-records (verified empirically; the zone
// listing shows zone-level records only).
type Timeweb struct {
	Zone  string // e.g. "example.com"
	Token string
	HTTP  *http.Client
}

func NewTimeweb(zone, token string) *Timeweb {
	return &Timeweb{Zone: zone, Token: token, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

type twRecord struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

func (t *Timeweb) subdomain(fqdn string) (string, error) {
	sub := strings.TrimSuffix(fqdn, "."+t.Zone)
	if sub == fqdn || sub == "" {
		return "", fmt.Errorf("timeweb: %q is not inside zone %q", fqdn, t.Zone)
	}
	return sub, nil
}

func (t *Timeweb) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, twBaseURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+t.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := t.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%s %s: %w", method, path, errTwNotFound)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("timeweb: %s %s: %s: %s", method, path, resp.Status, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// findA returns the record ID of an existing A record for fqdn, or 0. A 404
// simply means the subdomain has never been created.
func (t *Timeweb) findA(ctx context.Context, fqdn string) (int64, error) {
	var page struct {
		Records []twRecord `json:"dns_records"`
	}
	err := t.do(ctx, http.MethodGet, "/api/v1/domains/"+fqdn+"/dns-records?limit=100", nil, &page)
	if errors.Is(err, errTwNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	for _, r := range page.Records {
		if r.Type == "A" {
			return r.ID, nil
		}
	}
	return 0, nil
}

func (t *Timeweb) EnsureA(ctx context.Context, fqdn, ip string) error {
	sub, err := t.subdomain(fqdn)
	if err != nil {
		return err
	}
	id, err := t.findA(ctx, fqdn)
	if err != nil {
		return err
	}
	if id != 0 {
		return t.do(ctx, http.MethodPatch,
			fmt.Sprintf("/api/v1/domains/%s/dns-records/%d", fqdn, id),
			map[string]any{"type": "A", "value": ip}, nil)
	}
	// Creation goes through the zone: the subdomain field both creates the
	// per-fqdn namespace and puts the record into it.
	return t.do(ctx, http.MethodPost,
		fmt.Sprintf("/api/v1/domains/%s/dns-records", t.Zone),
		map[string]any{"type": "A", "value": ip, "subdomain": sub, "ttl": 600}, nil)
}

func (t *Timeweb) DeleteA(ctx context.Context, fqdn string) error {
	if _, err := t.subdomain(fqdn); err != nil {
		return err
	}
	id, err := t.findA(ctx, fqdn)
	if err != nil {
		return err
	}
	if id == 0 {
		return nil // already gone
	}
	err = t.do(ctx, http.MethodDelete,
		fmt.Sprintf("/api/v1/domains/%s/dns-records/%d", fqdn, id), nil, nil)
	if errors.Is(err, errTwNotFound) {
		return nil
	}
	return err
}
