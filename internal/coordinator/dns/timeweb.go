package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const twBaseURL = "https://api.timeweb.cloud"

// Timeweb manages A records in one DNS zone via the Timeweb Cloud API
// (token: panel → «API и Terraform»). The zone must be delegated to Timeweb NS.
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
	TTL  int    `json:"ttl"`
	Data struct {
		Value     string `json:"value"`
		Subdomain string `json:"subdomain"`
	} `json:"data"`
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("timeweb: %s %s: %s: %s", method, path, resp.Status, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// findA returns the record ID of an existing A record for the subdomain, or 0.
func (t *Timeweb) findA(ctx context.Context, sub string) (int64, error) {
	offset := 0
	for {
		var page struct {
			Meta    struct{ Total int } `json:"meta"`
			Records []twRecord          `json:"dns_records"`
		}
		path := fmt.Sprintf("/api/v1/domains/%s/dns-records?limit=100&offset=%d", t.Zone, offset)
		if err := t.do(ctx, http.MethodGet, path, nil, &page); err != nil {
			return 0, err
		}
		for _, r := range page.Records {
			if r.Type == "A" && r.Data.Subdomain == sub {
				return r.ID, nil
			}
		}
		offset += len(page.Records)
		if len(page.Records) == 0 || offset >= page.Meta.Total {
			return 0, nil
		}
	}
}

func (t *Timeweb) EnsureA(ctx context.Context, fqdn, ip string) error {
	sub, err := t.subdomain(fqdn)
	if err != nil {
		return err
	}
	id, err := t.findA(ctx, sub)
	if err != nil {
		return err
	}
	body := map[string]any{"type": "A", "value": ip, "subdomain": sub, "ttl": 600}
	if id != 0 {
		return t.do(ctx, http.MethodPatch,
			fmt.Sprintf("/api/v1/domains/%s/dns-records/%d", t.Zone, id), body, nil)
	}
	return t.do(ctx, http.MethodPost,
		fmt.Sprintf("/api/v1/domains/%s/dns-records", t.Zone), body, nil)
}

func (t *Timeweb) DeleteA(ctx context.Context, fqdn string) error {
	sub, err := t.subdomain(fqdn)
	if err != nil {
		return err
	}
	id, err := t.findA(ctx, sub)
	if err != nil {
		return err
	}
	if id == 0 {
		return nil // already gone
	}
	return t.do(ctx, http.MethodDelete,
		fmt.Sprintf("/api/v1/domains/%s/dns-records/%d", t.Zone, id), nil, nil)
}
