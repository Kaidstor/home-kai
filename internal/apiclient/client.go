// Package apiclient is the HTTP client for the coordinator API, shared by the
// agent and the admin CLI. The coordinator's self-signed TLS cert is
// authenticated by pinning its SHA-256 fingerprint (delivered inside the join
// command), not by the system CA store.
package apiclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kaidstor/home-kai/internal/api"
)

type Client struct {
	baseURL string
	bearer  string
	http    *http.Client
}

// New pins the coordinator cert when fingerprint is non-empty; an empty
// fingerprint disables TLS verification entirely (CLI convenience — callers
// should warn).
func New(baseURL, fingerprint, bearer string) (*Client, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	if fingerprint != "" {
		want, err := hex.DecodeString(fingerprint)
		if err != nil || len(want) != sha256.Size {
			return nil, fmt.Errorf("bad fingerprint %q: want 64 hex chars", fingerprint)
		}
		// Verification is replaced by the fingerprint pin.
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer certificate")
			}
			got := sha256.Sum256(rawCerts[0])
			if !bytes.Equal(got[:], want) {
				return fmt.Errorf("coordinator cert fingerprint mismatch: got %s", hex.EncodeToString(got[:]))
			}
			return nil
		}
	}
	return &Client{
		baseURL: baseURL,
		bearer:  bearer,
		http: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			// Above the coordinator's 55s long-poll hold.
			Timeout: 70 * time.Second,
		},
	}, nil
}

func (c *Client) SetBearer(b string) { c.bearer = b }

// Do issues one authenticated JSON request.
func (c *Client) Do(ctx context.Context, method, path string, in, out any) (int, error) {
	var rd io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.bearer)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return resp.StatusCode, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e api.ErrorResponse
		if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Error != "" {
			return resp.StatusCode, fmt.Errorf("%s %s: %s", method, path, e.Error)
		}
		return resp.StatusCode, fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out != nil {
		return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}
