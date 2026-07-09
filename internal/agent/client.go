package agent

import (
	"context"
	"fmt"
	"net/http"

	"github.com/kaidstor/home-kai/internal/api"
	"github.com/kaidstor/home-kai/internal/apiclient"
)

// Client wraps the shared coordinator HTTP client with the agent-side calls
// (enroll, netmap long-poll, status heartbeat, rekey).
type Client struct {
	*apiclient.Client
}

func NewClient(baseURL, fingerprint, bearer string) (*Client, error) {
	c, err := apiclient.New(baseURL, fingerprint, bearer)
	if err != nil {
		return nil, err
	}
	return &Client{Client: c}, nil
}

func (c *Client) Enroll(ctx context.Context, req api.EnrollRequest) (api.EnrollResponse, error) {
	var out api.EnrollResponse
	_, err := c.Do(ctx, http.MethodPost, "/v1/enroll", req, &out)
	return out, err
}

// Netmap long-polls; (nil, nil) means "no change" (304 within the hold time).
func (c *Client) Netmap(ctx context.Context, since int64) (*api.Netmap, error) {
	var nm api.Netmap
	code, err := c.Do(ctx, http.MethodGet, fmt.Sprintf("/v1/netmap?since=%d", since), nil, &nm)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotModified {
		return nil, nil
	}
	return &nm, nil
}

func (c *Client) ReportStatus(ctx context.Context, rep api.StatusReport) error {
	_, err := c.Do(ctx, http.MethodPost, "/v1/status", rep, nil)
	return err
}

func (c *Client) Rekey(ctx context.Context, pubKey string) error {
	_, err := c.Do(ctx, http.MethodPost, "/v1/rekey", api.RekeyRequest{WGPublicKey: pubKey}, nil)
	return err
}
