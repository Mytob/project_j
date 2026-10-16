package containerhealth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	origin string
	client *http.Client
}

func NewClient(origin string) *Client {
	return &Client{origin: strings.TrimRight(origin, "/"), client: &http.Client{Timeout: 2 * time.Second}}
}

func (c *Client) Snapshot(ctx context.Context) ([]Snapshot, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/containers", nil)
	if err != nil {
		return nil, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("private container health observer is unavailable")
	}
	var values []Snapshot
	if err := json.NewDecoder(response.Body).Decode(&values); err != nil {
		return nil, err
	}
	return values, nil
}
