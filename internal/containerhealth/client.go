package containerhealth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
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

// NewUnixClient talks to the host maintenance observer over its private Unix
// socket. The socket API is deliberately separate from the Docker API client.
func NewUnixClient(socketPath string) *Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socketPath)
	}}
	return &Client{origin: "http://maintenance", client: &http.Client{Transport: transport, Timeout: 4 * time.Second}}
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

func (c *Client) Inventory(ctx context.Context) (RuntimeInventory, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/inventory", nil)
	if err != nil {
		return RuntimeInventory{}, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return RuntimeInventory{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return RuntimeInventory{}, errors.New("private runtime inventory is unavailable")
	}
	var value RuntimeInventory
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	if err := decoder.Decode(&value); err != nil {
		return RuntimeInventory{}, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return RuntimeInventory{}, errors.New("private runtime inventory contains trailing data")
	}
	return value, nil
}
