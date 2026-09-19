// Package client is a small HTTP client for the dezhan server's control,
// metrics and object endpoints. It has no AWS/S3 dependency: it speaks the
// plain /healthz, /version, /metrics and /v routes, so it works against a local
// or air-gapped vault with anonymous access (the server's default). When the
// vault requires auth, run the commands against an endpoint reachable with the
// operator's network policy; SigV4 signing is a planned addition.
package client

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Client talks to one dezhan server.
type Client struct {
	Endpoint string
	HTTP     *http.Client
}

// New returns a client for endpoint (e.g. http://127.0.0.1:8080).
func New(endpoint string) *Client {
	return &Client{
		Endpoint: strings.TrimRight(endpoint, "/"),
		HTTP:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) do(ctx context.Context, method, path string, headers map[string]string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.Endpoint+path, body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.HTTP.Do(req)
}

func (c *Client) text(ctx context.Context, method, path string, headers map[string]string, body io.Reader) (string, int, error) {
	resp, err := c.do(ctx, method, path, headers, body)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(b), resp.StatusCode, nil
}

// Health returns the /healthz body ("ok" when live).
func (c *Client) Health(ctx context.Context) (string, error) {
	body, code, err := c.text(ctx, http.MethodGet, "/healthz", nil, nil)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("healthz: HTTP %d", code)
	}
	return strings.TrimSpace(body), nil
}

// Version returns the /version string.
func (c *Client) Version(ctx context.Context) (string, error) {
	body, code, err := c.text(ctx, http.MethodGet, "/version", nil, nil)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("version: HTTP %d", code)
	}
	return strings.TrimSpace(body), nil
}

// List returns the object names in the flat /v namespace.
func (c *Client) List(ctx context.Context) ([]string, error) {
	body, code, err := c.text(ctx, http.MethodGet, "/v", nil, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("list: HTTP %d", code)
	}
	var names []string
	for _, line := range strings.Split(body, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			names = append(names, s)
		}
	}
	sort.Strings(names)
	return names, nil
}

// Get retrieves an object's bytes from /v/<name>.
func (c *Client) Get(ctx context.Context, name string) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v/"+name, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get %s: HTTP %d: %s", name, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, nil
}

// Put stores data at /v/<name> under a retention mode (compliance|governance)
// and a retention window in seconds.
func (c *Client) Put(ctx context.Context, name string, data []byte, mode string, retainSecs int) (string, error) {
	h := map[string]string{
		"X-Dezhan-Mode":   mode,
		"X-Dezhan-Retain": strconv.Itoa(retainSecs),
		"Content-Type":    "application/octet-stream",
	}
	body, code, err := c.text(ctx, http.MethodPut, "/v/"+name, h, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	if code != http.StatusOK && code != http.StatusCreated {
		return "", fmt.Errorf("put %s: HTTP %d: %s", name, code, strings.TrimSpace(body))
	}
	return strings.TrimSpace(body), nil
}

// Delete removes /v/<name>. It succeeds only if retention allows (or bypass is
// permitted by the server); a retained object returns an error.
func (c *Client) Delete(ctx context.Context, name string, bypass bool) (string, error) {
	h := map[string]string{}
	if bypass {
		h["X-Dezhan-Bypass"] = "1"
	}
	body, code, err := c.text(ctx, http.MethodDelete, "/v/"+name, h, nil)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("delete %s: HTTP %d: %s", name, code, strings.TrimSpace(body))
	}
	return strings.TrimSpace(body), nil
}

// Admin POSTs to an /admin/<action> control endpoint. When token is non-empty
// it is sent as X-Dezhan-Admin-Token (required when the server sets
// DEZHAN_ADMIN_TOKEN). action is the bare name, e.g. "scrub" or "seal".
func (c *Client) Admin(ctx context.Context, action, token string) (string, error) {
	h := map[string]string{}
	if token != "" {
		h["X-Dezhan-Admin-Token"] = token
	}
	body, code, err := c.text(ctx, http.MethodPost, "/admin/"+action, h, nil)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("admin %s: HTTP %d: %s", action, code, strings.TrimSpace(body))
	}
	return strings.TrimSpace(body), nil
}

// Metrics is a parsed snapshot of /metrics.
type Metrics struct {
	Values  map[string]float64
	Version string
	Raw     string
}

// Metrics fetches and parses the Prometheus /metrics endpoint.
func (c *Client) Metrics(ctx context.Context) (*Metrics, error) {
	body, code, err := c.text(ctx, http.MethodGet, "/metrics", nil, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("metrics: HTTP %d", code)
	}
	m := &Metrics{Values: map[string]float64{}, Raw: body}
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, rest, ok := cut(line, " ")
		if !ok {
			continue
		}
		if base, labels, hasLabels := cut(name, "{"); hasLabels {
			if base == "dezhan_build_info" {
				m.Version = labelValue(strings.TrimSuffix(labels, "}"), "version")
			}
			name = base
		}
		if v, err := strconv.ParseFloat(strings.Fields(rest)[0], 64); err == nil {
			m.Values[name] = v
		}
	}
	return m, sc.Err()
}

// Get returns a metric value (0 if absent).
func (m *Metrics) Get(name string) float64 { return m.Values[name] }

func cut(s, sep string) (before, after string, found bool) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

func labelValue(labels, key string) string {
	for _, kv := range strings.Split(labels, ",") {
		k, v, ok := cut(kv, "=")
		if ok && strings.TrimSpace(k) == key {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}
