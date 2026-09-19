package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Stat issues a HEAD for /v/<name> and returns the response headers and status.
// It is the cheap "does it exist, and what is it" probe: Content-Length,
// Content-Type, and any X-Dezhan-* / x-amz-meta-* metadata the server attaches.
func (c *Client) Stat(ctx context.Context, name string) (http.Header, int, error) {
	resp, err := c.do(ctx, http.MethodHead, "/v/"+name, nil, nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return resp.Header, resp.StatusCode, fmt.Errorf("stat %s: not found", name)
	}
	if resp.StatusCode != http.StatusOK {
		return resp.Header, resp.StatusCode, fmt.Errorf("stat %s: HTTP %d", name, resp.StatusCode)
	}
	return resp.Header, resp.StatusCode, nil
}

// InterestingHeaders returns the subset of h worth showing for an object,
// lower-cased keys mapped to values, sorted-friendly.
func InterestingHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		lk := strings.ToLower(k)
		if lk == "content-length" || lk == "content-type" || lk == "etag" ||
			lk == "last-modified" || strings.HasPrefix(lk, "x-dezhan-") ||
			strings.HasPrefix(lk, "x-amz-meta-") || strings.HasPrefix(lk, "x-amz-version-id") {
			out[lk] = strings.Join(v, ", ")
		}
	}
	return out
}
