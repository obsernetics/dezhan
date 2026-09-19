package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// newTestClient spins up an httptest server whose handler is h and returns a
// Client pointed at it. The caller closes the returned server.
func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	return New(srv.URL), srv
}

func TestMetrics(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantVersion string
		wantValues  map[string]float64
	}{
		{
			name: "plain metric",
			body: "dezhan_objects 3\n",
			wantValues: map[string]float64{
				"dezhan_objects": 3,
			},
		},
		{
			name: "comments and blank lines skipped",
			body: "# HELP dezhan_objects number of objects\n" +
				"# TYPE dezhan_objects gauge\n" +
				"\n" +
				"dezhan_objects 7\n" +
				"\n",
			wantValues: map[string]float64{
				"dezhan_objects": 7,
			},
		},
		{
			name:        "build info label sets version",
			body:        "dezhan_build_info{version=\"1.3.0\"} 1\n",
			wantVersion: "1.3.0",
			wantValues: map[string]float64{
				"dezhan_build_info": 1,
			},
		},
		{
			name: "trailing tokens and timestamp parse first field",
			body: "dezhan_requests_total 42 1700000000000\n" +
				"dezhan_latency_seconds 0.5 extra tokens here\n",
			wantValues: map[string]float64{
				"dezhan_requests_total":  42,
				"dezhan_latency_seconds": 0.5,
			},
		},
		{
			name: "mixed document",
			body: "# a comment\n" +
				"dezhan_objects 3\n" +
				"dezhan_build_info{version=\"2.0.1\"} 1\n" +
				"\n" +
				"dezhan_bytes_stored 1024 1700000000000\n",
			wantVersion: "2.0.1",
			wantValues: map[string]float64{
				"dezhan_objects":      3,
				"dezhan_build_info":   1,
				"dezhan_bytes_stored": 1024,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/metrics" {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.body))
			})
			defer srv.Close()

			m, err := c.Metrics(context.Background())
			if err != nil {
				t.Fatalf("Metrics() error = %v", err)
			}
			if m.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", m.Version, tt.wantVersion)
			}
			if !reflect.DeepEqual(m.Values, tt.wantValues) {
				t.Errorf("Values = %v, want %v", m.Values, tt.wantValues)
			}
			// Metrics.Get mirrors the Values map.
			for name, want := range tt.wantValues {
				if got := m.Get(name); got != want {
					t.Errorf("Get(%q) = %v, want %v", name, got, want)
				}
			}
			// An absent metric reads as zero.
			if got := m.Get("does_not_exist"); got != 0 {
				t.Errorf("Get(absent) = %v, want 0", got)
			}
		})
	}
}

func TestList(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "sorted and blank lines trimmed",
			body: "gamma\n\nalpha\n  beta  \n\n",
			want: []string{"alpha", "beta", "gamma"},
		},
		{
			name: "already sorted",
			body: "a\nb\nc\n",
			want: []string{"a", "b", "c"},
		},
		{
			name: "empty body yields no names",
			body: "\n\n",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v" {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.body))
			})
			defer srv.Close()

			got, err := c.List(context.Background())
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("List() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHealth(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		want    string
		wantErr bool
	}{
		{
			name:   "ok trims body",
			status: http.StatusOK,
			body:   "  ok\n",
			want:   "ok",
		},
		{
			name:    "non-200 returns error",
			status:  http.StatusServiceUnavailable,
			body:    "down",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/healthz" {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			defer srv.Close()

			got, err := c.Health(context.Background())
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Health() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Health() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Health() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPut(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		retainSecs int
		wantRetain string
		status     int
		respBody   string
		want       string
	}{
		{
			name:       "compliance mode, 200",
			mode:       "compliance",
			retainSecs: 3600,
			wantRetain: "3600",
			status:     http.StatusOK,
			respBody:   "stored\n",
			want:       "stored",
		},
		{
			name:       "governance mode, 201",
			mode:       "governance",
			retainSecs: 86400,
			wantRetain: "86400",
			status:     http.StatusCreated,
			respBody:   "  created  ",
			want:       "created",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotMode, gotRetain, gotMethod string
			c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v/obj" {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				gotMethod = r.Method
				gotMode = r.Header.Get("X-Dezhan-Mode")
				gotRetain = r.Header.Get("X-Dezhan-Retain")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.respBody))
			})
			defer srv.Close()

			got, err := c.Put(context.Background(), "obj", []byte("payload"), tt.mode, tt.retainSecs)
			if err != nil {
				t.Fatalf("Put() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Put() = %q, want %q", got, tt.want)
			}
			if gotMethod != http.MethodPut {
				t.Errorf("method = %q, want PUT", gotMethod)
			}
			if gotMode != tt.mode {
				t.Errorf("X-Dezhan-Mode = %q, want %q", gotMode, tt.mode)
			}
			if gotRetain != tt.wantRetain {
				t.Errorf("X-Dezhan-Retain = %q, want %q", gotRetain, tt.wantRetain)
			}
		})
	}
}
