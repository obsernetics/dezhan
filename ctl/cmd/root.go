// Package cmd wires the dezhanctl command tree (Cobra) and the dashboard.
package cmd

import (
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/obsernetics/dezhan/ctl/internal/client"
)

var (
	endpoint string
	timeout  time.Duration
)

func defaultEndpoint() string {
	if e := os.Getenv("DEZHAN_ENDPOINT"); e != "" {
		return e
	}
	return "http://127.0.0.1:8080"
}

func newClient() *client.Client { return client.New(endpoint) }

var rootCmd = &cobra.Command{
	Use:   "dezhanctl",
	Short: "Control CLI and live dashboard for a dezhan vault",
	Long: `dezhanctl talks to a dezhan server over its plain HTTP control plane
(/healthz, /version, /metrics, /v). Run "dezhanctl dashboard" for a live TUI, or
use the subcommands to script health checks, listings and object operations.`,
	SilenceUsage: true,
}

// Execute runs the command tree.
func Execute() error { return rootCmd.Execute() }

func init() {
	rootCmd.PersistentFlags().StringVarP(&endpoint, "endpoint", "e", defaultEndpoint(),
		"dezhan server endpoint (or set DEZHAN_ENDPOINT)")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 10*time.Second, "request timeout")
}
