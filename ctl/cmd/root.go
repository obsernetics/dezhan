// Package cmd wires the dezhanctl command tree (Cobra) and the dashboard.
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/obsernetics/dezhan/ctl/internal/client"
)

var (
	endpoint   string
	timeout    time.Duration
	adminToken string
	jsonOut    bool
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
	rootCmd.PersistentFlags().StringVar(&adminToken, "admin-token", os.Getenv("DEZHAN_ADMIN_TOKEN"),
		"admin token for /admin/* actions (or set DEZHAN_ADMIN_TOKEN)")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "machine-readable JSON output")
}

// printJSON writes v as indented JSON to stdout.
func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
