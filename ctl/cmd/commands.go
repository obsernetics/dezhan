package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

func ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check the vault is live",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, cancel := ctx()
		defer cancel()
		h, err := newClient().Health(c)
		if err != nil {
			return err
		}
		fmt.Println(h)
		return nil
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the server version",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, cancel := ctx()
		defer cancel()
		v, err := newClient().Version(c)
		if err != nil {
			return err
		}
		fmt.Println(v)
		return nil
	},
}

var lsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List object names",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, cancel := ctx()
		defer cancel()
		names, err := newClient().List(c)
		if err != nil {
			return err
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	},
}

var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Print the raw Prometheus metrics",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, cancel := ctx()
		defer cancel()
		m, err := newClient().Metrics(c)
		if err != nil {
			return err
		}
		fmt.Print(m.Raw)
		return nil
	},
}

var getCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Fetch an object to stdout",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, cancel := ctx()
		defer cancel()
		b, err := newClient().Get(c, args[0])
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(b)
		return err
	},
}

var (
	putMode   string
	putRetain int
)

var putCmd = &cobra.Command{
	Use:   "put <name> <data>",
	Short: "Store an object under a retention",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, cancel := ctx()
		defer cancel()
		out, err := newClient().Put(c, args[0], []byte(args[1]), putMode, putRetain)
		if err != nil {
			return err
		}
		fmt.Println(out)
		return nil
	},
}

var delBypass bool

var delCmd = &cobra.Command{
	Use:   "del <name>",
	Short: "Delete an object (refused while retained)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, cancel := ctx()
		defer cancel()
		out, err := newClient().Delete(c, args[0], delBypass)
		if err != nil {
			return err
		}
		fmt.Println(out)
		return nil
	},
}

var (
	dashEvery time.Duration
	dashOnce  bool
	dashFrame bool
)

func init() {
	putCmd.Flags().StringVar(&putMode, "mode", "compliance", "retention mode: compliance|governance")
	putCmd.Flags().IntVar(&putRetain, "retain", 3600, "retention window in seconds")
	delCmd.Flags().BoolVar(&delBypass, "bypass", false, "request a retention bypass (server may refuse)")

	dashboardCmd.Flags().DurationVar(&dashEvery, "refresh", 2*time.Second, "refresh interval")
	dashboardCmd.Flags().BoolVar(&dashOnce, "once", false, "print one plain snapshot and exit (no TUI)")
	dashboardCmd.Flags().BoolVar(&dashFrame, "frame", false, "print one styled dashboard frame and exit (no TUI)")

	rootCmd.AddCommand(healthCmd, versionCmd, lsCmd, metricsCmd, getCmd, putCmd, delCmd, dashboardCmd)
}
