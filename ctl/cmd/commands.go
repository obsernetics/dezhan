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
		if jsonOut {
			return printJSON(map[string]any{"health": h, "ok": h == "ok"})
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
		if jsonOut {
			return printJSON(map[string]any{"version": v})
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
		if names == nil {
			names = []string{}
		}
		if jsonOut {
			return printJSON(names)
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	},
}

var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Print the vault metrics (raw Prometheus, or --json)",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, cancel := ctx()
		defer cancel()
		m, err := newClient().Metrics(c)
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(map[string]any{"version": m.Version, "values": m.Values})
		}
		fmt.Print(m.Raw)
		return nil
	},
}

var getOutput string

var getCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Fetch an object to stdout or a file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, cancel := ctx()
		defer cancel()
		b, err := newClient().Get(c, args[0])
		if err != nil {
			return err
		}
		if getOutput != "" && getOutput != "-" {
			if err := os.WriteFile(getOutput, b, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(b), getOutput)
			return nil
		}
		_, err = os.Stdout.Write(b)
		return err
	},
}

var (
	putMode   string
	putRetain int
	putFile   string
)

var putCmd = &cobra.Command{
	Use:   "put <name> [data]",
	Short: "Store an object under a retention (inline data or --file)",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, cancel := ctx()
		defer cancel()
		var data []byte
		switch {
		case putFile != "":
			b, err := os.ReadFile(putFile)
			if err != nil {
				return err
			}
			data = b
		case len(args) >= 2:
			data = []byte(args[1])
		default:
			return fmt.Errorf("provide <data> or --file")
		}
		out, err := newClient().Put(c, args[0], data, putMode, putRetain)
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
	getCmd.Flags().StringVarP(&getOutput, "output", "o", "", "write object to this file instead of stdout")
	putCmd.Flags().StringVar(&putMode, "mode", "compliance", "retention mode: compliance|governance")
	putCmd.Flags().IntVar(&putRetain, "retain", 3600, "retention window in seconds")
	putCmd.Flags().StringVarP(&putFile, "file", "f", "", "read object data from this file")
	delCmd.Flags().BoolVar(&delBypass, "bypass", false, "request a retention bypass (server may refuse)")

	dashboardCmd.Flags().DurationVar(&dashEvery, "refresh", 2*time.Second, "refresh interval")
	dashboardCmd.Flags().BoolVar(&dashOnce, "once", false, "print one plain snapshot and exit (no TUI)")
	dashboardCmd.Flags().BoolVar(&dashFrame, "frame", false, "print one styled dashboard frame and exit (no TUI)")

	rootCmd.AddCommand(healthCmd, versionCmd, lsCmd, metricsCmd, getCmd, putCmd, delCmd, dashboardCmd)
}
