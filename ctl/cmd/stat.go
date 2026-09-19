package cmd

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/obsernetics/dezhan/ctl/internal/client"
)

var statCmd = &cobra.Command{
	Use:   "stat <name>",
	Short: "Show an object's metadata (HEAD)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, cancel := ctx()
		defer cancel()
		h, code, err := newClient().Stat(c, args[0])
		if err != nil {
			return err
		}
		meta := client.InterestingHeaders(h)
		if jsonOut {
			return printJSON(map[string]any{"name": args[0], "status": code, "headers": meta})
		}
		fmt.Printf("name    %s\n", args[0])
		fmt.Printf("status  %d\n", code)
		keys := make([]string, 0, len(meta))
		for k := range meta {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("%-18s %s\n", k, meta[k])
		}
		return nil
	},
}

func init() { rootCmd.AddCommand(statCmd) }
