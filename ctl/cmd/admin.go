package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Operator control plane (POST /admin/*)",
	Long: `Operator actions on the vault's admin control plane. When the server sets
DEZHAN_ADMIN_TOKEN, pass --admin-token (or set DEZHAN_ADMIN_TOKEN).`,
}

func adminAction(use, short, action string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, cancel := ctx()
			defer cancel()
			out, err := newClient().Admin(c, action, adminToken)
			if err != nil {
				return err
			}
			if out != "" {
				fmt.Println(out)
			} else {
				fmt.Println("ok")
			}
			return nil
		},
	}
}

func init() {
	adminCmd.AddCommand(
		adminAction("scrub", "Run an integrity scrub and self-heal", "scrub"),
		adminAction("gc", "Garbage-collect orphaned chunks and manifests", "gc"),
		adminAction("seal", "Seal the vault read-only (persists across restart)", "seal"),
		adminAction("checkpoint", "Write a signed audit-chain checkpoint", "checkpoint"),
		adminAction("tick", "Advance trusted time from the system clock", "tick"),
	)
	rootCmd.AddCommand(adminCmd)
}
