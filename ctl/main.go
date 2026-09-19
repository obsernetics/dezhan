// Command dezhanctl is a control CLI and live TUI dashboard for a dezhan vault.
package main

import (
	"fmt"
	"os"

	"github.com/obsernetics/dezhan/ctl/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "dezhanctl:", err)
		os.Exit(1)
	}
}
