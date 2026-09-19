package cmd

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/obsernetics/dezhan/ctl/internal/tui"
)

var dashboardCmd = &cobra.Command{
	Use:     "dashboard",
	Aliases: []string{"dash", "tui"},
	Short:   "Live vault dashboard (TUI)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if dashOnce {
			return snapshot()
		}
		if dashFrame {
			fmt.Println(tui.New(newClient(), endpoint, dashEvery).FetchOnce(0).View())
			return nil
		}
		p := tea.NewProgram(tui.New(newClient(), endpoint, dashEvery), tea.WithAltScreen())
		_, err := p.Run()
		return err
	},
}

// snapshot prints a single plain-text view, for scripts and no-TTY environments.
func snapshot() error {
	c, cancel := ctx()
	defer cancel()
	cl := newClient()
	h, err := cl.Health(c)
	if err != nil {
		return err
	}
	v, _ := cl.Version(c)
	m, err := cl.Metrics(c)
	if err != nil {
		return err
	}
	names, _ := cl.List(c)
	fmt.Printf("endpoint  %s\n", endpoint)
	fmt.Printf("health    %s\n", h)
	fmt.Printf("version   %s\n", v)
	fmt.Printf("sealed    %v\n", m.Get("dezhan_sealed") != 0)
	fmt.Printf("objects   %.0f\n", m.Get("dezhan_objects"))
	fmt.Printf("stored    %.0f bytes\n", m.Get("dezhan_storage_bytes"))
	fmt.Printf("audit     %.0f entries\n", m.Get("dezhan_audit_entries"))
	fmt.Printf("quarantd  %.0f\n", m.Get("dezhan_quarantined"))
	fmt.Printf("scrubs    %.0f (repaired %.0f shards)\n",
		m.Get("dezhan_scrub_runs"), m.Get("dezhan_scrub_shards_repaired"))
	fmt.Printf("listed    %d objects\n", len(names))
	return nil
}
