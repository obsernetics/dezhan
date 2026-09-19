// Package tui renders a live dezhan vault dashboard with Bubble Tea.
package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/obsernetics/dezhan/ctl/internal/client"
)

type snapshotMsg struct {
	health  string
	version string
	metrics *client.Metrics
	objects []string
	err     error
	at      time.Time
}

type tickMsg time.Time

// Model is the dashboard state.
type Model struct {
	cli      *client.Client
	endpoint string
	every    time.Duration

	snap   snapshotMsg
	loaded bool
	width  int
	height int
}

// New builds a dashboard model.
func New(cli *client.Client, endpoint string, every time.Duration) Model {
	if every < time.Second {
		every = time.Second
	}
	return Model{cli: cli, endpoint: endpoint, every: every}
}

// Init starts the first fetch and the refresh ticker.
func (m Model) Init() tea.Cmd {
	return tea.Batch(m.fetch(), tick(m.every))
}

// FetchOnce fetches a single snapshot synchronously and returns a loaded model,
// so callers can render one static frame with View() without starting the TUI.
func (m Model) FetchOnce(width int) Model {
	if msg, ok := m.fetch()().(snapshotMsg); ok {
		m.snap = msg
		m.loaded = true
	}
	if width > 0 {
		m.width = width
	}
	return m
}

func (m Model) fetch() tea.Cmd {
	cli := m.cli
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		s := snapshotMsg{at: time.Now()}
		s.health, _ = cli.Health(ctx)
		s.version, _ = cli.Version(ctx)
		if mm, err := cli.Metrics(ctx); err != nil {
			s.err = err
		} else {
			s.metrics = mm
		}
		s.objects, _ = cli.List(ctx)
		return s
	}
}

func tick(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Update handles input, ticks and fetch results.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "r":
			return m, m.fetch()
		}
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tickMsg:
		return m, tea.Batch(m.fetch(), tick(m.every))
	case snapshotMsg:
		m.snap = msg
		m.loaded = true
	}
	return m, nil
}

var (
	cBlue   = lipgloss.Color("39")
	cGreen  = lipgloss.Color("42")
	cRed    = lipgloss.Color("196")
	cAmber  = lipgloss.Color("214")
	cGray   = lipgloss.Color("245")
	cFaint  = lipgloss.Color("240")

	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).
			Background(cBlue).Padding(0, 1)
	panelStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).
			BorderForeground(cFaint).Padding(0, 1)
	labelStyle = lipgloss.NewStyle().Foreground(cGray)
	valueStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231"))
	footStyle  = lipgloss.NewStyle().Foreground(cFaint)
)

// View renders the dashboard.
func (m Model) View() string {
	if !m.loaded {
		return "\n  connecting to " + m.endpoint + " ...\n"
	}
	s := m.snap
	var b strings.Builder

	title := titleStyle.Render(" dezhan vault ")
	sub := labelStyle.Render("  " + m.endpoint)
	if s.version != "" {
		sub += labelStyle.Render("  " + s.version)
	}
	b.WriteString(title + sub + "\n\n")

	// status line
	health := badge(s.health == "ok", strings.ToUpper(nz(s.health, "down")))
	b.WriteString("  " + health)
	if s.metrics != nil {
		sealed := s.metrics.Get("dezhan_sealed") != 0
		b.WriteString("   " + kv("sealed", boolBadge(sealed, sealed)))
		if s.metrics.Get("dezhan_ingest_only") != 0 {
			b.WriteString("   " + badge(false, "INGEST-ONLY"))
		}
		if s.metrics.Get("dezhan_sync_window_open") != 0 {
			b.WriteString("   " + badge(true, "SYNC-WINDOW OPEN"))
		}
	}
	b.WriteString("\n\n")

	// stat cards
	if s.metrics != nil {
		mm := s.metrics
		cards := []string{
			stat("objects", fmt.Sprintf("%.0f", mm.Get("dezhan_objects"))),
			stat("stored", human(mm.Get("dezhan_storage_bytes"))),
			stat("audit entries", fmt.Sprintf("%.0f", mm.Get("dezhan_audit_entries"))),
			stat("quarantined", warnNum(mm.Get("dezhan_quarantined"))),
			stat("retention denied", fmt.Sprintf("%.0f", mm.Get("dezhan_retention_denied_total"))),
			stat("scrub runs", fmt.Sprintf("%.0f", mm.Get("dezhan_scrub_runs"))),
			stat("shards repaired", fmt.Sprintf("%.0f", mm.Get("dezhan_scrub_shards_repaired"))),
			stat("trusted time", fmt.Sprintf("%.0fs", mm.Get("dezhan_trusted_time"))),
		}
		// four per row
		for i := 0; i < len(cards); i += 4 {
			end := i + 4
			if end > len(cards) {
				end = len(cards)
			}
			b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, cards[i:end]...) + "\n")
		}
	}
	b.WriteString("\n")

	// objects
	objTitle := labelStyle.Render(fmt.Sprintf("objects (%d)", len(s.objects)))
	var lines []string
	max := 12
	for i, o := range s.objects {
		if i >= max {
			lines = append(lines, footStyle.Render(fmt.Sprintf("... and %d more", len(s.objects)-max)))
			break
		}
		lines = append(lines, "• "+o)
	}
	if len(lines) == 0 {
		lines = append(lines, footStyle.Render("(none)"))
	}
	b.WriteString(objTitle + "\n" + panelStyle.Render(strings.Join(lines, "\n")) + "\n\n")

	if s.err != nil {
		b.WriteString(lipgloss.NewStyle().Foreground(cRed).Render("  "+s.err.Error()) + "\n")
	}
	b.WriteString(footStyle.Render(fmt.Sprintf("  updated %s · refresh %s · [r] refresh  [q] quit",
		s.at.Format("15:04:05"), m.every)))
	return b.String()
}

func stat(label, value string) string {
	body := valueStyle.Render(value) + "\n" + labelStyle.Render(label)
	return panelStyle.Width(20).Render(body)
}

func kv(label, value string) string {
	return labelStyle.Render(label+" ") + value
}

func badge(ok bool, text string) string {
	c := cGreen
	if !ok {
		c = cRed
	}
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(c).Padding(0, 1).Render(text)
}

func boolBadge(danger, state bool) string {
	txt := "no"
	if state {
		txt = "yes"
	}
	c := cGreen
	if danger {
		c = cAmber
	}
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("16")).Background(c).Padding(0, 1).Render(txt)
}

func warnNum(v float64) string {
	s := fmt.Sprintf("%.0f", v)
	if v > 0 {
		return lipgloss.NewStyle().Foreground(cRed).Bold(true).Render(s)
	}
	return s
}

func nz(s, dflt string) string {
	if strings.TrimSpace(s) == "" {
		return dflt
	}
	return s
}

func human(bytes float64) string {
	const unit = 1024.0
	if bytes < unit {
		return fmt.Sprintf("%.0f B", bytes)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	v := bytes / unit
	i := 0
	for v >= unit && i < len(units)-1 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}
