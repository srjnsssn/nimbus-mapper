package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type logLine struct {
	text      string
	isFinding bool
	severity  string
}

type Model struct {
	eventCh chan DemoEvent
	logs    []logLine
	spinner spinner.Model
	phase   string
	done    bool
	counts  map[string]int
	width   int
}

type DemoEvent struct {
	Line     string
	Phase    string
	Finding  bool
	Severity string
	Done     bool
}

func NewModel(eventCh chan DemoEvent) Model {
	s := spinner.New()
	s.Style = Brand
	s.Spinner = spinner.Dot
	return Model{
		eventCh: eventCh,
		spinner: s,
		phase:   "Initializing...",
		counts:  map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
		width:   80,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, waitForEvent(m.eventCh))
}

func waitForEvent(ch chan DemoEvent) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return DemoEvent{Done: true}
		}
		return msg
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case DemoEvent:
		if msg.Phase != "" {
			m.phase = msg.Phase
		}
		if msg.Line != "" {
			m.logs = append(m.logs, logLine{
				text:      msg.Line,
				isFinding: msg.Finding,
				severity:  msg.Severity,
			})
		}
		if msg.Finding {
			m.counts[msg.Severity]++
		}
		if msg.Done {
			m.done = true
			return m, tea.Quit
		}
		return m, waitForEvent(m.eventCh)

	case tea.WindowSizeMsg:
		m.width = msg.Width

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m Model) View() string {
	var b strings.Builder

	b.WriteString("  ")
	b.WriteString(Logo)
	b.WriteString(Muted.Render("  v0.1-alpha"))
	b.WriteString("\n\n")
	b.WriteString("  " + Separator + "\n\n")

	if !m.done {
		b.WriteString("  ")
		b.WriteString(m.spinner.View())
		b.WriteString("  ")
		b.WriteString(PhaseStyle.Render(m.phase))
		b.WriteString("\n\n")
	}

	start := 0
	if len(m.logs) > 10 {
		start = len(m.logs) - 10
	}
	for _, l := range m.logs[start:] {
		if l.isFinding {
			badge := SeverityBadge(l.severity)
			icon := Danger.Render("⚠")
			b.WriteString(fmt.Sprintf("  %s  %s  %s\n", icon, badge, Text.Render(l.text)))
		} else {
			b.WriteString(fmt.Sprintf("    %s\n", Muted.Render(l.text)))
		}
	}

	b.WriteString("\n  " + Separator + "\n")
	m.renderCounts(&b)
	b.WriteString("\n")
	b.WriteString(Muted.Render("  Ctrl+C to exit"))

	return lipgloss.NewStyle().
		Background(lipgloss.Color("#0F172A")).
		Padding(1, 2).
		Width(m.width).
		Render(b.String())
}

func (m Model) renderCounts(b *strings.Builder) {
	total := 0
	for _, v := range m.counts {
		total += v
	}
	b.WriteString(fmt.Sprintf("  Findings:  "))
	if m.counts["CRITICAL"] > 0 {
		b.WriteString(Danger.Render(fmt.Sprintf("%d CRITICAL", m.counts["CRITICAL"])))
		b.WriteString("  ")
	}
	if m.counts["HIGH"] > 0 {
		b.WriteString(Warning.Render(fmt.Sprintf("%d HIGH", m.counts["HIGH"])))
		b.WriteString("  ")
	}
	if m.counts["MEDIUM"] > 0 {
		b.WriteString(Brand.Render(fmt.Sprintf("%d MEDIUM", m.counts["MEDIUM"])))
		b.WriteString("  ")
	}
	if total == 0 {
		b.WriteString(Secure.Render("0 — All clear"))
	}
}
