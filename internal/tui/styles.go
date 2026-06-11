package tui

import "github.com/charmbracelet/lipgloss"

var (
	Brand   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0EA5E9"))
	Danger  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#EF4444"))
	Warning = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F59E0B"))
	Secure  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#10B981"))
	Muted   = lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8"))
	Text    = lipgloss.NewStyle().Foreground(lipgloss.Color("#F8FAFC"))
	Surface = lipgloss.NewStyle().Background(lipgloss.Color("#1E293B"))

	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#0EA5E9")).
			Background(lipgloss.Color("#1E293B")).
			Padding(0, 2)

	PhaseStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F8FAFC")).
			Background(lipgloss.Color("#1E293B")).
			Padding(0, 1)

	Separator = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#334155")).
			Render("──────────────────────────────────────────────────────")

	Logo = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#0EA5E9")).
		Render("☁  NIMBUS MAPPER")
)

func SeverityBadge(sev string) string {
	switch sev {
	case "CRITICAL":
		return Danger.Render("CRITICAL")
	case "HIGH":
		return Warning.Render("HIGH    ")
	case "MEDIUM":
		return Brand.Render("MEDIUM  ")
	case "LOW":
		return Muted.Render("LOW     ")
	default:
		return Muted.Render(sev)
	}
}
