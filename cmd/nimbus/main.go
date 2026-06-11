package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/charmbracelet/bubbletea"
	"github.com/yourusername/nimbus/internal/generator"
	"github.com/yourusername/nimbus/internal/mock"
	"github.com/yourusername/nimbus/internal/models"
	"github.com/yourusername/nimbus/internal/tui"
)

func countBySeverity(findings []models.Finding, sev models.Severity) int {
	n := 0
	for _, f := range findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

func main() {
	demo := flag.Bool("demo", false, "run demo mode with simulated cloud scan")
	flag.Parse()

	if !*demo {
		flag.Usage()
		os.Exit(0)
	}

	eventCh := make(chan tui.DemoEvent, 64)
	go tui.RunDemo(eventCh)

	p := tea.NewProgram(
		tui.NewModel(eventCh),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	if _, err := p.Run(); err != nil {
		log.Fatalf("TUI error: %v", err)
	}

	fmt.Println()

	graph := mock.DemoGraph()
	if err := generator.ExportGraph(graph, "nimbus_map.html"); err != nil {
		log.Fatalf("HTML export error: %v", err)
	}

	fmt.Println("✅  Scan complete. Graph generated at: ./nimbus_map.html")
	fmt.Printf("🔍  Findings: %d CRITICAL  %d HIGH  %d MEDIUM  %d LOW\n",
		countBySeverity(graph.Findings, "CRITICAL"),
		countBySeverity(graph.Findings, "HIGH"),
		countBySeverity(graph.Findings, "MEDIUM"),
		countBySeverity(graph.Findings, "LOW"))
	fmt.Println()
}
