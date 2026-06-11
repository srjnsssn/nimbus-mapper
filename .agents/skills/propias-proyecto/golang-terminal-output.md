---
name: golang-terminal-output
description: >
  Rules for building the full CLI output layer of Nimbus Mapper: interactive TUI with real-time
  scanning progress, severity-coded findings tables, and seamless degradation to pipeline-safe
  plain output. Covers the Charmbracelet ecosystem, event-driven rendering, terminal detection,
  adaptive layout, and the --format flag system.
triggers:
  - "when building or modifying the CLI output layer"
  - "when rendering the findings table"
  - "when adding or modifying progress spinners or scan status"
  - "when implementing or changing --format / -o flags"
  - "when handling NO_COLOR, CI, or --quiet flags"
  - "when writing anything that prints to stdout or stderr"
  - "when a goroutine needs to report progress or a finding"
---

# Skill: golang-terminal-output

## Project Context

Nimbus Mapper is a multi-cloud security scanner. Scans can span dozens of regions and hundreds
of projects simultaneously. The terminal output layer must:
- Show real-time per-region/per-provider scan progress without blocking worker goroutines.
- Render a live findings table that updates as vulnerabilities are discovered.
- Produce completely clean, decoration-free output when piped to `jq`, `grep`, or CI systems.
- Never be the reason a scan slows down — rendering must be asynchronous.

---

## Architecture: The Golden Rule

**No worker goroutine ever writes to stdout directly.**

All goroutines (AWS extractor, GCP extractor, Azure extractor) communicate exclusively through
a typed `chan ScanEvent`. A single dedicated renderer goroutine consumes that channel and owns
all writes to the terminal. This eliminates race conditions and TUI buffer corruption entirely.

```
[aws-worker] ─┐
[gcp-worker] ──┤──► chan ScanEvent ──► Renderer goroutine ──► stdout
[az-worker]  ─┘
```

---

## Environment Detection (Do This First)

Before any rendering logic, detect the environment and set a global render mode:

```go
// internal/ui/env.go

package ui

import (
    "os"
    "github.com/mattn/go-isatty"
)

type RenderMode int

const (
    RenderModeTUI      RenderMode = iota // Full Bubbletea TUI
    RenderModePlain                       // Line-by-line, no ANSI
    RenderModeJSON                        // Pure JSON to stdout, no UI
    RenderModeCSV                         // Pure CSV to stdout, no UI
    RenderModeSARIF                       // SARIF JSON to stdout
)

func DetectRenderMode(formatFlag string, noColor bool) RenderMode {
    switch formatFlag {
    case "json":  return RenderModeJSON
    case "csv":   return RenderModeCSV
    case "sarif": return RenderModeSARIF
    }
    // Even if format=table, degrade to plain if not a real terminal
    isTTY := isatty.IsTerminal(os.Stdout.Fd())
    isDumb := os.Getenv("TERM") == "dumb"
    isCI   := os.Getenv("CI") != ""
    if !isTTY || isDumb || isCI || noColor {
        return RenderModePlain
    }
    return RenderModeTUI
}
```

**CRITICAL:** If `RenderMode` is JSON/CSV/SARIF, **never initialize Bubbletea**. Not even
partially. Its initialization alone writes escape sequences to stdout that corrupt pipe output.

---

## Event System

Define all possible events that workers can emit. The renderer reacts to these exclusively.

```go
// internal/ui/events.go

package ui

type EventKind int

const (
    EventScanStarted   EventKind = iota
    EventScanProgress            // worker reports N/Total for a region
    EventFindingFound            // a security finding was detected
    EventScanDone                // a region/project finished cleanly
    EventScanError               // a region/project failed (partial, not fatal)
    EventAllDone                 // entire scan finished, used to trigger final table
)

type ScanProgress struct {
    Current int
    Total   int
    Label   string // e.g. "EC2 instances", "Firewall rules"
}

type ScanEvent struct {
    Kind     EventKind
    Provider string       // "aws" | "gcp" | "azure"
    Region   string       // e.g. "us-east-1", "europe-west1"
    Project  string       // GCP project or AWS account ID
    Progress ScanProgress
    Finding  *Finding     // non-nil only for EventFindingFound
    Err      error        // non-nil only for EventScanError
}
```

Workers emit like this — nothing else:

```go
// Inside a worker goroutine:
eventCh <- ui.ScanEvent{
    Kind:     ui.EventScanProgress,
    Provider: "aws",
    Region:   "us-east-1",
    Progress: ui.ScanProgress{Current: 14, Total: 47, Label: "Security Groups"},
}

eventCh <- ui.ScanEvent{
    Kind:     ui.EventFindingFound,
    Provider: "aws",
    Region:   "us-east-1",
    Finding:  &ui.Finding{
        Severity:   ui.SeverityCritical,
        ResourceID: "sg-0a1b2c3d",
        Title:      "Security Group allows SSH from 0.0.0.0/0",
    },
}
```

---

## Library Stack

| Library | Version | Purpose |
|---|---|---|
| `github.com/charmbracelet/bubbletea` | latest | Main TUI event loop (Elm architecture) |
| `github.com/charmbracelet/lipgloss`  | latest | Declarative terminal styling |
| `github.com/charmbracelet/bubbles`   | latest | Spinner, table, progress, viewport components |
| `github.com/mattn/go-isatty`         | latest | TTY detection |
| `golang.org/x/term`                  | latest | Terminal width/height via `term.GetSize()` |
| `github.com/charmbracelet/log`       | latest | Structured logger that respects TUI (writes to stderr) |

All are in go.mod. Never add alternatives without updating this skill.

---

## Severity Design System (lipgloss)

This palette is canonical across all output modes (ANSI for TUI, plain text labels for plain mode).

```go
// internal/ui/styles.go

package ui

import "github.com/charmbracelet/lipgloss"

var (
    StyleCritical = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#EF4444"))
    StyleHigh     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F59E0B"))
    StyleMedium   = lipgloss.NewStyle().Foreground(lipgloss.Color("#0EA5E9"))
    StyleLow      = lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280"))
    StyleSafe     = lipgloss.NewStyle().Foreground(lipgloss.Color("#22C55E"))

    StyleProvider = lipgloss.NewStyle().Foreground(lipgloss.Color("#A78BFA")).Bold(true)
    StyleRegion   = lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8"))
    StyleHeader   = lipgloss.NewStyle().Bold(true).Underline(true)
    StyleMuted    = lipgloss.NewStyle().Foreground(lipgloss.Color("#64748B"))
    StyleBrand    = lipgloss.NewStyle().Foreground(lipgloss.Color("#0EA5E9")).Bold(true)
)

func RenderSeverityBadge(s Severity) string {
    switch s {
    case SeverityCritical: return StyleCritical.Render("CRITICAL")
    case SeverityHigh:     return StyleHigh.Render("HIGH    ")
    case SeverityMedium:   return StyleMedium.Render("MEDIUM  ")
    default:               return StyleLow.Render("LOW     ")
    }
}
```

---

## Bubbletea Model (TUI Mode)

The main model tracks per-region scan state and accumulated findings:

```go
// internal/ui/model.go

package ui

import (
    tea "github.com/charmbracelet/bubbletea"
    "github.com/charmbracelet/bubbles/spinner"
)

type regionState struct {
    provider string
    region   string
    progress ScanProgress
    done     bool
    err      error
}

type Model struct {
    eventCh  <-chan ScanEvent
    regions  map[string]*regionState // key: "provider/region"
    findings []Finding
    spinner  spinner.Model
    width    int
    done     bool
}

// tickCmd polls the event channel without blocking the TUI loop
func tickCmd(ch <-chan ScanEvent) tea.Cmd {
    return func() tea.Msg {
        return <-ch
    }
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    switch ev := msg.(type) {
    case ScanEvent:
        switch ev.Kind {
        case EventScanProgress:
            key := ev.Provider + "/" + ev.Region
            m.regions[key] = &regionState{
                provider: ev.Provider,
                region:   ev.Region,
                progress: ev.Progress,
            }
        case EventFindingFound:
            m.findings = append(m.findings, *ev.Finding)
        case EventScanDone:
            key := ev.Provider + "/" + ev.Region
            if r, ok := m.regions[key]; ok {
                r.done = true
            }
        case EventAllDone:
            m.done = true
            return m, tea.Quit
        }
        return m, tickCmd(m.eventCh) // keep polling
    case tea.WindowSizeMsg:
        m.width = ev.Width
    }
    var cmd tea.Cmd
    m.spinner, cmd = m.spinner.Update(msg)
    return m, cmd
}
```

---

## Adaptive Table Width

Never hardcode column widths. Calculate them from terminal size at render time:

```go
// internal/ui/table.go

func RenderFindingsTable(findings []Finding, termWidth int) string {
    if termWidth <= 0 {
        termWidth = 100 // safe fallback
    }
    // Fixed columns: severity(10) + provider(8) + resource(20) + borders/padding(8)
    fixedCols  := 46
    titleWidth := max(termWidth-fixedCols, 20)

    rows := make([][]string, len(findings))
    for i, f := range findings {
        rows[i] = []string{
            RenderSeverityBadge(f.Severity),
            StyleProvider.Render(f.Provider),
            truncate(f.ResourceID, 20),
            truncate(f.Title, titleWidth),
        }
    }
    // Use bubbles/table or go-pretty for rendering
    // ...
}

func truncate(s string, n int) string {
    if len(s) <= n {
        return s
    }
    return s[:n-1] + "…"
}
```

---

## Plain Mode Renderer (non-TTY / CI)

When `RenderModePlain` is active, emit one line per significant event to stdout:

```go
// internal/ui/plain.go

func RunPlainRenderer(ctx context.Context, events <-chan ScanEvent, w io.Writer) {
    for {
        select {
        case <-ctx.Done():
            return
        case ev, ok := <-events:
            if !ok { return }
            switch ev.Kind {
            case EventScanStarted:
                fmt.Fprintf(w, "[START]   %s/%s\n", ev.Provider, ev.Region)
            case EventFindingFound:
                fmt.Fprintf(w, "[FINDING] %-8s %s/%s %s: %s\n",
                    ev.Finding.Severity.String(),
                    ev.Provider, ev.Region,
                    ev.Finding.ResourceID,
                    ev.Finding.Title,
                )
            case EventScanDone:
                fmt.Fprintf(w, "[DONE]    %s/%s\n", ev.Provider, ev.Region)
            case EventScanError:
                fmt.Fprintf(w, "[ERROR]   %s/%s: %v\n", ev.Provider, ev.Region, ev.Err)
            }
        }
    }
}
```

---

## Output Formats (--format flag)

| Flag value | Behavior | Colors | Who reads it |
|---|---|---|---|
| `table` (default) | Bubbletea TUI or plain depending on TTY | Yes (if TTY) | Humans |
| `json` | Newline-delimited JSON findings to stdout | Never | `jq`, APIs, SIEM |
| `csv` | RFC 4180 CSV with header row | Never | Excel, Sheets |
| `sarif` | SARIF 2.1.0 JSON for GitHub Security | Never | GitHub Advanced Security, VS Code |
| `markdown` | Markdown table for Confluence/Notion/PRs | Never | Docs, PRs |

---

## Exit Codes

These are semantic and must be consistent. CI pipelines rely on them.

| Code | Meaning |
|---|---|
| `0` | Scan completed, zero findings |
| `1` | Scan completed, findings were detected |
| `2` | Configuration or credential error (scan did not run) |
| `3` | Partial scan: some providers/regions failed, results incomplete |

---

## Environment Variables (must respect)

| Variable | Behavior |
|---|---|
| `NO_COLOR=1` | Disable all ANSI output. `lipgloss` respects this automatically. |
| `TERM=dumb` | Degrade to plain text, no box-drawing chars, no spinners. |
| `CI=true` | Auto-activate plain mode + one-line-per-event output. |
| `NIMBUS_NO_TUI=1` | Nimbus-specific override to force plain mode. |

---

## Anti-Patterns — NEVER DO THIS

- **NEVER** call `fmt.Println` or `fmt.Printf` from a worker goroutine. Always emit a `ScanEvent`.
- **NEVER** initialize `tea.NewProgram(...)` if the format flag is `json`, `csv`, or `sarif`.
  Bubbletea writes escape sequences on init that corrupt stdout even if no `View()` is ever called.
- **NEVER** use `lipgloss.Render()` in non-TUI mode. Detect `RenderModePlain` and use plain strings.
- **NEVER** hardcode terminal width. Always use `term.GetSize()` with a fallback of `80`.
- **NEVER** mix `log.Print` (stdlib) with Bubbletea — it writes to stdout and corrupts the TUI buffer.
  Use `charmbracelet/log` or `log/slog` directed to `stderr` only.
- **NEVER** call `os.Exit()` inside a renderer. Return the exit code to `main()` and call it there.

---

## Integration with Other Skills

- **golang-structured-logging**: All `slog` output goes to `stderr` or a log file. Never to `stdout`.
- **golang-data-pipeline**: Workers emit `ScanEvent` via the channel. The pipeline owns data; the UI owns rendering.
- **golang-concurrency**: The `chan ScanEvent` is the boundary between concurrency and rendering. Keep it buffered (e.g., `make(chan ScanEvent, 512)`) to avoid blocking scanners on slow renders.
