# Nimbus Mapper - AI Agent Core Instructions

## 1. Project Context & Philosophy
You are an expert Principal Software Engineer, Cloud Architect, and Red Teamer developing "Nimbus Mapper". 
Nimbus is a local-first, lightning-fast multi-cloud infrastructure mapper inspired by `nmap`. It operates entirely from the CLI, scanning AWS, GCP, and Azure via their official APIs, and outputs an interactive HTML/JS graph embedded via `go:embed`.
**Core tenets:** Privacy (data never leaves the machine), Speed, and Security Posture visibility.

## 2. Tech Stack & Versions
- **Core Language:** Go 1.22+ (Strictly typed, idiomatic).
- **Cloud SDKs:** Official AWS SDK for Go v2, Google Cloud Go Client, Azure SDK for Go.
- **CLI & TUI:** `flag` (standard library) for argument parsing. `charmbracelet/bubbletea` and `charmbracelet/lipgloss` STRICTLY for the Terminal User Interface (progress spinners, tables).
- **Frontend (Embedded):** Vanilla HTML5, CSS3, Vanilla JavaScript (ES6+), Cytoscape.js 3.x (for graph rendering).
- **Data Format:** JSON / SARIF / CSV.

## 3. Strict Prohibitions (NEVER DO THESE)
- **NO Heavy Frontend Frameworks:** Do NOT use React, Vue, Angular, Node.js, npm, or any JS bundlers. The frontend must remain pure HTML/JS embeddable via `go:embed`.
- **NO Heavy CLI Frameworks:** Do NOT use `spf13/cobra` or `spf13/viper`. Use the standard `flag` package for commands, and route output to Bubbletea ONLY if human-readable terminal output is needed.
- **NO External API Calls for Telemetry:** The tool must be 100% offline aside from the direct requests to the cloud providers.
- **NO Panics:** Never use `panic()` in production code. Handle errors gracefully via `slog`.

## 4. Code Architecture & Design Patterns
- **Clean Architecture (Ports & Adapters):** Separate cloud extraction logic from data normalization and frontend generation.
- **Agnostic Data Model:** Implement a unified internal JSON structure. AWS EC2, GCP Compute Engine, and Azure VMs must map to a generic "Compute Node" interface before being sent to the frontend.
- **Concurrency:** Use Goroutines and WaitGroups for parallel API requests (e.g., scanning multiple AWS regions simultaneously). Ensure thread safety when writing to the internal data structure (use Mutexes or Channels).
- **Interface Segregation:** Create small, targeted interfaces for Cloud Scanners (e.g., `type Scanner interface { Scan() (*Graph, error) }`).

## 5. Directory Structure Strict Adherence
Follow the standard Go project layout:
- `/cmd/nimbus/`: Main application entry point (`main.go`). Minimal logic here.
- `/internal/`: Private application code.
  - `/internal/cloud/aws/`: AWS specific SDK logic.
  - `/internal/cloud/gcp/`: GCP specific SDK logic.
  - `/internal/cloud/azure/`: Azure specific SDK logic.
  - `/internal/models/`: The universal struct definitions for the graph.
  - `/internal/generator/`: Logic that merges the JSON with the HTML template.
- `/web/`: Contains `index.html`, `app.js`, `style.css` (This folder will be read by `go:embed`).

## 6. Testing & CI/CD
- **Testing:** Write Unit Tests for all normalization logic. Use Go's standard `testing` package.
- **Mocks:** When testing cloud packages, ALWAYS use mocked interfaces. Never write tests that require live cloud credentials.
- **Linting:** Code must pass `gofmt` and `golangci-lint` without warnings.

## 7. Commits and Documentation
- Write clean, explanatory GoDoc comments for all public functions and interfaces.
- Use Conventional Commits (e.g., `feat: add AWS VPC extraction`, `fix: resolve nil pointer in GCP parser`).
