<p align="center">
  <img src="https://img.shields.io/badge/status-alpha-orange" alt="Status">
  <img src="https://img.shields.io/badge/go-1.24%2B-00ADD8?logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/privacy-first-10B981" alt="Privacy First">
</p>

<h1 align="center">☁ Nimbus Mapper v0.1-alpha</h1>
<p align="center"><em>Local-first, multi-cloud topology mapper & Red Team auditing tool — the <code>nmap</code> of cloud infrastructure.</em></p>
<p align="center"><sub>☁ <em>Nimbus</em> — Latin for "rain cloud." Proudly developed in <strong>Latam</strong>.</sub></p>

---

## The Vision

Every engineer inherits undocumented infrastructure. A new contract, an acquisition, a forgotten account — and you're staring at a cloud console with 47 regions, 2,000 resources, and zero visibility into what's exposed to the internet.

Existing solutions force you to upload your entire cloud configuration to third-party SaaS platforms. You grant them read-access (and often more) to your production environments, hoping their data centers don't get breached.

**Nimbus inverts this model entirely.**

It is a single-binary CLI tool that runs **100% offline**. It authenticates transparently through your terminal's existing cloud credentials, scans AWS, GCP, and Azure via their official SDKs, and generates a **self-contained, interactive HTML graph** — all without your data ever leaving your machine.

> **Privacy is not a feature. It is the architecture.**

---

## Application to OpenAI Codex for Open Source

### Why this project needs Codex

Nimbus is built by a **Systems Engineer and AI Platform Engineer** currently training in **offensive security (Red Teaming)**. This dual background drives a unique design philosophy: the tool must be as unforgiving as an adversary would be, surfacing every exposure, every misconfiguration, every blast radius — while remaining surgical and precise.

This v0.1-alpha Proof of Concept is the result of an advanced **Spec-Driven Development (SDD)** methodology orchestrated entirely through AI agents. Every line of Go, every CSS selector in the embedded Cytoscape graph, and every Bubbletea TUI component was generated autonomously from formal specifications (`spec.md`, `design.md`, `AGENTS.md`).

The project repository contains a dedicated `.agents/skills/` directory — a structured set of reusable, domain-specific prompts covering **Go concurrency patterns, error handling idioms, CLI flag design, security best practices, and performance optimization**. These skills act as the "operating system" for an AI agent workforce that writes, refactors, and audits the codebase.

### What Codex unlocks for v1.0

The v1.0 milestone requires implementing complex, multi-cloud API extraction engines for **AWS (EC2, S3, RDS, Lambda, VPCs, Security Groups, IAM), GCP (Compute Engine, Cloud SQL, GCS, VPCs), and Azure (VMs, SQL Database, VNets, NSGs)** — each with their own pagination, rate-limiting, and permission models.

With Codex access, our autonomous agents will be able to:

- **Generate idiomatic, production-ready SDK callers** for all three cloud providers, correctly handling pagination, throttling, and credential chain discovery — without requiring the developer to manually study each SDK's quirks.
- **Synthesize realistic integration tests** with mocked cloud responses, ensuring every edge case (rate limits, access denied, resource not found) is handled gracefully without panics.
- **Evolve the `.agents/skills/` knowledge base** from the output of Codex-generated code — creating a flywheel where each completed feature makes future features faster to build.

We believe Nimbus is the perfect case study to demonstrate that **AI agents, armed with Codex, can build enterprise-grade cybersecurity tooling** — not toy examples, but real, offensive-security-grade software that Cloudflare, Datadog, and Snowflake engineers would trust with their production infrastructure.

---

## Key Features

- **🔍 Multi-Cloud Discovery** — Scan AWS, GCP, and Azure through one unified CLI (v1.0 target; v0.1 PoC simulates all three with realistic mock data).
- **🎭 Bubbletea TUI** — Real-time progress spinners and status tables during scans. Beautiful terminal output powered by Charmbracelet.
- **🕸 Interactive Graph (Offline)** — Generated HTML embeds Cytoscape.js with zero external dependencies. Click any resource to inspect its metadata, security findings, and exposure level. Works without a web server.
- **🏗 Agnostic Data Model** — EC2 instances, GCE VMs, and Azure VMs all normalize to a single "Compute Node" type. The frontend never needs to know which cloud provider you scanned.
- **🚫 Privacy by Architecture** — No telemetry, no analytics, no external API calls except to the cloud providers themselves. Your infrastructure data stays on your laptop.
- **🎯 Red Team Ready** — Exposure-aware node coloring (Critical / Warning / Safe), severity-filtered views, and search-by-resource-name baked into the graph UI.

---

## Quick Start (PoC)

```bash
# Clone the repository
git clone https://github.com/yourusername/nimbus.git
cd nimbus

# Run the demo mode — simulates a full multi-cloud scan
# with realistic network topology and security findings
go run ./cmd/nimbus/ --demo
```

The Bubbletea TUI will display a progress sequence simulating resource discovery across AWS, GCP, and Azure. Upon completion, `nimbus_map.html` is written to the current directory. Open it in your browser:

```bash
open nimbus_map.html   # macOS
xdg-open nimbus_map.html  # Linux
```

---

## Architecture & Tech Stack

```
┌────────────────────────────────────────────────────────────┐
│                    cmd/nimbus/main.go                      │
│           (CLI entry point — flag parsing, orchestration)  │
└──────────┬─────────────────────────────────────┬───────────┘
           │                                     │
     ┌─────▼──────┐                      ┌──────▼──────────┐
     │  internal/ │                      │    internal/     │
     │  cloud/    │                      │   generator/     │
     │  aws       │                      │   (HTML merge)   │
     │  gcp       │                      │   web/           │
     │  azure     │                      │   index.html     │
     └─────┬──────┘                      │   style.css      │
           │                             │   app.js         │
     ┌─────▼──────┐                      └──────────────────┘
     │  internal/ │
     │  models/   │
     │  (schema)  │
     └────────────┘
```

| Layer | Technology |
|---|---|
| **Language** | Go 1.24+ — strictly typed, compiled to a single static binary |
| **Embedding** | `go:embed` — all frontend assets baked into the binary at compile time |
| **CLI** | `flag` (standard library) — zero external dependencies for argument parsing |
| **TUI** | [Charmbracelet Bubbletea](https://github.com/charmbracelet/bubbletea) + [Lipgloss](https://github.com/charmbracelet/lipgloss) — terminal UI framework |
| **Frontend** | Vanilla HTML5, CSS3, ES6+ — no bundlers, no frameworks, no npm |
| **Graph** | [Cytoscape.js](https://js.cytoscape.org/) 3.x — embedded offline graph rendering |
| **Cloud SDKs (v1.0)** | AWS SDK for Go v2, Google Cloud Go Client, Azure SDK for Go |

### Zero-Dependency Philosophy

The generated `nimbus_map.html` is a **single self-contained file**. All CSS and JavaScript (except Cytoscape.js itself, which is bundled as `cytoscape.min.js`) is inlined into the HTML at generation time. You can `scp` it to a jump box, email it to a colleague, or archive it for compliance — it works everywhere with zero setup.

---

## Project Structure

```
├── cmd/nimbus/              # CLI entry point
├── internal/
│   ├── cloud/aws/           # AWS SDK extraction (v1.0 target)
│   ├── cloud/gcp/           # GCP SDK extraction (v1.0 target)
│   ├── cloud/azure/         # Azure SDK extraction (v1.0 target)
│   ├── models/              # Universal graph data model
│   ├── generator/           # HTML merge + embedding
│   ├── tui/                 # Bubbletea TUI components
│   └── mock/                # Demo data generator
├── web/                     # Frontend assets (embedded)
├── .agents/skills/          # AI agent skill library
├── spec.md                  # Formal product specification
├── design.md                # Visual identity & accessibility guidelines
└── AGENTS.md                # AI agent core instructions
```

---

## Development Roadmap

| Phase | Milestone | Status |
|---|---|---|
| v0.1-alpha | PoC with demo mode, Bubbletea TUI, offline HTML graph, agnostic data model | ✅ Complete |
| v0.2-beta | AWS production scanner (EC2, S3, RDS, VPC, Security Groups) | 🔲 Next |
| v0.3-beta | GCP and Azure production scanners | 🔲 |
| v0.4-beta | Blast radius analysis, exposure-only mode, JSON/CSV pipeline output | 🔲 |
| v1.0-stable | All clouds, all output formats, timing templates, stealth mode | 🔲 |

---

<p align="center">
  <sub>☁ Nimbus Mapper — built for the engineers who inherit the undocumented cloud.</sub><br>
  <sub>Proudly developed in Latam 🏔</sub>
</p>
