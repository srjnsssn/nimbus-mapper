---
name: golang-packaging
description: >
  Build, compilation, and distribution configuration for Nimbus Mapper. Covers goreleaser
  configuration for multi-platform cross-compilation, CGO_ENABLED=0 static binary requirements,
  go:embed for bundled assets, Docker image construction with scratch/alpine base, Makefile
  targets, checksums and binary signing, Homebrew tap generation, and CI/CD release pipeline
  via GitHub Actions.
triggers:
  - "when configuring or modifying the goreleaser setup"
  - "when writing or modifying the Makefile"
  - "when building the Dockerfile or container image"
  - "when adding a new embedded asset (HTML, template, etc.)"
  - "when setting up the GitHub Actions release workflow"
  - "when publishing a new version or cutting a release"
  - "when a user asks how to install or build Nimbus Mapper"
---

# Skill: golang-packaging

## Project Context

Nimbus Mapper is a CLI security tool used by DevOps engineers and Red Teams.
Distribution requirements:
- **Zero dependencies**: the binary must run without installing Go, cloud SDKs, or any runtime.
- **Multi-platform**: Linux (amd64/arm64), macOS (Apple Silicon and Intel), Windows (amd64).
- **Verifiable**: every release ships with checksums and optionally GPG-signed binaries.
- **Containerizable**: a minimal Docker image for use in CI/CD pipelines.
- **Fast to install**: `go install`, Homebrew, and direct binary download must all work.

---

## Build Requirements

### CGO must be disabled

```bash
CGO_ENABLED=0
```

This is mandatory, not optional. Reasons:
1. CGO produces OS-specific binaries that cannot be cross-compiled.
2. CGO binaries depend on libc which may differ between build and run environments.
3. Static binaries copy into Docker `scratch` images without glibc.

**If a dependency requires CGO**, it must be replaced with a pure Go alternative.
Never merge code that silently re-enables CGO.

### Minimum Go Version

Set in `go.mod`. Must be >= 1.21 (required for `log/slog`):
```
go 1.21
```

---

## Makefile

```makefile
# Makefile

BINARY     := nimbus
VERSION    := $(shell git describe --tags --always --dirty)
COMMIT     := $(shell git rev-parse --short HEAD)
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS    := -ldflags="-s -w \
  -X main.version=$(VERSION) \
  -X main.commit=$(COMMIT) \
  -X main.buildDate=$(BUILD_DATE)"

# Default target: build for current OS/arch
.PHONY: build
build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/nimbus

# Build for all release targets
.PHONY: build-all
build-all:
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-amd64 ./cmd/nimbus
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-arm64 ./cmd/nimbus
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-darwin-amd64 ./cmd/nimbus
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY)-darwin-arm64 ./cmd/nimbus
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-windows-amd64.exe ./cmd/nimbus

# Run all tests
.PHONY: test
test:
	go test -race -count=1 ./...

# Run tests with coverage
.PHONY: coverage
coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Lint
.PHONY: lint
lint:
	golangci-lint run ./...

# Generate checksums for release binaries
.PHONY: checksums
checksums:
	sha256sum bin/$(BINARY)-* > bin/sha256sums.txt

# Docker image (for CI/CD use)
.PHONY: docker
docker:
	docker build --platform linux/amd64 -t nimbus-mapper:$(VERSION) -f Dockerfile .

# Install locally
.PHONY: install
install:
	CGO_ENABLED=0 go install $(LDFLAGS) ./cmd/nimbus

# Clean
.PHONY: clean
clean:
	rm -rf bin/ coverage.out coverage.html
```

---

## Version Injection via ldflags

```go
// cmd/nimbus/version.go

package main

// These are set at build time via -ldflags
var (
    version   = "dev"       // overridden by goreleaser / Makefile
    commit    = "unknown"
    buildDate = "unknown"
)

// versionCmd is added to the Cobra root command:
// nimbus version → prints version info
func printVersion() {
    fmt.Printf("nimbus-mapper %s\n  commit: %s\n  built:  %s\n",
        version, commit, buildDate)
}
```

---

## go:embed for Bundled Assets

If Nimbus ships with a web UI, report templates, or rule definition files, embed them:

```go
// internal/assets/assets.go

package assets

import "embed"

//go:embed web/dist/* templates/* rules/*.yaml
var FS embed.FS

// Usage anywhere in the binary:
// data, _ := assets.FS.ReadFile("templates/report.html")
// entries, _ := assets.FS.ReadDir("rules")
```

Rules for embedded assets:
- **Always embed production-built assets**, not source files. Add `web/dist/` to `.gitignore`
  and build it in CI before running `goreleaser`.
- **Never embed** `.env` files, credentials, or test fixtures.
- The `//go:embed` directive must appear immediately before the `var` declaration with no blank lines.

---

## goreleaser Configuration

```yaml
# .goreleaser.yaml

version: 2

before:
  hooks:
    - go mod tidy
    - go generate ./...    # triggers any go:generate directives (e.g., web asset build)

builds:
  - id: nimbus
    main: ./cmd/nimbus
    binary: nimbus
    env:
      - CGO_ENABLED=0
    goos:
      - linux
      - darwin
      - windows
    goarch:
      - amd64
      - arm64
    ignore:
      - goos: windows
        goarch: arm64   # Windows ARM64 is rarely needed
    ldflags:
      - -s -w
      - -X main.version={{.Version}}
      - -X main.commit={{.Commit}}
      - -X main.buildDate={{.Date}}
    flags:
      - -trimpath    # remove build paths from binary for reproducibility

archives:
  - id: nimbus
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    format: tar.gz
    format_overrides:
      - goos: windows
        format: zip
    files:
      - README.md
      - LICENSE
      - CHANGELOG.md

checksum:
  name_template: "checksums.txt"
  algorithm: sha256

signs:
  - artifacts: checksum
    args:
      - "--batch"
      - "--local-user"
      - "{{ .Env.GPG_FINGERPRINT }}"
      - "--output"
      - "${signature}"
      - "--detach-sign"
      - "${artifact}"

release:
  github:
    owner: your-org
    name: nimbus-mapper
  draft: false
  prerelease: auto    # tags like v1.0.0-beta.1 are marked as pre-release

brews:
  - name: nimbus-mapper
    homepage: "https://github.com/your-org/nimbus-mapper"
    description: "Multi-cloud security scanner for AWS, GCP, and Azure"
    license: "MIT"
    repository:
      owner: your-org
      name: homebrew-tap
    commit_author:
      name: goreleaserbot
      email: bot@goreleaser.com

changelog:
  sort: asc
  filters:
    exclude:
      - "^docs:"
      - "^test:"
      - "^chore:"
      - Merge pull request
      - Merge branch
```

---

## Dockerfile

Two-stage build: compile in a Go image, copy binary to scratch:

```dockerfile
# Dockerfile

# ── Stage 1: Build ─────────────────────────────────────────────────────
FROM golang:1.21-alpine AS builder

# Install git for go modules that use git tags
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Cache dependencies separately from source code
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=$(git describe --tags --always)" \
    -trimpath \
    -o nimbus ./cmd/nimbus

# ── Stage 2: Runtime ───────────────────────────────────────────────────
FROM scratch

# ca-certificates required for HTTPS calls to cloud APIs
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# The binary
COPY --from=builder /build/nimbus /usr/local/bin/nimbus

# Run as non-root (UID 65534 = nobody)
USER 65534

ENTRYPOINT ["/usr/local/bin/nimbus"]
```

**Notes:**
- Use `scratch` base for the smallest possible image (~10MB).
- If `scratch` causes issues (e.g., missing `/tmp`), use `alpine:3.19` instead.
- Never use `ubuntu` or `debian` base images — they are hundreds of MB for no benefit.
- The `ca-certificates` copy is mandatory — without it, all HTTPS calls to AWS/GCP/Azure APIs fail.

---

## GitHub Actions Release Workflow

```yaml
# .github/workflows/release.yml

name: Release

on:
  push:
    tags:
      - 'v*'   # Trigger on version tags: v1.0.0, v1.2.3-beta.1

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write   # required to create GitHub releases
      packages: write   # required to push to GHCR
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # goreleaser needs full git history for changelog

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true

      - name: Run tests before releasing
        run: go test -race ./...

      - name: Import GPG key (for signing checksums)
        uses: crazy-max/ghaction-import-gpg@v6
        with:
          gpg_private_key: ${{ secrets.GPG_PRIVATE_KEY }}
          passphrase: ${{ secrets.GPG_PASSPHRASE }}

      - name: Run goreleaser
        uses: goreleaser/goreleaser-action@v5
        with:
          distribution: goreleaser
          version: latest
          args: release --clean
        env:
          GITHUB_TOKEN:    ${{ secrets.GITHUB_TOKEN }}
          GPG_FINGERPRINT: ${{ secrets.GPG_FINGERPRINT }}
          HOMEBREW_TAP_GITHUB_TOKEN: ${{ secrets.HOMEBREW_TAP_GITHUB_TOKEN }}
```

---

## Installation Methods (for documentation)

```bash
# 1. go install (requires Go 1.21+)
go install github.com/your-org/nimbus-mapper/cmd/nimbus@latest

# 2. Homebrew (macOS/Linux)
brew install your-org/tap/nimbus-mapper

# 3. Direct binary download
curl -sSL https://github.com/your-org/nimbus-mapper/releases/latest/download/nimbus_linux_amd64.tar.gz \
  | tar -xz -C /usr/local/bin

# 4. Docker
docker run --rm -v ~/.aws:/root/.aws ghcr.io/your-org/nimbus-mapper:latest scan --provider aws

# 5. Verify checksum after download
sha256sum -c checksums.txt
```

---

## Anti-Patterns — NEVER DO THIS

- **NEVER** publish a release binary without the corresponding `checksums.txt`.
  Security tools that can't be verified are a supply chain risk.
- **NEVER** set `CGO_ENABLED=1` in the build pipeline. If a dependency requires CGO,
  replace it with a pure Go alternative and document the decision.
- **NEVER** embed test fixtures, `.env` files, `testdata/`, or development configs
  via `//go:embed`. Only production assets (built web UI, rule definitions).
- **NEVER** use `ubuntu` or `debian` as the Docker runtime base. Use `scratch` or `alpine`.
- **NEVER** run `goreleaser` without running `go test -race ./...` first.
  A release with failing tests is worse than no release.
- **NEVER** commit binaries to the repository. The `bin/` directory is in `.gitignore`.
  All binaries are built in CI and attached to GitHub releases.
- **NEVER** skip `-trimpath` in release builds. Without it, the binary embeds absolute
  paths from the build machine (e.g., `/home/runner/work/...`), which leaks CI infrastructure details.
