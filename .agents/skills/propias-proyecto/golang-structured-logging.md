---
name: golang-structured-logging
description: >
  Internal telemetry and diagnostic logging for Nimbus Mapper using Go 1.21+ log/slog.
  Covers strict stdout/stderr segregation (critical for TUI and pipeline compatibility),
  log levels, per-scan correlation IDs, subsystem tagging, error stack traces, the
  --verbose and --debug flags, log file output, and integration with the Bubbletea TUI
  and the JSON/CSV output modes.
triggers:
  - "when writing any log statement anywhere in the codebase"
  - "when handling or wrapping errors that need diagnostic context"
  - "when implementing the --verbose or --debug flag"
  - "when adding a new subsystem (new provider, new rule engine, etc.)"
  - "when debugging an issue that requires more observability"
  - "when a log statement might accidentally write to stdout"
---

# Skill: golang-structured-logging

## The Core Constraint

**`stdout` belongs exclusively to Nimbus output (TUI, JSON, CSV, SARIF).**

`log/slog`, `fmt.Println`, and any other diagnostic output goes to `stderr` or a log file.
This is non-negotiable because:
1. In TUI mode: anything written to stdout corrupts the Bubbletea buffer.
2. In JSON/CSV mode: any extra text to stdout corrupts the machine-readable output.
3. In pipe mode (`nimbus scan | jq`): only the final serialized data should reach jq.

---

## Library

Use **`log/slog`** (Go standard library, available from Go 1.21).
Do not add third-party logging libraries (zerolog, zap, logrus) — they add dependencies
without sufficient benefit for this use case.

```go
// go.mod: no additional dependency needed for slog
// Minimum Go version: 1.21 (already required for other features)
```

---

## Logger Initialization

Initialize the global logger in `main()` based on flags. All subsystems use the global logger
(or a child logger created from it with `slog.With()`):

```go
// cmd/nimbus/main.go

func initLogger(verboseFlag bool, debugFlag bool, logFile string) {
    level := slog.LevelWarn  // Default: only warnings and errors

    if verboseFlag { level = slog.LevelInfo }
    if debugFlag   { level = slog.LevelDebug }

    var handler slog.Handler

    if logFile != "" {
        // Write to file — useful for CI and long scans
        f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
        if err != nil {
            fmt.Fprintf(os.Stderr, "warning: cannot open log file %s: %v\n", logFile, err)
        } else {
            handler = slog.NewJSONHandler(f, &slog.HandlerOptions{Level: level})
        }
    }

    if handler == nil {
        // Default: text format to stderr
        // CRITICAL: always os.Stderr, never os.Stdout
        handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
            Level:     level,
            AddSource: debugFlag, // include file:line only in debug mode
        })
    }

    slog.SetDefault(slog.New(handler))
}
```

---

## Log Levels — When to Use Each

| Level | Method | When to use |
|---|---|---|
| `DEBUG` | `slog.Debug()` | Per-resource trace: "listing instances in us-east-1", API call parameters. High volume, off by default. |
| `INFO`  | `slog.Info()`  | Scan milestones: "started scanning account 123456", "found 47 instances". One per region/provider. |
| `WARN`  | `slog.Warn()`  | Non-fatal issues: PermissionDenied on a project, API not enabled, a region returning 0 resources unexpectedly. |
| `ERROR` | `slog.Error()` | Fatal per-provider failure: credential resolution failed, context cancelled, unexpected SDK error. |

**The TUI already shows scan progress and findings to the user. Logs are for diagnostics only.
Do not duplicate finding information in logs.**

---

## Correlation IDs

Every scan session gets a unique ID that appears in all log entries, making it easy to
grep a log file for a specific scan:

```go
// internal/log/context.go

type contextKey string

const scanIDKey contextKey = "scan_id"

// InjectScanID attaches a scan ID to the context and to the slog logger.
func InjectScanID(ctx context.Context) (context.Context, string) {
    scanID := generateScanID() // e.g. "nmbs-a3f9c2"
    ctx = context.WithValue(ctx, scanIDKey, scanID)
    // Inject into slog so all subsequent calls include it automatically:
    slog.SetDefault(slog.Default().With("scan_id", scanID))
    return ctx, scanID
}

func generateScanID() string {
    b := make([]byte, 4)
    rand.Read(b)
    return "nmbs-" + hex.EncodeToString(b)
}
```

---

## Subsystem Tagging

Every major subsystem creates a child logger with a `component` field.
This enables filtering: `grep '"component":"aws-extractor"' nimbus.log`

```go
// internal/aws/scanner.go
var log = slog.Default().With("component", "aws-extractor")

// internal/gcp/scanner.go
var log = slog.Default().With("component", "gcp-extractor")

// internal/azure/scanner.go
var log = slog.Default().With("component", "azure-extractor")

// internal/rules/engine.go
var log = slog.Default().With("component", "rules-engine")

// Usage:
log.Debug("listing instances", "region", region, "project", projectID)
log.Warn("permission denied", "resource", resourceID, "err", err)
log.Error("scan failed", "provider", "aws", "err", err)
```

---

## Error Wrapping and Logging

Always wrap errors with context before logging. Use `fmt.Errorf("context: %w", err)` for
wrapping and `slog.Error("msg", "err", err)` for logging. Never discard errors silently.

```go
// WRONG — loses context, makes debugging impossible
if err != nil {
    log.Error("failed")
    return
}

// WRONG — error string in a generic "error" key with no context
log.Error("error occurred", "error", err.Error())

// CORRECT — wrapped error with structured context fields
if err != nil {
    wrappedErr := fmt.Errorf("listing security groups in %s: %w", region, err)
    log.Error("security group scan failed",
        "region",   region,
        "provider", "aws",
        "err",      wrappedErr,
    )
    return wrappedErr
}
```

---

## Per-API-Call Debug Logging Pattern

At DEBUG level, log before and after each API call with timing:

```go
func (s *AWSScanner) scanSecurityGroups(ctx context.Context,
    region string, client EC2Client) error {

    log.Debug("starting security group scan", "region", region)
    start := time.Now()

    var count int
    // ... scan logic ...
    count++

    log.Debug("security group scan complete",
        "region",     region,
        "count",      count,
        "duration_ms", time.Since(start).Milliseconds(),
    )
    return nil
}
```

---

## Integration with TUI (Bubbletea Mode)

In TUI mode, the logger must route to stderr only. Never route to stdout.
The initialization in `main()` already handles this, but be explicit in tests:

```go
// In tests, always redirect logger to discard or a buffer:
func TestMain(m *testing.M) {
    // Silence logs during tests unless -v is passed
    if testing.Verbose() {
        slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr,
            &slog.HandlerOptions{Level: slog.LevelDebug})))
    } else {
        slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
    }
    os.Exit(m.Run())
}
```

---

## Log Format Reference

**Text format** (default, human-readable in terminal):
```
time=2024-01-15T10:23:44Z level=INFO msg="scan started" scan_id=nmbs-a3f9c2 component=aws-extractor regions=3
time=2024-01-15T10:23:45Z level=WARN msg="permission denied, skipping" scan_id=nmbs-a3f9c2 component=gcp-extractor project=my-project-id err="rpc error: code = PermissionDenied"
time=2024-01-15T10:23:47Z level=ERROR msg="azure scan failed" scan_id=nmbs-a3f9c2 component=azure-extractor subscription=xxx err="listing VMs: ...: context deadline exceeded"
```

**JSON format** (with `--log-file nimbus.log`):
```json
{"time":"2024-01-15T10:23:44Z","level":"INFO","msg":"scan started","scan_id":"nmbs-a3f9c2","component":"aws-extractor","regions":3}
```

---

## Anti-Patterns — NEVER DO THIS

- **NEVER** use `log.Print`, `log.Printf`, `log.Println` (stdlib `log` package).
  It writes to stderr by default but is not structured and cannot be silenced by level.
- **NEVER** use `fmt.Println`, `fmt.Printf`, or `fmt.Fprintf(os.Stdout, ...)` for diagnostic
  messages. Those are for the output layer only (serializers and plain renderer).
- **NEVER** use `fmt.Fprintf(os.Stderr, ...)` for diagnostic messages directly.
  Always use `slog` so the messages are structured, leveled, and silenceable.
- **NEVER** call `slog.SetDefault(...)` outside of `main()` or test setup.
  Subsystems get child loggers via `slog.Default().With(...)`, not by replacing the default.
- **NEVER** log at `INFO` inside a tight loop (e.g., per-instance). Use `DEBUG`.
  Logging 10,000 INFO lines for 10,000 EC2 instances floods stderr unnecessarily.
- **NEVER** include raw cloud API response bodies in log messages, even at DEBUG.
  They often contain ARNs and account identifiers (see `golang-secrets-handling` skill).
- **NEVER** swallow errors with `_ = someFunc()`. Wrap and log them, or propagate them.
  Silent failures in a security scanner are worse than noisy ones.
