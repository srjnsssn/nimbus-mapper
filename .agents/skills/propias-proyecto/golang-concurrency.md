---
name: golang-concurrency
description: >
  Concurrency patterns for Nimbus Mapper: worker pools, semaphores, errgroup usage,
  context propagation and cancellation, channel design (buffered vs unbuffered, fan-in,
  fan-out), rate limiting per provider, and safe goroutine lifecycle management.
  This skill is the foundation that all provider scanners (aws, gcp, azure) build on.
triggers:
  - "when writing goroutine-based scanning logic"
  - "when implementing a worker pool for regions or projects"
  - "when using channels to pass results between goroutines"
  - "when implementing context cancellation or timeouts"
  - "when a scan needs to be rate-limited per provider or account"
  - "when goroutines need to be cleaned up on Ctrl+C or timeout"
  - "when a data race is detected by the race detector"
---

# Skill: golang-concurrency

## Project Context

Nimbus Mapper's performance entirely depends on concurrency. A sequential scan of
20 AWS regions × 5 resource types × 3 providers would take 10–30 minutes.
With proper concurrency it finishes in 30–90 seconds.

The concurrency model must be:
- **Bounded**: never launch unlimited goroutines. Cloud APIs have rate limits.
- **Cancellable**: Ctrl+C must stop all goroutines cleanly, not leave them running.
- **Safe**: no data races. The race detector (`go test -race`) must pass.
- **Composable**: each provider scanner uses the same patterns, making them predictable.

---

## Core Pattern: errgroup + Semaphore

This is the primary pattern used throughout Nimbus Mapper:

```go
import "golang.org/x/sync/errgroup"

func ScanAll(ctx context.Context, items []string, maxConcurrent int,
    fn func(ctx context.Context, item string) error) error {

    sem := make(chan struct{}, maxConcurrent) // semaphore
    eg, ctx := errgroup.WithContext(ctx)

    for _, item := range items {
        item := item // capture loop variable — required before Go 1.22
        sem <- struct{}{} // acquire slot (blocks if maxConcurrent goroutines are active)
        eg.Go(func() error {
            defer func() { <-sem }() // release slot when done
            return fn(ctx, item)
        })
    }
    return eg.Wait() // blocks until all goroutines finish or one returns an error
}
```

**Key behaviors:**
- `errgroup.WithContext` creates a child context that is cancelled when any goroutine
  returns a non-nil error.
- `eg.Wait()` returns the first non-nil error from any goroutine.
- The semaphore channel limits concurrency without a third-party library.

---

## Recommended Concurrency Limits

These are defaults. Allow override via config flags:

```go
const (
    DefaultAWSRegionConcurrency    = 5  // parallel AWS regions
    DefaultGCPProjectConcurrency   = 8  // parallel GCP projects
    DefaultAzureSubConcurrency     = 4  // parallel Azure subscriptions
    DefaultResourceTypeConcurrency = 6  // parallel resource types within a region/project
)
// Total max goroutines at peak:
// (5 AWS regions × 6 resource types) + (8 GCP projects × 6) + (4 Azure × 6) = 102 goroutines
// This is well within Go's capability and cloud API quotas.
```

---

## Channel Design

### Buffered channels (preferred for result passing)

```go
// Buffer size = estimated throughput burst
// Too small: producers block, slowing scanners
// Too large: wastes memory

nodeCh   := make(chan NodeEvent, 1024)  // node results from all providers
uiEvents := make(chan ui.ScanEvent, 512) // progress events to renderer
```

### Fan-in from multiple providers

```go
// Each provider scanner writes to the same channel.
// The channel is closed ONLY after ALL scanners finish (in Run(), not in scanners).

func Run(ctx context.Context) {
    nodeCh := make(chan NodeEvent, 1024)
    eg, ctx := errgroup.WithContext(ctx)

    eg.Go(func() error { return awsScanner.Scan(ctx, nodeCh) })
    eg.Go(func() error { return gcpScanner.Scan(ctx, nodeCh) })
    eg.Go(func() error { return azureScanner.Scan(ctx, nodeCh) })

    // IMPORTANT: close happens AFTER all writers finish
    go func() {
        eg.Wait()
        close(nodeCh)
    }()

    // Consumer (aggregator) reads until channel is closed
    for ev := range nodeCh {
        aggregator.Handle(ev)
    }
}
```

---

## Context Propagation

Every function that does I/O (API calls, sleeps, retries) must accept and respect `ctx`:

```go
// CORRECT — context propagated, cancellation respected
func (s *Scanner) scanRegion(ctx context.Context, region string) error {
    client := ec2.NewFromConfig(s.cfg)
    paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
    for paginator.HasMorePages() {
        // The SDK respects ctx — if cancelled, NextPage returns ctx.Err()
        page, err := paginator.NextPage(ctx)
        if err != nil {
            if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
                return nil // Clean exit — not an error, just cancellation
            }
            return err
        }
        // ... process page
    }
    return nil
}

// WRONG — ignores cancellation, goroutine cannot be stopped
func (s *Scanner) scanRegionBad(region string) error {
    client := ec2.NewFromConfig(s.cfg)
    // context.Background() ignores parent cancellation
    paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
    for paginator.HasMorePages() {
        page, _ := paginator.NextPage(context.Background()) // WRONG
        _ = page
    }
    return nil
}
```

---

## Graceful Shutdown (Ctrl+C)

```go
// cmd/nimbus/main.go

func main() {
    // signal.NotifyContext creates a context that is cancelled on SIGINT/SIGTERM
    ctx, stop := signal.NotifyContext(context.Background(),
        os.Interrupt, syscall.SIGTERM)
    defer stop()

    result, err := pipeline.Run(ctx, cfg)

    // Check if we stopped early due to signal
    if ctx.Err() != nil {
        fmt.Fprintln(os.Stderr, "\nScan interrupted. Saving partial results...")
        // result contains whatever was collected before cancellation
        outputPartialResults(result)
        os.Exit(3) // Exit code 3 = partial results
    }
    // ... normal exit
}
```

---

## Rate Limiter per Provider

```go
// internal/ratelimit/limiter.go
import "golang.org/x/time/rate"

// ProviderLimiter holds per-account rate limiters
type ProviderLimiter struct {
    mu       sync.Mutex
    limiters map[string]*rate.Limiter
    rps      float64 // requests per second
    burst    int
}

func NewProviderLimiter(rps float64, burst int) *ProviderLimiter {
    return &ProviderLimiter{
        limiters: make(map[string]*rate.Limiter),
        rps:      rps,
        burst:    burst,
    }
}

func (pl *ProviderLimiter) Wait(ctx context.Context, accountID string) error {
    pl.mu.Lock()
    l, ok := pl.limiters[accountID]
    if !ok {
        l = rate.NewLimiter(rate.Limit(pl.rps), pl.burst)
        pl.limiters[accountID] = l
    }
    pl.mu.Unlock()
    return l.Wait(ctx) // blocks until a token is available or ctx is cancelled
}

// Usage:
// limiter.Wait(ctx, accountID) // before each API call
```

---

## Anti-Patterns — NEVER DO THIS

- **NEVER** launch goroutines without a bound. Always use a semaphore or worker pool.
  Unbounded goroutines will exhaust cloud API quotas in seconds on large environments.
- **NEVER** use `sync.WaitGroup` when you need error propagation. Use `errgroup` instead.
  `WaitGroup` discards errors; `errgroup` returns the first error and cancels siblings.
- **NEVER** close a channel from a writer goroutine if there are multiple writers.
  Only the coordinator (the function that launched all writers) closes the channel,
  after all writers have returned.
- **NEVER** use `time.Sleep` in a goroutine without checking `ctx.Done()`.
  Use `select { case <-time.After(d): ... case <-ctx.Done(): return ctx.Err() }`.
- **NEVER** access a shared map from multiple goroutines without synchronization.
  Use the Aggregator pattern (single writer goroutine) or `sync.RWMutex`.
- **NEVER** ignore the loop variable capture issue in goroutines (pre-Go 1.22):
  `for _, item := range items { go func() { use(item) }() }` — `item` is shared.
  Always copy: `item := item` before the `go func()` closure.
- **NEVER** use `runtime.GOMAXPROCS` to tune concurrency. It controls OS thread count,
  not goroutine count. Use the semaphore pattern for I/O-bound work like API scanning.
