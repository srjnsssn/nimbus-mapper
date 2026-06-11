---
name: golang-data-pipeline
description: >
  Concurrency architecture and data normalization layer for Nimbus Mapper. Covers the
  NimbusNode and NimbusEdge schema (the Agnostic Nimbus Schema), the channel-based
  aggregation pipeline, deduplication logic, fan-in from multiple cloud providers,
  serialization to JSON/CSV/SARIF/Markdown, and the context-based cancellation model.
  This is the backbone that all provider scanners feed into.
triggers:
  - "when structuring Go channels for result aggregation"
  - "when defining or modifying the NimbusNode or NimbusEdge schema"
  - "when merging results from multiple cloud providers or regions"
  - "when implementing deduplication of findings or nodes"
  - "when serializing output to JSON, CSV, SARIF, or Markdown"
  - "when implementing the context timeout or cancellation model"
  - "when adding a new provider that needs to integrate with the pipeline"
---

# Skill: golang-data-pipeline

## Project Context

Nimbus Mapper runs AWS, GCP, and Azure extractors concurrently. Each produces a stream of
`NimbusNode` objects and `Finding` objects. The pipeline must:
- Aggregate all results into a unified in-memory graph without race conditions.
- Deduplicate identical findings (same resource, same rule, emitted from multiple sources).
- Support cancellation: if the user hits Ctrl+C, all workers stop and partial results are saved.
- Serialize the final result set to multiple formats from a single in-memory structure.

---

## The Agnostic Nimbus Schema

All provider-specific data must be normalized to these two types before entering the pipeline.
No AWS, GCP, or Azure SDK types should ever appear in the serialized output.

```go
// internal/model/schema.go

package model

// NimbusNode represents any cloud resource, normalized across providers.
type NimbusNode struct {
    // Identity
    ID           string            // Provider-native: ARN, self-link, Azure resource ID
    ShortID      string            // Human-friendly: "i-0a1b2c3d", "my-bucket"
    Type         string            // Canonical type: see NodeType constants below
    Provider     string            // "aws" | "gcp" | "azure"
    AccountID    string            // AWS account ID / GCP project ID / Azure subscription ID
    Region       string            // Normalized region name

    // Network
    PublicIP     string
    PrivateIPs   []string
    Subnet       string            // CIDR or subnet ID
    VPC          string            // VPC/VNet ID

    // Identity attachment
    IAMRole      string            // Instance profile ARN / SA email / managed identity object ID
    AttachedRules []string         // Security Group IDs / NSG IDs / Firewall rule names

    // Metadata
    Name         string
    Tags         map[string]string // Normalized from provider-specific label systems
    CreatedAt    *time.Time

    // Security output (injected by cloud-misconfiguration-rules skill)
    ExposureLevel ExposureLevel
    Findings      []Finding        // All findings for this specific node

    // Raw data (for deep analysis, never in default output)
    RawMetadata  json.RawMessage   `json:"-"` // Excluded from default serialization
}

// Canonical node type constants — use these everywhere, never free-form strings
const (
    NodeTypeEC2Instance      = "aws_ec2_instance"
    NodeTypeSecurityGroup    = "aws_security_group"
    NodeTypeS3Bucket         = "aws_s3_bucket"
    NodeTypeRDSInstance      = "aws_rds_instance"
    NodeTypeLambdaFunction   = "aws_lambda_function"
    NodeTypeGCEInstance      = "gcp_compute_instance"
    NodeTypeGCSBucket        = "gcp_storage_bucket"
    NodeTypeGKECluster       = "gcp_gke_cluster"
    NodeTypeCloudRunService  = "gcp_cloud_run_service"
    NodeTypeAzureVM          = "azure_virtual_machine"
    NodeTypeAzureNSG         = "azure_nsg"
    NodeTypeAzureStorage     = "azure_storage_account"
    NodeTypeAzureAKS         = "azure_aks_cluster"
)

// NimbusEdge represents a relationship between two nodes.
type NimbusEdge struct {
    SourceID      string
    TargetID      string
    PortRange     string   // "22-22" | "0-65535" | "IAM" | "HTTPS"
    Protocol      string   // "tcp" | "udp" | "icmp" | "iam"
    EdgeType      string   // "network_ingress" | "network_egress" | "iam_can_read" | "iam_can_write"
    ViaIdentity   string   // for IAM edges: the role/SA enabling the connection
    Bidirectional bool
}
```

---

## Pipeline Architecture

```
                          ┌─────────────────────────────┐
                          │         Pipeline             │
                          │                              │
[aws-scanner]  ──────────►│  chan NodeEvent              │
[gcp-scanner]  ──────────►│  (buffered, 1024)            │
[azure-scanner]──────────►│                              │
                          │  Aggregator goroutine:        │
                          │   - receives NodeEvents       │
                          │   - deduplicates              │
                          │   - builds graph              │
                          │   - notifies UI               │
                          │                              │
                          │  Result: ScanResult          │
                          │   .Nodes []NimbusNode        │
                          │   .Edges []NimbusEdge        │
                          │   .Findings []Finding        │
                          └──────────┬──────────────────┘
                                     │
                          Serializer (format flag):
                          JSON / CSV / SARIF / Markdown
```

---

## Event Types for the Pipeline

```go
// internal/pipeline/events.go

type NodeEventKind int

const (
    NodeEventUpsert  NodeEventKind = iota // new or updated node
    NodeEventFinding                       // new finding for an existing node
    NodeEventEdge                          // new edge between two nodes
)

type NodeEvent struct {
    Kind    NodeEventKind
    Node    *model.NimbusNode  // non-nil for Upsert
    Finding *model.Finding      // non-nil for Finding
    Edge    *model.NimbusEdge   // non-nil for Edge
}
```

Workers emit NodeEvents instead of writing directly to a map:
```go
// Inside any scanner, after normalizing a resource:
nodeCh <- pipeline.NodeEvent{
    Kind: pipeline.NodeEventUpsert,
    Node: &model.NimbusNode{
        ID:       "i-0a1b2c3d",
        Type:     model.NodeTypeEC2Instance,
        Provider: "aws",
        // ...
    },
}
```

---

## Aggregator

The aggregator is the single goroutine that owns the in-memory graph:

```go
// internal/pipeline/aggregator.go

type Aggregator struct {
    nodes    map[string]*model.NimbusNode  // key: node.ID
    edges    []model.NimbusEdge
    findings []model.Finding
    mu       sync.RWMutex                  // only for reads from other goroutines
                                           // (aggregator writes are single-threaded)
    // Dedup sets:
    seenFindings map[string]struct{}       // key: finding.ID (hash)
    seenEdges    map[string]struct{}       // key: hash(source+target+port+type)
}

func (a *Aggregator) Run(ctx context.Context, nodeCh <-chan NodeEvent,
    uiEvents chan<- ui.ScanEvent) *ScanResult {
    for {
        select {
        case <-ctx.Done():
            // Context cancelled (Ctrl+C or timeout) — return partial results
            return a.buildResult()
        case ev, ok := <-nodeCh:
            if !ok {
                // Channel closed = all scanners done
                return a.buildResult()
            }
            a.handleEvent(ev, uiEvents)
        }
    }
}

func (a *Aggregator) handleEvent(ev NodeEvent, uiEvents chan<- ui.ScanEvent) {
    switch ev.Kind {
    case NodeEventUpsert:
        a.upsertNode(ev.Node)

    case NodeEventFinding:
        // Dedup by finding ID (deterministic hash)
        if _, seen := a.seenFindings[ev.Finding.ID]; seen { return }
        a.seenFindings[ev.Finding.ID] = struct{}{}
        a.findings = append(a.findings, *ev.Finding)
        // Attach finding to its node
        if node, ok := a.nodes[ev.Finding.ResourceID]; ok {
            node.Findings = append(node.Findings, *ev.Finding)
            node.ExposureLevel = recomputeExposure(node)
        }
        // Forward to UI for live display
        uiEvents <- ui.ScanEvent{
            Kind:    ui.EventFindingFound,
            Finding: ev.Finding,
        }

    case NodeEventEdge:
        key := edgeKey(ev.Edge)
        if _, seen := a.seenEdges[key]; seen { return }
        a.seenEdges[key] = struct{}{}
        a.edges = append(a.edges, *ev.Edge)
    }
}

func (a *Aggregator) upsertNode(n *model.NimbusNode) {
    if existing, ok := a.nodes[n.ID]; ok {
        // Merge: preserve existing findings, update fields from new scan
        n.Findings = existing.Findings
        n.ExposureLevel = existing.ExposureLevel
    }
    a.nodes[n.ID] = n
}
```

---

## Deduplication

Finding ID is a deterministic hash — same resource + same rule always produces the same ID:

```go
// internal/model/finding.go

func NewFindingID(provider, accountID, resourceID, ruleID string) string {
    h := sha256.New()
    fmt.Fprintf(h, "%s|%s|%s|%s", provider, accountID, resourceID, ruleID)
    return fmt.Sprintf("%x", h.Sum(nil))[:16] // 16-char prefix is sufficient
}
```

---

## Serializers

All serializers take a `*ScanResult` and write to an `io.Writer`.
They never write directly to `os.Stdout` — the caller provides the writer.

```go
// internal/output/json.go
func WriteJSON(result *pipeline.ScanResult, w io.Writer, maskIDs bool) error {
    enc := json.NewEncoder(w)
    enc.SetIndent("", "  ")
    // Apply redaction if --mask-ids
    if maskIDs {
        result = result.Redacted()
    }
    return enc.Encode(result)
}

// internal/output/csv.go
func WriteCSV(result *pipeline.ScanResult, w io.Writer, maskIDs bool) error {
    cw := csv.NewWriter(w)
    defer cw.Flush()
    // Header row
    cw.Write([]string{"severity","provider","account","region","resource_id","resource_type","rule_id","title"})
    for _, f := range result.Findings {
        if maskIDs { f = secrets.RedactFinding(f, true) }
        cw.Write([]string{
            string(f.Severity), f.Provider, f.AccountID,
            f.Region, f.ResourceID, f.ResourceType, f.RuleID, f.Title,
        })
    }
    return cw.Error()
}

// internal/output/sarif.go
// SARIF 2.1.0 — compatible with GitHub Code Scanning, VS Code SARIF Viewer
type SARIFReport struct {
    Version string      `json:"version"` // "2.1.0"
    Schema  string      `json:"$schema"`
    Runs    []SARIFRun  `json:"runs"`
}
// Map Finding.Severity → SARIF level: critical→error, high→error, medium→warning, low→note
// Map Finding.RuleID  → SARIF rule with helpUri pointing to cloud docs
```

---

## Context & Cancellation Model

```go
// internal/pipeline/run.go

func Run(cfg *config.Config) (*ScanResult, error) {
    // Top-level context with optional timeout
    ctx := context.Background()
    if cfg.Timeout > 0 {
        var cancel context.CancelFunc
        ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
        defer cancel()
    }

    // Handle Ctrl+C gracefully — return partial results, don't panic
    ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
    defer stop()

    nodeCh   := make(chan NodeEvent, 1024)  // buffered to decouple scanners from aggregator
    uiEvents := make(chan ui.ScanEvent, 512)

    // Start aggregator
    var result *ScanResult
    aggDone := make(chan struct{})
    go func() {
        defer close(aggDone)
        agg := NewAggregator()
        result = agg.Run(ctx, nodeCh, uiEvents)
    }()

    // Start UI renderer (non-blocking)
    go ui.RunRenderer(ctx, uiEvents, os.Stdout)

    // Start all provider scanners concurrently
    eg, scanCtx := errgroup.WithContext(ctx)
    if cfg.AWS.Enabled {
        eg.Go(func() error { return aws.NewScanner(cfg.AWS).Scan(scanCtx, nodeCh) })
    }
    if cfg.GCP.Enabled {
        eg.Go(func() error { return gcp.NewScanner(cfg.GCP).Scan(scanCtx, nodeCh) })
    }
    if cfg.Azure.Enabled {
        eg.Go(func() error { return azure.NewScanner(cfg.Azure).Scan(scanCtx, nodeCh) })
    }

    // Wait for all scanners to finish, then close the node channel
    scanErr := eg.Wait()
    close(nodeCh)

    // Wait for aggregator to process all remaining events
    <-aggDone

    return result, scanErr
}
```

---

## Anti-Patterns — NEVER DO THIS

- **NEVER** use a global `map[string]NimbusNode` without synchronization.
  All map writes go through the Aggregator goroutine. Map reads from other goroutines
  use `sync.RWMutex`. No exceptions.
- **NEVER** call `json.Marshal` on a `NimbusNode` that still contains `RawMetadata`
  in the default output path. `RawMetadata` has `json:"-"` for a reason — it may contain
  account IDs and internal API response fields.
- **NEVER** close `nodeCh` from inside a scanner goroutine. Only the `Run()` function
  closes it after `eg.Wait()` confirms all scanners have returned.
- **NEVER** deduplicate by `(resourceID, ruleID)` alone. Include `accountID` and `provider`
  in the hash. The same resource ID can exist in different accounts (e.g., two AWS accounts
  can both have an S3 bucket named `backup`).
- **NEVER** serialize `[]Finding` in a separate pass from `[]NimbusNode`. Build the
  `ScanResult` struct once from the Aggregator's final state and serialize that single struct.
  Parallel serialization of separate lists can produce inconsistent output.
- **NEVER** use `os.Exit()` in the pipeline. Return errors to `main()` and let it handle exit codes.
