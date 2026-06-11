---
name: gcp-go-sdk
description: >
  Complete standards for all GCP API interactions in Nimbus Mapper using the official Google
  Cloud Go libraries. Covers Application Default Credentials, service account impersonation,
  org/folder/project hierarchy traversal, resource enumeration (Compute Engine, Cloud Storage,
  Cloud Run, GKE, Cloud SQL, IAM), pagination via iterators, quota management, and normalized
  NimbusNode output. Includes error handling for PermissionDenied and API-not-enabled cases.
triggers:
  - "when writing or modifying any GCP extraction logic"
  - "when querying Compute Engine, Cloud Storage, Cloud Run, GKE, Cloud SQL, or IAM"
  - "when configuring GCP authentication or ADC"
  - "when traversing GCP org, folders, or projects"
  - "when handling GCP quota errors or PermissionDenied"
  - "when writing multi-project GCP scan logic"
---

# Skill: gcp-go-sdk

## Project Context

GCP environments differ from AWS in one critical way: the resource hierarchy is
**Organization → Folders (n levels deep) → Projects**. A correct scanner starts from the
organization root and traverses downward — never from a hardcoded project list. Projects can
be nested inside folders up to arbitrary depth. IAM policies apply at every level and are
inherited downward.

Nimbus Mapper must:
- Traverse the full org hierarchy to discover all active projects.
- Scan Compute Engine, Cloud Storage, Cloud Run, GKE, Cloud SQL, and IAM in each project.
- Respect GCP's per-API per-project quota limits.
- Handle `PermissionDenied` on individual projects without aborting the full scan.

---

## Go Module Dependencies

```
go get cloud.google.com/go/compute/apiv1
go get cloud.google.com/go/resourcemanager/apiv3
go get cloud.google.com/go/storage
go get cloud.google.com/go/run/apiv2
go get cloud.google.com/go/container/apiv1
go get google.golang.org/api/iam/v1
go get google.golang.org/api/sqladmin/v1
go get google.golang.org/api/cloudresourcemanager/v3
go get google.golang.org/api/option
go get google.golang.org/api/impersonate
go get golang.org/x/oauth2/google
go get google.golang.org/grpc/codes
go get google.golang.org/grpc/status
```

---

## Authentication: Application Default Credentials (ADC)

**Never parse JSON key files manually. Never hardcode credentials.**
Use ADC — the SDK resolves credentials automatically in this priority order:

1. `GOOGLE_APPLICATION_CREDENTIALS` env var pointing to a service account JSON key file
2. gcloud user credentials (`gcloud auth application-default login`) — for local development
3. Attached service account via GCE/GKE metadata server — for production workloads
4. Workload Identity Federation (for CI systems like GitHub Actions)

```go
// internal/gcp/client.go

package gcp

import (
    "context"
    "google.golang.org/api/option"
    "google.golang.org/api/impersonate"
)

type ClientOptions struct {
    QuotaProject       string // project to bill API quota against
    ImpersonateAccount string // SA email to impersonate (optional)
    Scopes             []string
}

// BuildClientOptions returns option.ClientOption slice for any GCP client constructor.
func BuildClientOptions(ctx context.Context, opts ClientOptions) ([]option.ClientOption, error) {
    scopes := opts.Scopes
    if len(scopes) == 0 {
        scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
    }

    var clientOpts []option.ClientOption

    if opts.ImpersonateAccount != "" {
        // Impersonate a service account — the current ADC identity must have
        // roles/iam.serviceAccountTokenCreator on the target SA
        ts, err := impersonate.CredentialsTokenSource(ctx,
            impersonate.CredentialsConfig{
                TargetPrincipal: opts.ImpersonateAccount,
                Scopes:          scopes,
            })
        if err != nil {
            return nil, fmt.Errorf("setting up impersonation for %s: %w",
                opts.ImpersonateAccount, err)
        }
        clientOpts = append(clientOpts, option.WithTokenSource(ts))
    }
    // ADC is used automatically if no explicit credentials are set above

    if opts.QuotaProject != "" {
        clientOpts = append(clientOpts, option.WithQuotaProject(opts.QuotaProject))
    }

    return clientOpts, nil
}
```

### When to use Impersonation vs direct ADC

| Context | Auth method |
|---|---|
| Running locally during development | `gcloud auth application-default login` (ADC) |
| Running on GKE with Workload Identity | ADC via metadata server |
| Scanning multiple projects with different SAs | Impersonate a per-project reader SA |
| CI/CD (GitHub Actions, Cloud Build) | Workload Identity Federation or SA key in secrets manager |
| **Never** | Hardcoded JSON keys in source code or go.mod |

---

## Hierarchy Traversal: Org → Folders → Projects

**Always start from the organization.** Never hardcode project IDs unless the user
explicitly passes `--projects proj1,proj2`.

```go
// internal/gcp/hierarchy.go

package gcp

import (
    "cloud.google.com/go/resourcemanager/apiv3"
    resourcemanagerpb "cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
    "google.golang.org/api/iterator"
)

// ListAllProjects discovers ALL active projects under an org.
// Uses SearchProjects which traverses org+folders in a single API call.
func ListAllProjects(ctx context.Context, orgID string,
    copts []option.ClientOption) ([]string, error) {

    c, err := resourcemanager.NewProjectsClient(ctx, copts...)
    if err != nil {
        return nil, fmt.Errorf("creating resource manager client: %w", err)
    }
    defer c.Close()

    var projectIDs []string
    // Query searches recursively through all folders under the org
    query := fmt.Sprintf("parent:organizations/%s state:ACTIVE", orgID)
    it := c.SearchProjects(ctx, &resourcemanagerpb.SearchProjectsRequest{Query: query})

    for {
        proj, err := it.Next()
        if errors.Is(err, iterator.Done) {
            break
        }
        if err != nil {
            return nil, fmt.Errorf("iterating projects: %w", err)
        }
        projectIDs = append(projectIDs, proj.GetProjectId())
    }
    return projectIDs, nil
}

// ListFolders returns all folders under a parent (org or folder), recursively.
// Useful for building the full hierarchy path to display in findings.
func ListFolders(ctx context.Context, parent string,
    copts []option.ClientOption) ([]*resourcemanagerpb.Folder, error) {

    c, err := resourcemanager.NewFoldersClient(ctx, copts...)
    if err != nil {
        return nil, err
    }
    defer c.Close()

    var all []*resourcemanagerpb.Folder
    it := c.ListFolders(ctx, &resourcemanagerpb.ListFoldersRequest{Parent: parent})
    for {
        f, err := it.Next()
        if errors.Is(err, iterator.Done) {
            break
        }
        if err != nil {
            return nil, err
        }
        all = append(all, f)
        // Recurse into sub-folders
        sub, err := ListFolders(ctx, f.GetName(), copts)
        if err == nil {
            all = append(all, sub...)
        }
    }
    return all, nil
}
```

---

## Universal Pagination Pattern

Every GCP Go client uses iterators. The pattern is identical across all APIs:

```go
it := client.List(ctx, req)
for {
    item, err := it.Next()
    if errors.Is(err, iterator.Done) { break }
    if err != nil {
        return handleGCPError("listing X", err)
    }
    process(item)
}
```

**Never** manage page tokens manually. The iterator handles them internally.

---

## Rate Limiting & Quota Management

GCP enforces quotas per (project, API). Use a `rate.Limiter` per project to avoid 429s.

```go
// internal/gcp/ratelimit.go

import "golang.org/x/time/rate"

type ProjectLimiter struct {
    mu       sync.Mutex
    limiters map[string]*rate.Limiter
}

func (pl *ProjectLimiter) Get(projectID string) *rate.Limiter {
    pl.mu.Lock()
    defer pl.mu.Unlock()
    if l, ok := pl.limiters[projectID]; ok {
        return l
    }
    l := rate.NewLimiter(rate.Every(200*time.Millisecond), 5) // 5 req/200ms burst
    pl.limiters[projectID] = l
    return l
}

// Retry with backoff for ResourceExhausted (429) and Unavailable (503):
func callWithRetry(ctx context.Context, fn func() error) error {
    backoff := 500 * time.Millisecond
    for attempt := 0; attempt < 5; attempt++ {
        err := fn()
        if err == nil { return nil }

        st, ok := status.FromError(err)
        if !ok { return err }

        switch st.Code() {
        case codes.ResourceExhausted, codes.Unavailable:
            select {
            case <-ctx.Done(): return ctx.Err()
            case <-time.After(backoff):
                backoff = min(backoff*2, 30*time.Second)
            }
        case codes.PermissionDenied, codes.NotFound:
            // Log warning, return nil — do not abort the scan
            slog.Warn("gcp permission denied or not found, skipping",
                "code", st.Code(), "msg", st.Message())
            return nil
        case codes.FailedPrecondition:
            // API not enabled on this project — log and skip
            slog.Warn("gcp api not enabled on project, skipping",
                "msg", st.Message())
            return nil
        default:
            return err
        }
    }
    return fmt.Errorf("gcp: max retries exceeded")
}
```

---

## Resource Enumeration Targets

### Compute Engine — VM Instances
```go
// Use AggregatedList to get all instances across all zones in a single paginated call.
// Do NOT loop over zones manually.
client, _ := compute.NewInstancesRESTClient(ctx, copts...)
it := client.AggregatedList(ctx, &computepb.AggregatedListInstancesRequest{
    Project: projectID,
})
// Key security fields:
// - networkInterfaces[].accessConfigs[].natIP  → has public IP?
// - serviceAccounts[].email → what SA is attached?
// - shieldedInstanceConfig.enableSecureBoot → Shielded VM enabled?
// - metadata.items: look for "serial-port-enable" = "1" (dangerous)
// - labels: for context (env, team, owner)
```

### Compute Engine — Firewall Rules
```go
// CRITICAL security signal: rules with sourceRanges containing 0.0.0.0/0 or ::/0
client, _ := compute.NewFirewallsRESTClient(ctx, copts...)
it := client.List(ctx, &computepb.ListFirewallsRequest{Project: projectID})
// For each rule:
// - Skip if direction != "INGRESS" or disabled == true
// - Flag CRITICAL if sourceRanges has "0.0.0.0/0" or "::/0"
// - Correlate targetTags / targetServiceAccounts with VM instances
// - List ports: sensitive ones (22, 3389, 5432, 3306, 27017, 6379)
```

### Cloud Storage — Buckets
```go
client, _ := storage.NewClient(ctx, copts...)
it := client.Buckets(ctx, projectID)
// For each bucket:
// 1. Check IAM policy: allUsers or allAuthenticatedUsers in any binding = HIGH
// 2. Check UniformBucketLevelAccess: if disabled, ACLs may expose objects
// 3. Check RetentionPolicy: absence may allow deletion of audit logs
// 4. Check publicAccessPrevention: if "inherited" and org policy not set = risk
policy, _ := client.Bucket(name).IAM().Policy(ctx)
for _, b := range policy.InternalProto().GetBindings() {
    for _, m := range b.GetMembers() {
        if m == "allUsers" || m == "allAuthenticatedUsers" { /* flag */ }
    }
}
```

### GKE — Clusters
```go
client, _ := container.NewClusterManagerClient(ctx, copts...)
resp, _ := client.ListClusters(ctx, &containerpb.ListClustersRequest{
    Parent: fmt.Sprintf("projects/%s/locations/-", projectID), // "-" = all locations
})
// Security checks per cluster:
// - masterAuthorizedNetworksConfig.enabled = false → API server open to world
// - legacyAbac.enabled = true → deprecated, insecure authorization
// - networkPolicy == nil → no network policy = unrestricted pod-to-pod traffic
// - nodePools[].config.oauthScopes contains "cloud-platform" → overly broad scope
// - privateClusterConfig.enablePrivateNodes = false → nodes have public IPs
```

### Cloud Run — Services
```go
client, _ := run.NewServicesClient(ctx, copts...)
it := client.ListServices(ctx, &runpb.ListServicesRequest{
    Parent: fmt.Sprintf("projects/%s/locations/-", projectID),
})
// Security checks:
// - ingress == "all" AND IAM policy has allUsers invoker = publicly accessible without auth
// - Get IAM policy: runpb service IAM via resourcemanager or REST
```

### Cloud SQL — Instances
```go
sqlService, _ := sqladmin.NewService(ctx, copts...)
resp, _ := sqlService.Instances.List(projectID).Context(ctx).Do()
// Security checks per instance:
// - settings.ipConfiguration.authorizedNetworks has entry with value "0.0.0.0/0" = CRITICAL
// - settings.ipConfiguration.requireSsl = false → unencrypted connections allowed
// - settings.backupConfiguration.enabled = false → no backups
// - databaseFlags: check for dangerous flags (log_checkpoints=off, etc.)
```

### IAM — Service Accounts & Org Bindings
```go
iamService, _ := iam.NewService(ctx, copts...)
// List all service accounts in project:
resp, _ := iamService.Projects.ServiceAccounts.List("projects/" + projectID).
    Context(ctx).Do()
// Flag: SA with keys older than 90 days
// Flag: SA with Editor or Owner role at project level

// Get project-level IAM policy:
crmService, _ := cloudresourcemanager.NewService(ctx, copts...)
policy, _ := crmService.Projects.GetIamPolicy(projectID,
    &crmv3.GetIamPolicyRequest{}).Context(ctx).Do()
// Flag: role "roles/owner" or "roles/editor" granted to a user (not a group)
// Flag: external accounts (outside org domain) with any role
// Flag: allUsers or allAuthenticatedUsers in any binding
```

---

## Concurrency Model

```go
// internal/gcp/scanner.go

func (s *GCPScanner) ScanProjects(ctx context.Context,
    projects []string, events chan<- ui.ScanEvent) error {
    eg, ctx := errgroup.WithContext(ctx)

    for _, proj := range projects {
        proj := proj
        s.sem <- struct{}{} // max concurrent projects
        eg.Go(func() error {
            defer func() { <-s.sem }()
            return s.scanProject(ctx, proj, events)
        })
    }
    return eg.Wait()
}

func (s *GCPScanner) scanProject(ctx context.Context,
    projectID string, events chan<- ui.ScanEvent) error {
    eg, ctx := errgroup.WithContext(ctx)

    // All resource types scan in parallel within a project
    eg.Go(func() error { return s.scanFirewalls(ctx, projectID, events) })
    eg.Go(func() error { return s.scanInstances(ctx, projectID, events) })
    eg.Go(func() error { return s.scanBuckets(ctx, projectID, events) })
    eg.Go(func() error { return s.scanGKE(ctx, projectID, events) })
    eg.Go(func() error { return s.scanCloudRun(ctx, projectID, events) })
    eg.Go(func() error { return s.scanIAM(ctx, projectID, events) })

    return eg.Wait()
}
```

---

## Anti-Patterns — NEVER DO THIS

- **NEVER** manage page tokens manually. Use `it.Next()` and `iterator.Done`. Always.
- **NEVER** abort the scan on `codes.PermissionDenied`. One project without access
  is expected in large orgs. Log a warning and skip.
- **NEVER** ignore `codes.FailedPrecondition` — it means the API (e.g., Compute Engine API)
  is not enabled on that project. Log a warning and skip the resource type for that project.
- **NEVER** use a single `rate.Limiter` globally. GCP quotas are per-project, per-API.
- **NEVER** call `log.Printf("%+v", gcpConfig)` or print raw client options — they may contain
  token sources that expose credentials.
- **NEVER** list zones manually and loop over them for Compute instances.
  Use `AggregatedList` with location `-` to get all zones in a single paginated call.
- **NEVER** hardcode project IDs. Accept them via `--projects` flag or discover via org traversal.
