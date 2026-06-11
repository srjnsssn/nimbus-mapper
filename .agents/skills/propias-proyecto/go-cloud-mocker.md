---
name: go-cloud-mocker
description: >
  Standards for writing unit and integration tests in Nimbus Mapper that mock AWS, GCP,
  and Azure cloud APIs. Covers interface wrapping patterns, manual mock structs, table-driven
  tests, edge case simulation (429, 403, partial failures, empty responses), localstack usage
  for AWS, fake GCP servers, and CI/CD requirements. Zero live cloud credentials required
  to pass the test suite.
triggers:
  - "when writing any test that involves a cloud provider SDK client"
  - "when creating or modifying mock implementations of cloud APIs"
  - "when testing AWS, GCP, or Azure extraction logic"
  - "when simulating rate limiting, permission errors, or API failures"
  - "when setting up CI/CD to run tests without cloud credentials"
  - "when a function directly accepts an AWS/GCP/Azure SDK client (it should accept an interface)"
  - "when writing table-driven tests for scanner logic"
---

# Skill: go-cloud-mocker

## Core Philosophy

**Every test in Nimbus Mapper must pass on a machine with no internet access and no cloud credentials.**

This is enforced in CI by setting `AWS_DEFAULT_REGION=us-east-1` with no actual credentials,
and by blocking outbound network access during `go test`. A test that fails without credentials
is a test that was written incorrectly.

This constraint exists because:
1. Cloud API calls in tests are slow (100ms–2s each), making the test suite painful to run.
2. Live credentials in CI are a security risk.
3. Tests that hit real APIs are flaky (network, quota, resource state).
4. Test infrastructure should cost $0 to run.

---

## The Interface Wrapping Pattern

**Never** pass a raw AWS/GCP/Azure SDK client to a function. Always extract an interface
containing only the methods that function actually calls. This makes the function testable
without any mock framework.

### AWS Example

```go
// internal/aws/instances.go

// WRONG — takes the concrete SDK client, untestable without live AWS
func ScanInstances(ctx context.Context, client *ec2.Client, region string) ([]model.NimbusNode, error) {
    // ...
}

// CORRECT — takes a minimal interface, fully mockable
type DescribeInstancesAPI interface {
    DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput,
        optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

func ScanInstances(ctx context.Context, client DescribeInstancesAPI,
    region string) ([]model.NimbusNode, error) {
    // same logic, now testable with any struct implementing the interface
}

// Production usage: ec2.Client satisfies DescribeInstancesAPI automatically
realClient := ec2.NewFromConfig(cfg)
nodes, err := ScanInstances(ctx, realClient, "us-east-1")
```

### GCP Example

```go
// internal/gcp/firewalls.go

// Define only the GCP iterator behavior we need
type FirewallIterator interface {
    Next() (*computepb.Firewall, error)
}

type FirewallsAPI interface {
    List(ctx context.Context, req *computepb.ListFirewallsRequest,
        opts ...gax.CallOption) FirewallIterator
}

func ScanFirewalls(ctx context.Context, client FirewallsAPI,
    projectID string) ([]model.Finding, error) {
    it := client.List(ctx, &computepb.ListFirewallsRequest{Project: projectID})
    for {
        fw, err := it.Next()
        if errors.Is(err, iterator.Done) { break }
        if err != nil { return nil, err }
        // evaluate firewall rule...
    }
    return findings, nil
}
```

### Azure Example

```go
// internal/azure/nsg.go

type NSGListPager interface {
    More() bool
    NextPage(ctx context.Context) (armnetwork.SecurityGroupsClientListAllResponse, error)
}

type NSGsAPI interface {
    NewListAllPager(options *armnetwork.SecurityGroupsClientListAllOptions) NSGListPager
}

func ScanNSGs(ctx context.Context, client NSGsAPI,
    subscriptionID string) ([]model.Finding, error) {
    pager := client.NewListAllPager(nil)
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil { return nil, err }
        for _, nsg := range page.Value {
            // evaluate NSG rules...
        }
    }
    return findings, nil
}
```

---

## Manual Mock Structs

Prefer manual mocks over code-generation frameworks (mockery, gomock).
Manual mocks are explicit, easy to read, and require no tooling:

```go
// internal/aws/testdata/mocks.go (or internal/aws/scanner_test.go for small mocks)

// mockEC2Client implements DescribeInstancesAPI for tests
type mockEC2Client struct {
    // Fields control what the mock returns
    instances  []ec2Types.Reservation
    err        error
    callCount  int // assert it was called the expected number of times
}

func (m *mockEC2Client) DescribeInstances(ctx context.Context,
    params *ec2.DescribeInstancesInput,
    _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
    m.callCount++
    if m.err != nil {
        return nil, m.err
    }
    return &ec2.DescribeInstancesOutput{Reservations: m.instances}, nil
}

// mockFirewallsClient implements FirewallsAPI for GCP firewall tests
type mockFirewallsClient struct {
    rules []*computepb.Firewall
    err   error
}

func (m *mockFirewallsClient) List(_ context.Context,
    _ *computepb.ListFirewallsRequest,
    _ ...gax.CallOption) FirewallIterator {
    return &mockFirewallIterator{rules: m.rules, err: m.err}
}

type mockFirewallIterator struct {
    rules []*computepb.Firewall
    pos   int
    err   error
}

func (it *mockFirewallIterator) Next() (*computepb.Firewall, error) {
    if it.err != nil { return nil, it.err }
    if it.pos >= len(it.rules) { return nil, iterator.Done }
    fw := it.rules[it.pos]
    it.pos++
    return fw, nil
}
```

---

## Table-Driven Tests

All scanner tests must be table-driven. This makes it trivial to add edge cases:

```go
// internal/aws/instances_test.go

func TestScanInstances(t *testing.T) {
    tests := []struct {
        name           string
        instances      []ec2Types.Reservation
        apiErr         error
        wantNodes      int
        wantFindings   int
        wantErr        bool
    }{
        {
            name:      "single running instance without public IP",
            instances: []ec2Types.Reservation{{
                Instances: []ec2Types.Instance{{
                    InstanceId: aws.String("i-0000000000000001"),
                    State:      &ec2Types.InstanceState{Name: ec2Types.InstanceStateNameRunning},
                    // No public IP
                }},
            }},
            wantNodes:    1,
            wantFindings: 0,
        },
        {
            name: "instance with public IP and open SSH security group",
            instances: []ec2Types.Reservation{{
                Instances: []ec2Types.Instance{{
                    InstanceId: aws.String("i-0000000000000002"),
                    NetworkInterfaces: []ec2Types.InstanceNetworkInterface{{
                        Association: &ec2Types.InstanceNetworkInterfaceAssociation{
                            PublicIp: aws.String("1.2.3.4"),
                        },
                    }},
                    SecurityGroups: []ec2Types.GroupIdentifier{{
                        GroupId: aws.String("sg-exposed"),
                    }},
                }},
            }},
            wantNodes:    1,
            wantFindings: 1, // SG with 0.0.0.0/0:22 should be a finding
        },
        {
            name:    "API returns 403 AccessDenied",
            apiErr:  &smithy.GenericAPIError{Code: "AccessDenied", Message: "Access denied"},
            wantErr: false, // 403 should NOT propagate — scanner logs and returns nil
            wantNodes: 0,
        },
        {
            name:    "API returns 429 rate limited",
            apiErr:  &smithy.GenericAPIError{Code: "RequestLimitExceeded", Message: "Too many requests"},
            wantErr: true, // 429 after retries exhausted SHOULD propagate
        },
        {
            name:      "empty response — no instances in region",
            instances: []ec2Types.Reservation{},
            wantNodes: 0,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            mock := &mockEC2Client{instances: tt.instances, err: tt.apiErr}
            nodes, err := ScanInstances(context.Background(), mock, "us-east-1")

            if tt.wantErr {
                require.Error(t, err)
            } else {
                require.NoError(t, err)
            }
            assert.Len(t, nodes, tt.wantNodes)

            var findings int
            for _, n := range nodes { findings += len(n.Findings) }
            assert.Equal(t, tt.wantFindings, findings)
        })
    }
}
```

---

## Mandatory Edge Cases

Every scanner function must have test cases covering ALL of these:

```go
// Edge case checklist — add a test for each:

// 1. Empty response (region/project has no resources of this type)
//    Expected: no findings, no error, 0 nodes returned

// 2. Single resource, compliant (no misconfiguration)
//    Expected: 1 node, ExposureLevel=Safe, 0 findings

// 3. Single resource, non-compliant (has a misconfiguration)
//    Expected: 1 node, ExposureLevel=Critical/Warning, >= 1 finding

// 4. HTTP 403 / PermissionDenied / AccessDenied
//    Expected: no error returned (logged as WARN), 0 nodes

// 5. HTTP 429 / ResourceExhausted / RequestLimitExceeded
//    Expected: error returned after retries exhausted

// 6. Context cancelled mid-scan
//    Expected: function returns ctx.Err(), no panic

// 7. Pagination — more than one page of results
//    Expected: all pages processed, total count matches mock data

// 8. API-not-enabled (GCP: FailedPrecondition)
//    Expected: no error returned (logged as WARN), 0 nodes

// 9. Large response — 1000+ resources
//    Expected: all processed without memory issues, test completes < 100ms
```

---

## Context Cancellation Tests

```go
func TestScanInstancesCancellation(t *testing.T) {
    // Create a context that's already cancelled
    ctx, cancel := context.WithCancel(context.Background())
    cancel() // cancel immediately

    // Mock that would block if context isn't respected
    mock := &mockEC2Client{
        instances: makeLotsOfInstances(1000),
    }

    _, err := ScanInstances(ctx, mock, "us-east-1")
    // Should return quickly without processing all 1000 instances
    assert.ErrorIs(t, err, context.Canceled)
}
```

---

## LocalStack for AWS Integration Tests (Optional)

For integration tests that test the full AWS scan flow end-to-end,
use LocalStack (a local AWS mock server). These tests are tagged `//go:build integration`:

```go
//go:build integration
// +build integration

// Run with: go test -tags=integration ./...
// Requires: docker run -p 4566:4566 localstack/localstack

func TestFullAWSScan_LocalStack(t *testing.T) {
    // Point SDK to localstack
    cfg, _ := config.LoadDefaultConfig(context.Background(),
        config.WithRegion("us-east-1"),
        config.WithEndpointResolverWithOptions(
            aws.EndpointResolverWithOptionsFunc(func(service, region string, _ ...interface{}) (aws.Endpoint, error) {
                return aws.Endpoint{URL: "http://localhost:4566"}, nil
            }),
        ),
        config.WithCredentialsProvider(
            credentials.NewStaticCredentialsProvider("test", "test", "test"),
        ),
    )

    // Set up test resources in localstack, then run scanner...
}
```

Integration tests are **never** run in standard CI. They require a separate `make test-integration`
target and a Docker environment.

---

## Test Helpers

```go
// internal/testutil/helpers.go

package testutil

import (
    "github.com/aws/aws-sdk-go-v2/aws"
    ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// MakeEC2Instance creates a test EC2 instance with sensible defaults.
// Override fields as needed in tests.
func MakeEC2Instance(opts ...func(*ec2Types.Instance)) ec2Types.Instance {
    inst := ec2Types.Instance{
        InstanceId:   aws.String("i-test-" + randomHex(8)),
        InstanceType: ec2Types.InstanceTypeT3Micro,
        State:        &ec2Types.InstanceState{Name: ec2Types.InstanceStateNameRunning},
    }
    for _, opt := range opts {
        opt(&inst)
    }
    return inst
}

// WithPublicIP is a functional option for MakeEC2Instance
func WithPublicIP(ip string) func(*ec2Types.Instance) {
    return func(i *ec2Types.Instance) {
        i.NetworkInterfaces = []ec2Types.InstanceNetworkInterface{{
            Association: &ec2Types.InstanceNetworkInterfaceAssociation{
                PublicIp: aws.String(ip),
            },
        }}
    }
}

// AssertFindingExists checks that a specific rule fired in a finding list
func AssertFindingExists(t *testing.T, findings []model.Finding, ruleID string) {
    t.Helper()
    for _, f := range findings {
        if f.RuleID == ruleID { return }
    }
    t.Errorf("expected finding with RuleID=%q but none found in %v",
        ruleID, findingRuleIDs(findings))
}

func AssertNoFindings(t *testing.T, findings []model.Finding) {
    t.Helper()
    if len(findings) > 0 {
        t.Errorf("expected 0 findings but got %d: %v",
            len(findings), findingRuleIDs(findings))
    }
}
```

---

## CI Configuration

```yaml
# .github/workflows/test.yml

- name: Run unit tests (no cloud credentials needed)
  run: go test -race -count=1 ./...
  env:
    # These env vars exist but point to nothing — ensures no accidental live calls
    AWS_DEFAULT_REGION: us-east-1
    AWS_ACCESS_KEY_ID: test
    AWS_SECRET_ACCESS_KEY: test
    # GCP: no GOOGLE_APPLICATION_CREDENTIALS set → ADC will fail → tests must not use ADC
    # Azure: no AZURE_* vars → DefaultAzureCredential will fail → tests must not use it
```

---

## Anti-Patterns — NEVER DO THIS

- **NEVER** pass `ec2.Client`, `compute.InstancesClient`, or `armcompute.VirtualMachinesClient`
  directly to scanner functions. Always wrap behind an interface.
- **NEVER** call `config.LoadDefaultConfig` in a test. Tests must not touch the credential chain.
- **NEVER** write a test that skips if `AWS_ACCESS_KEY_ID` is not set:
  `if os.Getenv("AWS_ACCESS_KEY_ID") == "" { t.Skip() }`. That is an integration test
  masquerading as a unit test. Put it behind `//go:build integration`.
- **NEVER** use `t.Parallel()` in tests that share mutable global state (e.g., global slog logger
  replaced in `TestMain`). Always initialize test-local loggers.
- **NEVER** assert on error message strings: `assert.Equal(t, "some AWS error text", err.Error())`.
  AWS error messages change. Assert on error types or codes: `errors.As(err, &apiErr)`.
- **NEVER** write a test with a single happy-path case. Every function needs at least the
  empty-response and 403-PermissionDenied cases covered.
- **NEVER** name mock files `mock_*.go` without a build tag if they import SDK packages —
  they will be compiled into the production binary.
