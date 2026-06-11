---
name: aws-sdk-go-v2
description: >
  Complete standards for all AWS API interactions in Nimbus Mapper using aws-sdk-go-v2.
  Covers credential chain, multi-region and multi-account traversal, pagination patterns,
  rate limiting with exponential backoff, resource enumeration targets (EC2, VPC, S3, IAM,
  RDS, Lambda, ELB), and the normalized NimbusNode output model.
triggers:
  - "when writing or modifying any AWS extraction logic"
  - "when querying EC2, VPC, S3, IAM, RDS, Lambda, ELB, or any AWS service"
  - "when configuring AWS authentication or credentials"
  - "when handling AWS pagination or API throttling"
  - "when writing multi-region or multi-account scan logic"
  - "when mocking AWS in tests"
---

# Skill: aws-sdk-go-v2

## Project Context

Nimbus Mapper scans AWS environments for security misconfigurations. AWS is commonly the
largest provider in enterprise environments — production accounts can have 20+ regions active,
hundreds of VPCs, and thousands of EC2 instances. The extractor must be:
- **Concurrent**: scan multiple regions in parallel, multiple resource types per region in parallel.
- **Safe**: read-only by design, never modify any resource.
- **Resilient**: handle throttling, partial failures, and missing permissions without aborting.
- **Complete**: enumerate all resource types relevant to the `cloud-misconfiguration-rules` skill.

---

## SDK Version

**Always use `github.com/aws/aws-sdk-go-v2`.** Never use v1 (`github.com/aws/aws-sdk-go`).
The v1 SDK is deprecated. All patterns in this skill are v2-specific.

```
go get github.com/aws/aws-sdk-go-v2
go get github.com/aws/aws-sdk-go-v2/config
go get github.com/aws/aws-sdk-go-v2/service/ec2
go get github.com/aws/aws-sdk-go-v2/service/s3
go get github.com/aws/aws-sdk-go-v2/service/iam
go get github.com/aws/aws-sdk-go-v2/service/rds
go get github.com/aws/aws-sdk-go-v2/service/lambda
go get github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2
go get github.com/aws/aws-sdk-go-v2/service/organizations
go get github.com/aws/aws-sdk-go-v2/credentials/stscreds
```

---

## Authentication: Credential Chain

**Never prompt the user for credentials. Never accept hardcoded keys.**
Use `config.LoadDefaultConfig` which resolves credentials in this order automatically:

1. `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` environment variables
2. `~/.aws/credentials` file (named profiles via `--profile` flag)
3. IAM Instance Profile (if running on EC2)
4. ECS task role (if running in ECS)
5. Assume Role via `--role-arn` flag (for cross-account scanning)

```go
// internal/aws/client.go

package aws

import (
    "context"
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/credentials/stscreds"
    "github.com/aws/aws-sdk-go-v2/service/sts"
)

type ClientConfig struct {
    Profile  string // --profile flag
    Region   string
    RoleARN  string // --role-arn flag for cross-account
    RoleSessionName string
}

func NewConfig(ctx context.Context, cfg ClientConfig) (aws.Config, error) {
    opts := []func(*config.LoadOptions) error{
        config.WithRegion(cfg.Region),
    }
    if cfg.Profile != "" {
        opts = append(opts, config.WithSharedConfigProfile(cfg.Profile))
    }

    baseCfg, err := config.LoadDefaultConfig(ctx, opts...)
    if err != nil {
        return aws.Config{}, fmt.Errorf("loading AWS config: %w", err)
    }

    // Assume role for cross-account scanning
    if cfg.RoleARN != "" {
        stsClient := sts.NewFromConfig(baseCfg)
        provider := stscreds.NewAssumeRoleProvider(stsClient, cfg.RoleARN,
            func(o *stscreds.AssumeRoleOptions) {
                o.RoleSessionName = cfg.RoleSessionName
                if o.RoleSessionName == "" {
                    o.RoleSessionName = "nimbus-mapper-scan"
                }
            },
        )
        baseCfg.Credentials = aws.NewCredentialsCache(provider)
    }

    return baseCfg, nil
}
```

---

## Multi-Account Traversal via AWS Organizations

For enterprise scanning, enumerate all accounts in the organization:

```go
// internal/aws/org.go

func ListOrganizationAccounts(ctx context.Context, cfg aws.Config) ([]string, error) {
    client := organizations.NewFromConfig(cfg)
    var accountIDs []string

    paginator := organizations.NewListAccountsPaginator(client,
        &organizations.ListAccountsInput{})
    for paginator.HasMorePages() {
        page, err := paginator.NextPage(ctx)
        if err != nil {
            return nil, fmt.Errorf("listing org accounts: %w", err)
        }
        for _, acct := range page.Accounts {
            if acct.Status == orgTypes.AccountStatusActive {
                accountIDs = append(accountIDs, aws.ToString(acct.Id))
            }
        }
    }
    return accountIDs, nil
}
```

For each account, call `NewConfig` with a role ARN like:
`arn:aws:iam::{accountID}:role/NimbusReadOnlyRole`

---

## Multi-Region Discovery

Never hardcode a list of regions. Discover active regions dynamically:

```go
// internal/aws/regions.go

func ListActiveRegions(ctx context.Context, cfg aws.Config) ([]string, error) {
    // Use EC2 DescribeRegions with the base config (us-east-1 as anchor)
    anchorCfg := cfg.Copy()
    anchorCfg.Region = "us-east-1"

    client := ec2.NewFromConfig(anchorCfg)
    resp, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
        Filters: []ec2Types.Filter{{
            Name:   aws.String("opt-in-status"),
            Values: []string{"opt-in-not-required", "opted-in"},
        }},
        AllRegions: aws.Bool(false), // only regions the account has opted into
    })
    if err != nil {
        return nil, err
    }

    regions := make([]string, len(resp.Regions))
    for i, r := range resp.Regions {
        regions[i] = aws.ToString(r.RegionName)
    }
    return regions, nil
}
```

---

## Pagination Pattern

**Always use paginators.** Never assume a single API call returns all results.
AWS returns max 100–1000 items per page depending on the API.

```go
// Correct pattern for ANY paginated AWS API
paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{
    // Optional filters
    Filters: []ec2Types.Filter{{
        Name:   aws.String("instance-state-name"),
        Values: []string{"running", "stopped"},
    }},
})

for paginator.HasMorePages() {
    page, err := paginator.NextPage(ctx)
    if err != nil {
        return handleAWSError(err) // see error handling section
    }
    for _, reservation := range page.Reservations {
        for _, instance := range reservation.Instances {
            process(instance)
        }
    }
}
```

---

## Rate Limiting & Exponential Backoff

GCP has quota per project; AWS has per-account per-region API rate limits.
Handle `RequestLimitExceeded` and `Throttling` errors with backoff:

```go
// internal/aws/retry.go

import (
    "github.com/aws/aws-sdk-go-v2/aws/retry"
    smithy "github.com/aws/smithy-go"
)

// Attach to any client:
cfg.Retryer = func() aws.Retryer {
    return retry.NewAdaptiveMode(func(o *retry.AdaptiveModeOptions) {
        o.StandardOptions = append(o.StandardOptions,
            retry.WithMaxAttempts(5),
            retry.WithMaxBackoff(30*time.Second),
        )
    })
}

// Manual check for non-retryable permission errors:
func handleAWSError(err error) error {
    var ae smithy.APIError
    if errors.As(err, &ae) {
        switch ae.ErrorCode() {
        case "AccessDenied", "UnauthorizedOperation":
            // Log warning, return nil — missing permissions on one resource
            // should not abort the entire scan
            slog.Warn("permission denied, skipping", "code", ae.ErrorCode(), "msg", ae.ErrorMessage())
            return nil
        }
    }
    return err
}
```

---

## Resource Enumeration Targets

### EC2 Instances
```go
// Key fields to extract for security analysis:
// - InstanceId, InstanceType, State
// - NetworkInterfaces[].Association.PublicIp (exposed publicly?)
// - SecurityGroups[].GroupId (cross-reference with SG rules)
// - IamInstanceProfile.Arn (what permissions does this instance have?)
// - MetadataOptions.HttpTokens ("optional" = IMDSv1 vuln, should be "required")
// - Tags (for context: Name, Environment, Owner)
```

### Security Groups (critical for misconfiguration rules)
```go
paginator := ec2.NewDescribeSecurityGroupsPaginator(client,
    &ec2.DescribeSecurityGroupsInput{})
// For each SG, inspect IpPermissions (inbound rules):
// Flag if IpRanges contains "0.0.0.0/0" OR Ipv6Ranges contains "::/0"
// Cross with sensitive ports: 22 (SSH), 3389 (RDP), 5432 (Postgres),
//   3306 (MySQL), 27017 (MongoDB), 6379 (Redis), 9200 (Elasticsearch)
```

### S3 Buckets
```go
// s3.ListBuckets is not paginated and returns ALL buckets in account
resp, _ := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
// For each bucket: check GetBucketAcl, GetBucketPolicy, GetPublicAccessBlock
// A bucket is "exposed" if PublicAccessBlockConfiguration has any field = false
// AND the ACL or policy grants s3:GetObject to "*"
```

### IAM (use global us-east-1 client — IAM is not regional)
```go
// Enumerate: roles, policies attached to roles, users, groups
// Flag: AdministratorAccess policy attached to EC2 instance profile
// Flag: inline policies with "Effect":"Allow","Action":"*","Resource":"*"
// Use IAM Access Analyzer findings as additional signal
```

### RDS Instances
```go
// Flag: PubliclyAccessible = true
// Flag: StorageEncrypted = false
// Flag: MultiAZ = false (not a security issue but useful context)
// Flag: DeletionProtection = false
// Check associated VPC security groups (same SG rules logic as EC2)
```

### Lambda Functions
```go
// Flag: functions with resource-based policies granting invoke to "*"
// Flag: functions using runtime versions that are deprecated
// Check: environment variables for hardcoded secrets (scan for key patterns)
```

### ELBv2 (ALB/NLB)
```go
// Flag: listeners on HTTP (port 80) without redirect to HTTPS
// Flag: security policies using old TLS versions (TLS 1.0, 1.1)
// Check: associated target groups → linked instances
```

---

## NimbusNode Output Model

After extraction, normalize all AWS resources to the shared schema:

```go
// internal/model/node.go (shared across providers)

type NimbusNode struct {
    ID           string            // Provider-native ID: "i-0a1b2c3d", "sg-xxx", "arn:..."
    Type         string            // "ec2_instance" | "security_group" | "s3_bucket" | ...
    Provider     string            // "aws"
    AccountID    string
    Region       string
    Name         string            // From Name tag or resource name
    PublicIP     string            // Empty if not internet-facing
    PrivateIP    string
    Subnet       string            // VPC subnet CIDR or ID
    AttachedRules []string         // Security Group IDs or Firewall rule names
    IAMRole      string            // Instance profile ARN or service role
    Tags         map[string]string
    ExposureLevel ExposureLevel    // Injected by cloud-misconfiguration-rules skill
    RawMetadata  json.RawMessage   // Full provider-specific struct for deep analysis
}
```

---

## Concurrency Model for AWS

```go
// internal/aws/scanner.go

type AWSScanner struct {
    sem     chan struct{} // semaphore: max concurrent region scans
    limiter *rate.Limiter
}

func NewAWSScanner(maxConcurrent int) *AWSScanner {
    return &AWSScanner{
        sem:     make(chan struct{}, maxConcurrent),
        limiter: rate.NewLimiter(rate.Every(100*time.Millisecond), 10),
    }
}

func (s *AWSScanner) ScanAllRegions(ctx context.Context, regions []string,
    cfg aws.Config, events chan<- ui.ScanEvent) error {
    eg, ctx := errgroup.WithContext(ctx)

    for _, region := range regions {
        region := region
        s.sem <- struct{}{} // acquire slot
        eg.Go(func() error {
            defer func() { <-s.sem }()
            regionalCfg := cfg.Copy()
            regionalCfg.Region = region
            return s.scanRegion(ctx, region, regionalCfg, events)
        })
    }
    return eg.Wait()
}

func (s *AWSScanner) scanRegion(ctx context.Context, region string,
    cfg aws.Config, events chan<- ui.ScanEvent) error {
    eg, ctx := errgroup.WithContext(ctx)

    // Scan all resource types concurrently within the region
    ec2Client := ec2.NewFromConfig(cfg)
    eg.Go(func() error { return s.scanInstances(ctx, region, ec2Client, events) })
    eg.Go(func() error { return s.scanSecurityGroups(ctx, region, ec2Client, events) })
    eg.Go(func() error { return s.scanVPCs(ctx, region, ec2Client, events) })

    s3Client := s3.NewFromConfig(cfg)
    eg.Go(func() error { return s.scanBuckets(ctx, region, s3Client, events) })

    return eg.Wait()
}
```

---

## Testing: Always Mock, Never Hit Live AWS

```go
// internal/aws/scanner_test.go

// Define an interface matching the EC2 methods you use:
type EC2DescribeInstancesAPI interface {
    DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput,
        optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

// Mock implementation for tests:
type mockEC2Client struct {
    instances []ec2Types.Instance
}

func (m *mockEC2Client) DescribeInstances(ctx context.Context,
    params *ec2.DescribeInstancesInput,
    _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
    return &ec2.DescribeInstancesOutput{
        Reservations: []ec2Types.Reservation{{Instances: m.instances}},
    }, nil
}

// Test:
func TestScanInstancesDetectsPublicIP(t *testing.T) {
    mock := &mockEC2Client{instances: []ec2Types.Instance{
        {InstanceId: aws.String("i-test"),
         NetworkInterfaces: []ec2Types.InstanceNetworkInterface{{
             Association: &ec2Types.InstanceNetworkInterfaceAssociation{
                 PublicIp: aws.String("1.2.3.4"),
             },
         }}},
    }}
    // ... assert finding is emitted
}
```

---

## Anti-Patterns — NEVER DO THIS

- **NEVER** import `github.com/aws/aws-sdk-go` (v1). Check go.mod after any `go get`.
- **NEVER** call a single non-paginated API and assume all results fit in one response.
  Example: `DescribeInstances` without a paginator silently drops results in large accounts.
- **NEVER** hardcode region lists like `[]string{"us-east-1", "us-west-2"}`.
  Use `ListActiveRegions()` to discover opt-in regions.
- **NEVER** abort the entire scan on `AccessDenied`. Log a warning and continue.
  Partial results are far more useful than a crashed scan.
- **NEVER** log the full `aws.Config` struct — it contains the resolved credentials.
- **NEVER** write tests that require `AWS_ACCESS_KEY_ID` to be set. All tests must use mocks.
- **NEVER** use `os.Getenv("AWS_ACCESS_KEY_ID")` in application code.
  Let `config.LoadDefaultConfig` handle all credential resolution.
