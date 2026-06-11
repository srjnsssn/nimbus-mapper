---
name: cloud-misconfiguration-rules
description: >
  The security evaluation engine for Nimbus Mapper. Defines all detection rules for cloud
  misconfigurations across AWS, GCP, and Azure. Covers network exposure (open ports, public
  IPs), storage exposure (public buckets/blobs), IAM over-privilege (wildcards, admin roles),
  encryption gaps, and the severity model. Defines the Finding and ExposureLevel types.
  Rules are provider-agnostic where possible and provider-specific where required.
triggers:
  - "when implementing or modifying any security detection rule"
  - "when evaluating network exposure of a resource"
  - "when checking IAM policies, roles, or bindings for over-privilege"
  - "when analyzing security groups, NSGs, or firewall rules"
  - "when checking storage (S3, GCS, Azure Blob) for public access"
  - "when calculating or injecting ExposureLevel into a NimbusNode"
  - "when adding a new resource type that needs security evaluation"
  - "when the --blast-radius flag logic needs updating"
---

# Skill: cloud-misconfiguration-rules

## Project Context

Nimbus Mapper is a security scanner, not just a topology mapper. Every enumerated resource
must pass through the misconfiguration rules engine before being emitted as a `NimbusNode`.
The engine injects an `ExposureLevel` field and produces zero or more `Finding` objects
that are sent to the UI via the `ScanEvent` channel.

This skill defines:
1. The canonical `Finding` and `ExposureLevel` data types.
2. All detection rules organized by category.
3. The multi-factor exposure model (a resource is only CRITICAL if multiple conditions align).
4. Rules for what is explicitly NOT a finding (to avoid false positives).

---

## Core Data Types

```go
// internal/model/finding.go

package model

type Severity string

const (
    SeverityCritical Severity = "CRITICAL" // Actively exploitable, immediate action
    SeverityHigh     Severity = "HIGH"     // Significant risk, fix soon
    SeverityMedium   Severity = "MEDIUM"   // Notable misconfiguration, plan fix
    SeverityLow      Severity = "LOW"      // Hygiene issue, informational
    SeverityInfo     Severity = "INFO"     // Context only, not a risk
)

type ExposureLevel string

const (
    ExposureCritical ExposureLevel = "Critical" // Internet-exposed + dangerous rule + sensitive port
    ExposureWarning  ExposureLevel = "Warning"  // Misconfigured but not directly exploitable
    ExposureSafe     ExposureLevel = "Safe"     // No actionable risk detected
)

type Finding struct {
    ID          string            // Deterministic: hash(provider+resourceID+ruleID)
    RuleID      string            // e.g. "AWS-SG-001", "GCP-FW-001", "AZ-NSG-001"
    Severity    Severity
    Provider    string            // "aws" | "gcp" | "azure"
    AccountID   string            // AWS account ID / GCP project ID / Azure subscription ID
    Region      string
    ResourceID  string            // Provider-native ID (ARN, self-link, resource ID)
    ResourceType string           // "security_group" | "firewall_rule" | "storage_bucket" ...
    Title       string            // Short human-readable summary
    Description string            // Detailed explanation of the risk
    Remediation string            // Specific fix instructions for this provider
    References  []string          // CIS benchmark IDs, CVEs, AWS/GCP/Azure docs URLs
    RawEvidence map[string]string // Specific field values that triggered the rule
}
```

---

## Rule Categories

### Category 1: Network Exposure (Highest Priority)

A resource is **CRITICAL** only when ALL of the following are true:
1. A firewall rule / NSG rule / security group allows inbound from `0.0.0.0/0` or `::/0`
2. The affected port is sensitive (see list below)
3. The resource has a public IP OR is in a subnet with an active internet gateway

A resource is **HIGH** when:
- Open to `0.0.0.0/0` on a non-sensitive port (e.g., 80/443)
- OR open to a wide non-RFC1918 CIDR (e.g., `0.0.0.0/0` on any port)

**Sensitive ports:**
```go
var SensitivePorts = map[int]string{
    22:    "SSH",
    23:    "Telnet",
    3389:  "RDP",
    5432:  "PostgreSQL",
    3306:  "MySQL/MariaDB",
    1433:  "MSSQL",
    27017: "MongoDB",
    6379:  "Redis",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch cluster",
    2181:  "ZooKeeper",
    11211: "Memcached",
    5984:  "CouchDB",
    8080:  "HTTP alt (often admin panels)",
    8443:  "HTTPS alt",
    2375:  "Docker daemon (unauthenticated)",
    2376:  "Docker daemon (TLS)",
    10250: "Kubelet API",
    6443:  "Kubernetes API server",
}
```

**AWS-specific rule — SG-001:**
```go
func EvalSecurityGroup(sg ec2Types.SecurityGroup, instance *ec2Types.Instance) []Finding {
    var findings []Finding
    for _, perm := range sg.IpPermissions {
        for _, ipRange := range perm.IpRanges {
            if aws.ToString(ipRange.CidrIp) != "0.0.0.0/0" { continue }
            ports := extractPortRange(perm)
            for _, port := range ports {
                sev := SeverityHigh
                if _, sensitive := SensitivePorts[port]; sensitive {
                    sev = SeverityCritical
                }
                findings = append(findings, Finding{
                    RuleID:       "AWS-SG-001",
                    Severity:     sev,
                    ResourceType: "security_group",
                    Title: fmt.Sprintf("Security Group allows %s from 0.0.0.0/0",
                        SensitivePorts[port]),
                    Remediation: fmt.Sprintf(
                        "Restrict port %d ingress to specific CIDR ranges. "+
                        "See: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html",
                        port),
                    References:  []string{"CIS AWS 5.1", "CIS AWS 5.2"},
                    RawEvidence: map[string]string{
                        "cidr": "0.0.0.0/0",
                        "port": fmt.Sprintf("%d", port),
                        "sg_id": aws.ToString(sg.GroupId),
                    },
                })
            }
        }
    }
    return findings
}
```

**GCP-specific rule — GCP-FW-001:**
```go
func EvalFirewallRule(fw *computepb.Firewall) []Finding {
    if fw.GetDirection() != "INGRESS" || fw.GetDisabled() { return nil }
    for _, src := range fw.GetSourceRanges() {
        if src != "0.0.0.0/0" && src != "::/0" { continue }
        // Exposed — determine severity from allowed ports
        for _, allowed := range fw.GetAllowed() {
            // Finding: GCP-FW-001
        }
    }
    return nil
}
```

---

### Category 2: Storage Exposure

**Rule STOR-001 — Public Storage Bucket/Blob (CRITICAL)**

```go
// Applies to: AWS S3, GCP Cloud Storage, Azure Blob Storage

// AWS S3:
// CRITICAL if: GetPublicAccessBlock returns any field = false
//              AND bucket policy or ACL grants s3:GetObject to "*"
// HIGH if: GetPublicAccessBlock has any field = false (potential, not confirmed)

// GCP Cloud Storage:
// CRITICAL if: IAM binding has member "allUsers" with any storage role
// HIGH if: member is "allAuthenticatedUsers" (any Google account)
// INFO if: uniformBucketLevelAccess is disabled (ACLs possible, check them)

// Azure Blob:
// HIGH if: storageAccount.allowBlobPublicAccess = true
// CRITICAL if: allowBlobPublicAccess = true AND container.publicAccess != "None"

func EvalStorageExposure(bucket StorageBucket) *Finding {
    if !bucket.IsPublic { return nil }
    return &Finding{
        RuleID:      "STOR-001",
        Severity:    SeverityCritical,
        ResourceType: "storage_bucket",
        Title:       fmt.Sprintf("Storage bucket %q is publicly accessible", bucket.Name),
        Description: "The storage bucket allows unauthenticated read access from the internet. " +
                     "Any data in this bucket is potentially exposed.",
        Remediation: storageRemediationByProvider(bucket.Provider),
        References:  []string{"CIS AWS 2.1.5", "CIS GCP 5.1", "CIS Azure 3.7"},
    }
}
```

**Rule STOR-002 — Unencrypted Storage (MEDIUM)**
- AWS: S3 bucket without default encryption (`ServerSideEncryptionConfiguration` absent)
- AWS: EBS volume with `Encrypted = false`
- GCP: Disk without CMEK (Customer-Managed Encryption Key) — only flag in regulated contexts
- Azure: Storage account with `requireInfrastructureEncryption = false`

---

### Category 3: IAM Over-Privilege

**Rule IAM-001 — Wildcard permissions (CRITICAL)**
```go
// AWS: inline or managed policy with:
//   "Effect": "Allow", "Action": "*", "Resource": "*"
// OR: "Action": ["iam:*"], "Action": ["s3:*"] on Resource: "*"
// attached to an EC2 instance profile or Lambda execution role

// GCP: project IAM binding with role "roles/owner" or "roles/editor"
// assigned to a service account attached to a Compute instance

// Azure: role assignment of "Owner" or "Contributor" to a managed identity
// attached to a VM

func EvalIAMPolicy(policy IAMPolicy, attachedTo string) []Finding {
    for _, stmt := range policy.Statements {
        if stmt.Effect != "Allow" { continue }
        if hasWildcardAction(stmt) && hasWildcardResource(stmt) {
            return []Finding{{
                RuleID:      "IAM-001",
                Severity:    SeverityCritical,
                Title:       "Wildcard IAM permissions attached to compute resource",
                Description: fmt.Sprintf(
                    "Resource %s has an IAM policy with Action:* and Resource:*. "+
                    "This grants full access to all AWS services and can be used for "+
                    "privilege escalation and lateral movement.", attachedTo),
                Remediation: "Replace wildcard policies with least-privilege policies " +
                             "scoped to specific actions and resources.",
                References:  []string{"CIS AWS 1.16", "MITRE ATT&CK T1078.004"},
            }}
        }
    }
    return nil
}
```

**Rule IAM-002 — Admin role on compute (HIGH)**
- AWS: `AdministratorAccess` managed policy on EC2 instance profile
- GCP: `roles/owner` or `roles/editor` on SA attached to VM
- Azure: `Owner` role assignment on VM managed identity

**Rule IAM-003 — Cross-account / cross-tenant trust (HIGH)**
- AWS: IAM role trust policy allowing `sts:AssumeRole` from an external account ID
  (not in the organization's account list)
- GCP: Service account key shared with external Workspace domain
- Azure: RBAC assignment to a guest user or external service principal

**Rule IAM-004 — Long-lived service account keys (MEDIUM)**
- GCP: Service account key with `validAfterTime` older than 90 days
- AWS: IAM access key with `CreateDate` older than 90 days and `Status = Active`

---

### Category 4: Encryption in Transit

**Rule TLS-001 — Weak or missing TLS (MEDIUM)**
- AWS RDS: `ca_cert` is `rds-ca-2015` (deprecated)
- AWS ELB: Listener security policy allows TLS 1.0 or 1.1
- Azure SQL: `minimalTlsVersion` != `"1.2"`
- Azure Storage: `minimumTlsVersion` != `"TLS1_2"`
- GCP Cloud SQL: `settings.ipConfiguration.requireSsl = false`

---

### Category 5: Logging & Monitoring Gaps (LOW/INFO)

These are not exploitable directly but are required for incident detection:
- AWS: CloudTrail not enabled in all regions (`IsMultiRegionTrail = false`)
- AWS: S3 bucket access logging disabled
- GCP: Cloud Audit Logs `DATA_READ` / `DATA_WRITE` not enabled for sensitive APIs
- Azure: Diagnostic settings not configured for subscription activity log

Severity: **LOW** unless a compliance framework (PCI-DSS, SOC2) requires them — then **MEDIUM**.

---

## ExposureLevel Injection

After all findings are collected for a resource, compute its overall `ExposureLevel`:

```go
func ComputeExposureLevel(findings []Finding, hasPublicIP bool) ExposureLevel {
    if len(findings) == 0 {
        return ExposureSafe
    }
    for _, f := range findings {
        if f.Severity == SeverityCritical && hasPublicIP {
            return ExposureCritical
        }
    }
    for _, f := range findings {
        if f.Severity == SeverityCritical || f.Severity == SeverityHigh {
            return ExposureWarning
        }
    }
    return ExposureSafe
}
```

---

## Explicit Non-Findings (Avoid False Positives)

The following are intentionally NOT flagged:

```go
var SafeInternalCIDRs = []string{
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10", // Shared address space (RFC 6598)
    "fc00::/7",      // IPv6 ULA
    "fe80::/10",     // IPv6 link-local
}

// A firewall rule allowing 10.0.0.0/8:* is internal VPC traffic — NOT exposed.
// Only flag as exposed if combined with --blast-radius flag and cross-VPC peering analysis.

// Port 443 open to 0.0.0.0/0 → HIGH, not CRITICAL (it's a web server, expected)
// Port 80 open to 0.0.0.0/0 with redirect to 443 → INFO (acceptable, flag missing HSTS instead)
// EBS snapshot shared with own account → not a finding
// S3 bucket with static website hosting AND PublicAccessBlock properly configured → not a finding
```

---

## Rule Registry

All rules must be registered. This allows `--rules` flag filtering and report metadata:

```go
// internal/rules/registry.go

type Rule struct {
    ID          string
    Category    string   // "network" | "storage" | "iam" | "encryption" | "logging"
    Providers   []string // ["aws"] | ["gcp"] | ["aws","gcp","azure"]
    Severity    Severity
    Title       string
    CISMapping  []string
    MITREMapping []string
}

var Registry = []Rule{
    {ID: "AWS-SG-001",  Category: "network",    Providers: []string{"aws"},
     Severity: SeverityCritical, Title: "Security group allows inbound from 0.0.0.0/0",
     CISMapping: []string{"CIS AWS 5.1", "CIS AWS 5.2"}},
    {ID: "GCP-FW-001",  Category: "network",    Providers: []string{"gcp"},
     Severity: SeverityCritical, Title: "Firewall rule allows ingress from 0.0.0.0/0"},
    {ID: "AZ-NSG-001",  Category: "network",    Providers: []string{"azure"},
     Severity: SeverityCritical, Title: "NSG allows inbound from Internet on sensitive port"},
    {ID: "STOR-001",    Category: "storage",    Providers: []string{"aws","gcp","azure"},
     Severity: SeverityCritical, Title: "Storage publicly accessible"},
    {ID: "IAM-001",     Category: "iam",        Providers: []string{"aws","gcp","azure"},
     Severity: SeverityCritical, Title: "Wildcard permissions on compute resource"},
    // ... etc
}
```

---

## Anti-Patterns — NEVER DO THIS

- **NEVER** flag RFC1918 (`10.x`, `172.16.x`, `192.168.x`) ingress rules as "exposed to internet".
  Internal VPC traffic is NOT an internet exposure finding.
- **NEVER** emit a `SeverityCritical` finding solely because a port is open to `0.0.0.0/0`
  without confirming the resource has a public IP or an internet gateway route.
- **NEVER** hardcode remediation text as generic advice. Each finding must have
  provider-specific remediation pointing to the actual console/CLI fix.
- **NEVER** create a new Finding type without adding it to the Rule Registry.
- **NEVER** flag HTTP (port 80) open to `0.0.0.0/0` as CRITICAL — that is a web server.
  Flag it as HIGH only if there is no corresponding HTTPS listener.
- **NEVER** skip the `--blast-radius` flag check before emitting lateral movement findings.
  Cross-VPC and cross-account analysis is opt-in and computationally expensive.
