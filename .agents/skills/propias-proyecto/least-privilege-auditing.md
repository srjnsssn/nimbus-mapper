---
name: least-privilege-auditing
description: >
  IAM and RBAC analysis engine for Nimbus Mapper. Covers effective permission calculation,
  blast radius computation (--blast-radius flag), cross-account/cross-tenant trust detection,
  admin role detection on compute resources, unused permissions, and lateral movement path
  mapping across AWS, GCP, and Azure. Defines how identity findings are linked to NimbusEdge
  (lateral movement edges) in the graph output.
triggers:
  - "when implementing or modifying IAM or RBAC analysis logic"
  - "when the --blast-radius flag is used"
  - "when calculating effective permissions of a compute resource"
  - "when detecting cross-account AssumeRole or cross-project impersonation"
  - "when checking for admin/owner roles on VMs, functions, or containers"
  - "when building NimbusEdge objects for lateral movement paths"
  - "when analyzing service accounts, instance profiles, or managed identities"
---

# Skill: least-privilege-auditing

## Project Context

Nimbus Mapper maps not only the physical network (IPs, ports, firewall rules) but also
the **logical identity network** (who can access what, and from where). This is required
to answer the question: "If this EC2 instance is compromised, what else can the attacker reach?"

This skill powers two modes:
1. **Standard scan**: detect over-privileged identities attached to compute resources.
2. **Blast radius mode** (`--blast-radius <resource-id>`): starting from a specific resource,
   calculate all resources reachable via identity (IAM/RBAC) from that resource.

---

## Core Data Types

```go
// internal/model/identity.go

// IdentityNode represents an IAM entity (role, SA, managed identity)
type IdentityNode struct {
    ID          string   // ARN / SA email / Azure object ID
    Type        string   // "aws_role" | "aws_user" | "gcp_service_account" | "azure_managed_identity"
    Provider    string
    AccountID   string
    DisplayName string
    // Computed:
    EffectivePermissions []Permission
    IsAdmin              bool     // has Owner/AdministratorAccess equivalent
    IsOverPrivileged     bool     // has more permissions than needed (heuristic)
    AttachedResources    []string // resource IDs using this identity
}

// Permission is a normalized, provider-agnostic permission entry
type Permission struct {
    Action   string // "s3:GetObject" | "compute.instances.start" | "Microsoft.Compute/*/read"
    Resource string // "*" | specific ARN/path
    Effect   string // "Allow" | "Deny"
    // Source of the permission (for traceability):
    PolicyID string // AWS policy ARN | GCP role name | Azure role definition ID
}

// NimbusEdge represents a potential lateral movement path
type NimbusEdge struct {
    SourceID    string // Resource that has the identity
    TargetID    string // Resource reachable via that identity
    PortRange   string // "IAM" (identity-based, not network-based)
    EdgeType    string // "iam_can_read" | "iam_can_write" | "iam_can_assume" | "network"
    ViaIdentity string // The identity (role ARN / SA email) enabling the path
    Bidirectional bool
}
```

---

## Standard IAM Checks (No --blast-radius required)

### Check 1: Admin Role on Compute (CRITICAL)

```go
// AWS: AdministratorAccess or equivalent attached to EC2 instance profile
func CheckEC2AdminRole(instance ec2Types.Instance, policies []iam.Policy) *model.Finding {
    for _, policy := range policies {
        if isAdminPolicy(policy) {
            return &model.Finding{
                RuleID:   "IAM-002",
                Severity: model.SeverityCritical,
                Title:    "EC2 instance has AdministratorAccess IAM role",
                Description: fmt.Sprintf(
                    "Instance %s is attached to IAM role with AdministratorAccess. "+
                    "If compromised, the attacker gains full AWS account access.",
                    aws.ToString(instance.InstanceId)),
                Remediation: "Replace AdministratorAccess with a least-privilege policy " +
                             "scoped to the specific actions the application requires.",
                References: []string{"CIS AWS 1.16", "MITRE ATT&CK T1078.004"},
            }
        }
    }
    return nil
}

// Admin policy heuristics:
func isAdminPolicy(policy iam.Policy) bool {
    name := aws.ToString(policy.PolicyName)
    arn  := aws.ToString(policy.Arn)
    return name == "AdministratorAccess" ||
           arn == "arn:aws:iam::aws:policy/AdministratorAccess" ||
           hasWildcardStatement(policy) // inline policy with Action:* Resource:*
}
```

### Check 2: Cross-Account Trust (HIGH)

```go
// AWS: IAM role trust policy allowing sts:AssumeRole from an account
// outside the organization's known account list
func CheckCrossAccountTrust(role iamTypes.Role, orgAccountIDs []string) *model.Finding {
    trustPolicy, err := url.QueryUnescape(aws.ToString(role.AssumeRolePolicyDocument))
    if err != nil { return nil }

    var doc PolicyDocument
    json.Unmarshal([]byte(trustPolicy), &doc)

    for _, stmt := range doc.Statement {
        if stmt.Effect != "Allow" { continue }
        for _, principal := range extractPrincipals(stmt) {
            accountID := extractAccountFromARN(principal)
            if accountID == "" { continue }
            if !slices.Contains(orgAccountIDs, accountID) {
                return &model.Finding{
                    RuleID:   "IAM-003",
                    Severity: model.SeverityHigh,
                    Title:    "IAM role trusts an external AWS account",
                    Description: fmt.Sprintf(
                        "Role %q allows AssumeRole from account %s, which is not "+
                        "part of your AWS Organization. This could enable unauthorized access.",
                        aws.ToString(role.RoleName), accountID),
                    Remediation: "Review the trust policy. If the external account is a " +
                                 "known vendor, document the justification. Otherwise, remove it.",
                    RawEvidence: map[string]string{
                        "external_account": accountID,
                        "role_arn": aws.ToString(role.Arn),
                    },
                }
            }
        }
    }
    return nil
}
```

### Check 3: Long-Lived Service Account Keys (MEDIUM)

```go
// GCP: Service account key older than 90 days
const maxKeyAgeDays = 90

func CheckGCPKeyAge(sa *iampb.ServiceAccount, keys []*iampb.ServiceAccountKey) []model.Finding {
    var findings []model.Finding
    for _, key := range keys {
        if key.KeyType != iampb.ServiceAccountKeyType_USER_MANAGED { continue }

        createdAt, _ := time.Parse(time.RFC3339, key.ValidAfterTime)
        age := time.Since(createdAt)
        if age > maxKeyAgeDays*24*time.Hour {
            findings = append(findings, model.Finding{
                RuleID:   "IAM-004",
                Severity: model.SeverityMedium,
                Title:    fmt.Sprintf("Service account key is %d days old", int(age.Hours()/24)),
                Description: "Long-lived SA keys are a credential exposure risk. " +
                             "Prefer Workload Identity or short-lived tokens.",
                Remediation: "Rotate or delete this key. Use Workload Identity for GKE, " +
                             "or impersonation for cross-project access.",
                RawEvidence: map[string]string{
                    "key_id":    key.Name,
                    "sa_email":  sa.Email,
                    "key_age_days": fmt.Sprintf("%d", int(age.Hours()/24)),
                },
            })
        }
    }
    return findings
}
```

---

## Blast Radius Mode (--blast-radius <resource-id>)

This mode is computationally expensive and opt-in. It maps the full reachability graph
from a specific starting resource using its attached identity.

```go
// internal/iam/blastradius.go

type BlastRadiusResult struct {
    Origin       string          // The starting resource ID
    Identity     IdentityNode    // The identity attached to origin
    ReachableBy  []ReachablePath // All resources reachable via IAM from origin
    LateralEdges []NimbusEdge    // Graph edges for visualization
}

type ReachablePath struct {
    TargetResourceID   string
    TargetResourceType string
    AccessType         string   // "read" | "write" | "admin" | "assume_role"
    ViaPermission      string   // The specific permission enabling access
    ViaPolicy          string   // Policy ARN / role name granting it
    IsTransitive       bool     // True if reached via role chaining
}

func ComputeBlastRadius(ctx context.Context, originResourceID string,
    providers []CloudProvider) (*BlastRadiusResult, error) {

    // Step 1: Find the identity attached to origin resource
    identity, err := resolveAttachedIdentity(ctx, originResourceID, providers)
    if err != nil || identity == nil {
        return nil, fmt.Errorf("no identity attached to %s", originResourceID)
    }

    // Step 2: Enumerate effective permissions of that identity
    perms, err := GetEffectivePermissions(ctx, identity)
    if err != nil { return nil, err }

    // Step 3: For each permission, find matching resources
    var paths []ReachablePath
    var edges []NimbusEdge
    for _, perm := range perms {
        targets, err := findResourcesMatchingPermission(ctx, perm, providers)
        if err != nil { continue }
        for _, target := range targets {
            paths = append(paths, ReachablePath{
                TargetResourceID: target.ID,
                AccessType:       classifyAccessType(perm.Action),
                ViaPermission:    perm.Action,
                ViaPolicy:        perm.PolicyID,
            })
            edges = append(edges, NimbusEdge{
                SourceID:    originResourceID,
                TargetID:    target.ID,
                PortRange:   "IAM",
                EdgeType:    "iam_" + classifyAccessType(perm.Action),
                ViaIdentity: identity.ID,
            })
        }
    }

    // Step 4: Check for role chaining (can this identity assume other roles?)
    chainedRoles := findAssumableRoles(ctx, identity, providers)
    for _, role := range chainedRoles {
        // Recurse one level (do NOT recurse infinitely — max depth 3)
        subResult, _ := ComputeBlastRadius(ctx, role.ID, providers)
        if subResult != nil {
            for _, p := range subResult.ReachableBy {
                p.IsTransitive = true
                paths = append(paths, p)
            }
        }
    }

    return &BlastRadiusResult{
        Origin:      originResourceID,
        Identity:    *identity,
        ReachableBy: paths,
        LateralEdges: edges,
    }, nil
}
```

---

## Effective Permission Calculation per Provider

### AWS

```go
// AWS effective permissions = union of:
// 1. Attached managed policies (inline + AWS-managed)
// 2. Inline role policies
// 3. Permission boundaries (RESTRICTING — subtract permissions outside boundary)
// 4. SCPs from AWS Organizations (RESTRICTING — subtract denied actions)

func GetAWSEffectivePermissions(ctx context.Context,
    roleARN string, cfg aws.Config) ([]Permission, error) {
    iamClient := iam.NewFromConfig(cfg)

    // Get attached policies
    roleName := extractRoleNameFromARN(roleARN)
    attached, _ := iamClient.ListAttachedRolePolicies(ctx,
        &iam.ListAttachedRolePoliciesInput{RoleName: &roleName})

    var permissions []Permission
    for _, p := range attached.AttachedPolicies {
        stmts, err := getPolicyStatements(ctx, iamClient, aws.ToString(p.PolicyArn))
        if err != nil { continue }
        for _, stmt := range stmts {
            if stmt.Effect == "Allow" {
                for _, action := range normalizeActions(stmt.Action) {
                    permissions = append(permissions, Permission{
                        Action:   action,
                        Resource: normalizeResource(stmt.Resource),
                        Effect:   "Allow",
                        PolicyID: aws.ToString(p.PolicyArn),
                    })
                }
            }
        }
    }
    return permissions, nil
}
```

### GCP

```go
// GCP effective permissions = union of roles granted to SA at:
// 1. Resource level (bucket IAM, etc.)
// 2. Project level
// 3. Folder level (inherited)
// 4. Org level (inherited)
// GCP uses predefined roles → expand to individual permissions via roles.get API

// Key roles to flag as admin:
var gcpAdminRoles = []string{
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.organizationAdmin",
    "roles/iam.serviceAccountAdmin",
}
```

---

## Anti-Patterns — NEVER DO THIS

- **NEVER** recurse blast radius deeper than 3 hops. Role chaining can be circular
  (roleA can assume roleB which can assume roleA). Always track visited identities and break cycles.
- **NEVER** run blast radius analysis without the explicit `--blast-radius` flag.
  It requires many additional API calls and significantly increases scan time and quota usage.
- **NEVER** build NimbusEdge objects for IAM paths without verifying the target resource
  actually exists in the current scan's NimbusNode set.
- **NEVER** flag `roles/viewer` or `Reader` RBAC as admin — read-only access is expected.
  Only flag roles that allow write, delete, or credential access (`iam:PassRole`, `actAs`, etc.)
- **NEVER** treat SCPs or permission boundaries as "safe" without verifying they actually
  restrict the relevant actions. An SCP that denies `ec2:TerminateInstances` does not
  prevent `s3:GetObject` from being exploited.
- **NEVER** emit a blast radius Finding without including `IsTransitive = true/false`
  in the evidence — transitive paths via role chaining are less immediately exploitable
  than direct permissions and should be ranked lower.
