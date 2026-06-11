---
name: azure-sdk-go
description: >
  Complete standards for all Azure API interactions in Nimbus Mapper using azure-sdk-for-go v2
  ARM packages. Covers DefaultAzureCredential, subscription and resource group traversal,
  resource enumeration (VMs, NSGs, VNets, Storage Accounts, AKS, Azure SQL), pagination
  via pagers, throttling and retry handling, and normalized NimbusNode output.
triggers:
  - "when writing or modifying any Azure extraction logic"
  - "when querying VMs, NSGs, VNets, Storage, AKS, or Azure SQL"
  - "when configuring Azure authentication or credentials"
  - "when traversing Azure subscriptions or resource groups"
  - "when handling Azure throttling (429) or authorization errors"
  - "when writing multi-subscription Azure scan logic"
---

# Skill: azure-sdk-go

## Project Context

Azure's resource model differs from AWS and GCP: the hierarchy is
**Management Groups → Subscriptions → Resource Groups → Resources**.
Large enterprises have dozens of subscriptions organized under Management Groups.
Nimbus Mapper must traverse all accessible subscriptions and enumerate resources
within each, scanning for NSG misconfigurations, public storage, over-privileged
identities, and exposed compute.

**SDK Package Rule:** Always use `github.com/Azure/azure-sdk-for-go/sdk` (v2 ARM packages).
Never use the legacy `github.com/Azure/azure-sdk-for-go` v1 packages — they are deprecated,
lack context support, and have a completely different client model.

---

## Go Module Dependencies

```
go get github.com/Azure/azure-sdk-for-go/sdk/azidentity
go get github.com/Azure/azure-sdk-for-go/sdk/azcore
go get github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription
go get github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources
go get github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5
go get github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4
go get github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage
go get github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2
go get github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4
go get github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql
```

---

## Authentication: DefaultAzureCredential

**Always use `azidentity.NewDefaultAzureCredential()`.**
It resolves credentials in this order automatically:

1. `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` + `AZURE_TENANT_ID` env vars (service principal)
2. Workload Identity (AKS pod identity)
3. Managed Identity (Azure VM, App Service, Functions)
4. Azure CLI (`az login`) — for local development
5. Azure PowerShell credentials

```go
// internal/azure/client.go

package azure

import (
    "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
    "github.com/Azure/azure-sdk-for-go/sdk/azcore"
    "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type ClientFactory struct {
    cred           azcore.TokenCredential
    subscriptionID string
    clientOpts     *arm.ClientOptions
}

func NewClientFactory(subscriptionID string) (*ClientFactory, error) {
    cred, err := azidentity.NewDefaultAzureCredential(nil)
    if err != nil {
        return nil, fmt.Errorf("azure: creating default credential: %w", err)
    }
    return &ClientFactory{
        cred:           cred,
        subscriptionID: subscriptionID,
        clientOpts: &arm.ClientOptions{
            ClientOptions: azcore.ClientOptions{
                Retry: policy.RetryOptions{
                    MaxRetries:    5,
                    RetryDelay:    500 * time.Millisecond,
                    MaxRetryDelay: 30 * time.Second,
                    // Azure returns 429 with Retry-After header; SDK respects it
                    StatusCodes: []int{429, 500, 502, 503, 504},
                },
            },
        },
    }, nil
}
```

### Specific credential types (when DefaultAzureCredential is insufficient)

```go
// Service Principal with client secret — for CI without managed identity
cred, _ := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)

// Managed Identity with specific client ID (user-assigned)
cred, _ := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
    ID: azidentity.ClientID(clientID),
})

// For impersonating another service principal:
// Use client certificate credential pointing to a PFX/PEM with the target SP cert
cred, _ := azidentity.NewClientCertificateCredential(tenantID, clientID, certs, key, nil)
```

---

## Subscription Traversal

Enumerate all accessible subscriptions — never hardcode a subscription ID:

```go
// internal/azure/subscriptions.go

import "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"

func ListSubscriptions(ctx context.Context, cred azcore.TokenCredential,
    opts *arm.ClientOptions) ([]string, error) {

    client, err := armsubscription.NewSubscriptionsClient(cred, opts)
    if err != nil {
        return nil, err
    }

    var ids []string
    pager := client.NewListPager(nil)
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil {
            return nil, fmt.Errorf("listing azure subscriptions: %w", err)
        }
        for _, sub := range page.Value {
            if sub.State != nil && *sub.State == armsubscription.SubscriptionStateEnabled {
                ids = append(ids, *sub.SubscriptionID)
            }
        }
    }
    return ids, nil
}
```

---

## Universal Pagination Pattern

All v2 ARM clients use **pagers**. The pattern is identical across every Azure API:

```go
pager := client.NewListPager(resourceGroup, nil) // or NewListAllPager for subscription-wide
for pager.More() {
    page, err := pager.NextPage(ctx)
    if err != nil {
        return handleAzureError(err)
    }
    for _, item := range page.Value {
        process(item)
    }
}
```

**Never** manage `$skipToken` or continuation tokens manually.

---

## Error Handling

```go
// internal/azure/errors.go

import (
    "github.com/Azure/azure-sdk-for-go/sdk/azcore"
    "github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
)

func handleAzureError(err error) error {
    var respErr *azcore.ResponseError
    if errors.As(err, &respErr) {
        switch respErr.StatusCode {
        case 403:
            // AuthorizationFailed — missing permissions on this resource
            // Log warning, return nil (do not abort scan)
            slog.Warn("azure authorization failed, skipping",
                "code", respErr.ErrorCode,
                "msg", respErr.RawResponse.Request.URL.String())
            return nil
        case 404:
            // Resource deleted between list and get — safe to ignore
            return nil
        case 429:
            // Should be handled by SDK retry policy, but log if it bubbles up
            slog.Warn("azure rate limit exceeded despite retries")
            return err
        }
    }
    return err
}
```

---

## Resource Enumeration Targets

### Virtual Machines
```go
client, _ := armcompute.NewVirtualMachinesClient(subscriptionID, cred, opts)
pager := client.NewListAllPager(nil) // across ALL resource groups
// Key security fields:
// - properties.networkProfile.networkInterfaces[].id → resolve NIC → get public IP
// - properties.osProfile.linuxConfiguration.disablePasswordAuthentication
// - properties.storageProfile.osDisk.encryptionSettings → disk encrypted?
// - identity.type == "SystemAssigned" or "UserAssigned" → what managed identity?
// - properties.diagnosticsProfile.bootDiagnostics.enabled (useful for context)
// Cross-reference NIC → PublicIPAddress to determine if VM is internet-facing
```

### Network Security Groups (NSGs) — CRITICAL
```go
client, _ := armnetwork.NewSecurityGroupsClient(subscriptionID, cred, opts)
pager := client.NewListAllPager(nil)
// For each NSG, inspect securityRules AND defaultSecurityRules:
// Flag CRITICAL if:
//   - direction == "Inbound"
//   - access == "Allow"
//   - sourceAddressPrefix == "*" OR "Internet" OR "0.0.0.0/0"
//   - destinationPortRange includes: 22, 3389, 5432, 3306, 27017, 6379, 9200
// Cross-reference: which subnets and NICs have this NSG attached?
// An NSG with inbound 0.0.0.0/0:* is CRITICAL; with specific port is HIGH
```

### Public IP Addresses
```go
client, _ := armnetwork.NewPublicIPAddressesClient(subscriptionID, cred, opts)
pager := client.NewListAllPager(nil)
// Build a map[resourceID]publicIP for cross-referencing with VMs and load balancers
// Flag: static public IPs not associated with any resource (orphaned, billing waste)
```

### Storage Accounts
```go
client, _ := armstorage.NewAccountsClient(subscriptionID, cred, opts)
pager := client.NewListPager(nil)
// Security checks per account:
// - properties.allowBlobPublicAccess == true → containers may be public
// - properties.minimumTlsVersion != "TLS1_2" → weak TLS
// - properties.supportsHttpsTrafficOnly == false → HTTP allowed
// - properties.networkAcls.defaultAction == "Allow" → open to all networks
// For each storage account with allowBlobPublicAccess=true, enumerate containers:
blobClient, _ := armstorage.NewBlobContainersClient(subscriptionID, cred, opts)
containerPager := blobClient.NewListPager(rg, accountName, nil)
// Flag container if properties.publicAccess != "None"
```

### AKS Clusters
```go
client, _ := armcontainerservice.NewManagedClustersClient(subscriptionID, cred, opts)
pager := client.NewListPager(nil)
// Security checks:
// - properties.apiServerAccessProfile.enablePrivateCluster == false → public API server
// - properties.networkProfile.networkPolicy == nil → no network policy
// - properties.aadProfile == nil → no Azure AD integration
// - agentPoolProfiles[].enableNodePublicIP == true → nodes have public IPs
// - properties.addonProfiles["azurepolicy"].enabled == false → no Azure Policy
```

### Azure SQL
```go
client, _ := armsql.NewServersClient(subscriptionID, cred, opts)
pager := client.NewListPager(nil)
// Security checks per server:
// - Firewall rules: check for rule with startIPAddress="0.0.0.0" (Allow Azure services)
//   and especially any rule with startIPAddress="0.0.0.0" endIPAddress="255.255.255.255"
// - properties.minimalTlsVersion != "1.2" → weak TLS
// - properties.publicNetworkAccess == "Enabled" → internet-facing
// - Transparent Data Encryption: check via databases endpoint
firewallClient, _ := armsql.NewFirewallRulesClient(subscriptionID, cred, opts)
```

### RBAC — Role Assignments
```go
client, _ := armauthorization.NewRoleAssignmentsClient(subscriptionID, cred, opts)
// List at subscription scope to catch all assignments
pager := client.NewListForScopePager("/subscriptions/"+subscriptionID, nil)
// Flag: roleDefinitionId corresponds to "Owner" or "Contributor" assigned to:
//   - A user directly (not a group) — violates RBAC hygiene
//   - A service principal from outside the tenant
// Resolve roleDefinitionId to name via armauthorization.NewRoleDefinitionsClient
```

---

## Concurrency Model

```go
// internal/azure/scanner.go

func (s *AzureScanner) ScanSubscriptions(ctx context.Context,
    subscriptions []string, events chan<- ui.ScanEvent) error {
    eg, ctx := errgroup.WithContext(ctx)

    for _, subID := range subscriptions {
        subID := subID
        s.sem <- struct{}{}
        eg.Go(func() error {
            defer func() { <-s.sem }()
            return s.scanSubscription(ctx, subID, events)
        })
    }
    return eg.Wait()
}

func (s *AzureScanner) scanSubscription(ctx context.Context,
    subscriptionID string, events chan<- ui.ScanEvent) error {
    eg, ctx := errgroup.WithContext(ctx)

    factory, err := NewClientFactory(subscriptionID)
    if err != nil {
        return err
    }

    eg.Go(func() error { return s.scanVMs(ctx, factory, subscriptionID, events) })
    eg.Go(func() error { return s.scanNSGs(ctx, factory, subscriptionID, events) })
    eg.Go(func() error { return s.scanStorage(ctx, factory, subscriptionID, events) })
    eg.Go(func() error { return s.scanAKS(ctx, factory, subscriptionID, events) })
    eg.Go(func() error { return s.scanRBAC(ctx, factory, subscriptionID, events) })

    return eg.Wait()
}
```

---

## Anti-Patterns — NEVER DO THIS

- **NEVER** import `github.com/Azure/azure-sdk-for-go` (legacy v1). Verify go.mod has only
  `azure-sdk-for-go/sdk/...` paths.
- **NEVER** call `.NextPage()` without checking `.More()` first — it will panic on exhausted pagers.
- **NEVER** hardcode subscription IDs. Discover them via `ListSubscriptions()`.
- **NEVER** ignore 403 `AuthorizationFailed` errors by crashing — log and skip the resource.
- **NEVER** check NSG rules only at the NSG level. An NSG can be attached to a subnet (affects
  all VMs in subnet) or directly to a NIC (affects one VM). Always resolve both associations.
- **NEVER** assume a VM is internet-facing from `publicIPAddress` on the VM object alone.
  Azure's public IPs are separate resources — always resolve the NIC → PublicIPAddress chain.
- **NEVER** use `context.Background()` directly in scanners. Accept and propagate the `ctx`
  passed by the worker pool so cancellation works correctly.
