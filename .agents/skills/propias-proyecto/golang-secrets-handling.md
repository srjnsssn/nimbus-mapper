---
name: golang-secrets-handling
description: >
  Operational security rules for handling credentials, tokens, ARNs, account IDs, and any
  sensitive string in Nimbus Mapper. Covers log sanitization, memory scrubbing of credential
  structs, the redaction pipeline for JSON/CSV output, the --mask-ids flag implementation,
  patterns for detecting accidentally leaked secrets in environment variables and code,
  and secure credential resolution order.
triggers:
  - "when handling, reading, or passing any credential, token, or secret"
  - "when writing log statements that touch configuration or API responses"
  - "when serializing findings or nodes to JSON, CSV, or any output format"
  - "when implementing the --mask-ids flag"
  - "when printing struct values that may contain embedded credentials"
  - "when scanning Lambda environment variables for hardcoded secrets"
  - "when any sensitive string (ARN, account ID, subscription ID) appears in output"
---

# Skill: golang-secrets-handling

## Project Context

Nimbus Mapper reads cloud credentials and API responses that routinely contain sensitive data:
AWS access key IDs, GCP service account tokens, Azure client secrets, ARNs, account IDs,
project numbers, and subscription IDs. A scanner that leaks credentials in its own logs
or output would be counterproductive — it must handle all of this data with strict hygiene.

This skill applies to every layer: credential loading, API response processing, logging,
and the final JSON/CSV/SARIF output.

---

## Sensitive Data Classification

```go
// internal/secrets/classify.go

// Tier 1 — NEVER appear in any log, stdout, or output file (not even masked)
var tier1Secrets = []string{
    "AWS_SECRET_ACCESS_KEY",
    "AZURE_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS contents",
    "private key material",
    "session tokens",
    "STS temporary credentials",
}

// Tier 2 — Mask in output when --mask-ids is active, log at DEBUG only
var tier2Identifiers = []string{
    "AWS account ID (12-digit)",
    "AWS ARN",
    "GCP project number",
    "GCP project ID",
    "Azure subscription ID",
    "Azure tenant ID",
    "resource IDs containing account numbers",
}

// Tier 3 — Safe to include in output, always visible
var tier3Public = []string{
    "resource names (e.g. 'my-prod-bucket')",
    "region names",
    "severity levels",
    "finding titles and descriptions",
    "public IP addresses (they are the finding evidence)",
}
```

---

## Log Sanitization

**Rule: Never log a struct that contains credentials, even with `%+v`.**

AWS SDK v2 configuration structs, GCP credential token sources, and Azure credential objects
all embed credential data internally. Printing them with `%+v` can expose tokens.

```go
// WRONG — may expose AWS credentials embedded in cfg.Credentials
slog.Debug("loaded config", "cfg", fmt.Sprintf("%+v", awsCfg))

// CORRECT — log only the safe scalar fields
slog.Debug("loaded aws config",
    "region", awsCfg.Region,
    "profile", profileName,  // the profile name, not the credentials
)
```

```go
// WRONG — GCP option.ClientOption may contain token source internals
slog.Debug("gcp client options", "opts", fmt.Sprintf("%+v", clientOpts))

// CORRECT
slog.Debug("gcp client initialized",
    "project", projectID,
    "impersonating", impersonateAccount, // the SA email (not the token)
)
```

---

## Redaction Middleware

Implement a redaction layer that sits between the pipeline output and serialization.
It activates when `--mask-ids` is passed:

```go
// internal/secrets/redact.go

package secrets

import (
    "regexp"
    "strings"
)

// Compiled at startup — not per-call
var redactPatterns = []*redactRule{
    {
        name:    "aws_account_id",
        pattern: regexp.MustCompile(`\b(\d{12})\b`),
        replace: func(m string) string { return m[:4] + "****" + m[8:] },
    },
    {
        name:    "aws_arn",
        // Mask the account ID component within ARNs
        pattern: regexp.MustCompile(`arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:(\d{12}):`),
        replace: func(m string) string {
            return strings.Replace(m, extractAccountID(m), "XXXXXXXXXXXX", 1)
        },
    },
    {
        name:    "gcp_project_number",
        pattern: regexp.MustCompile(`projects/(\d{10,12})`),
        replace: func(m string) string { return "projects/REDACTED" },
    },
    {
        name:    "azure_subscription_id",
        // UUIDs used as Azure subscription IDs
        pattern: regexp.MustCompile(
            `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
        replace: func(m string) string { return "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" },
    },
    {
        name:    "aws_access_key_id",
        // AWS access key IDs start with AKIA, ASIA, AROA, etc.
        pattern: regexp.MustCompile(`(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}`),
        replace: func(m string) string { return m[:4] + "****************" },
    },
}

type redactRule struct {
    name    string
    pattern *regexp.Regexp
    replace func(string) string
}

// RedactString applies all active rules to a string value.
func RedactString(s string, maskIDs bool) string {
    if !maskIDs {
        return s
    }
    for _, rule := range redactPatterns {
        s = rule.pattern.ReplaceAllStringFunc(s, rule.replace)
    }
    return s
}

// RedactFinding returns a copy of the finding with sensitive IDs masked.
// Called in the serialization path, never on the in-memory working copy.
func RedactFinding(f model.Finding, maskIDs bool) model.Finding {
    if !maskIDs {
        return f
    }
    copy := f
    copy.ResourceID  = RedactString(f.ResourceID, true)
    copy.AccountID   = RedactString(f.AccountID, true)
    copy.Description = RedactString(f.Description, true)
    // Redact evidence map values
    copy.RawEvidence = make(map[string]string, len(f.RawEvidence))
    for k, v := range f.RawEvidence {
        copy.RawEvidence[k] = RedactString(v, true)
    }
    return copy
}
```

---

## Memory Scrubbing

When credential material is loaded into memory and no longer needed, overwrite it.
Go's GC does not guarantee when memory is freed, and heap dumps can expose secrets.

```go
// internal/secrets/memory.go

package secrets

// SecureWipe overwrites a byte slice with zeros.
// Use this for any []byte that held a private key, token, or password.
func SecureWipe(b []byte) {
    for i := range b {
        b[i] = 0
    }
    // Note: this does NOT prevent the GC from having already copied the slice.
    // For true security, use mlock/munlock via golang.org/x/sys/unix on Linux.
    // For most Nimbus use cases, SecureWipe is sufficient.
}

// SecureWipeString is a best-effort wipe for string values (strings are immutable in Go,
// so we can only wipe the underlying array via unsafe — use sparingly).
func SecureWipeString(s *string) {
    if s == nil || *s == "" {
        return
    }
    b := []byte(*s)
    SecureWipe(b)
    *s = ""
}
```

Usage pattern:
```go
// When loading a JSON key file for GCP:
keyData, err := os.ReadFile(keyPath)
defer secrets.SecureWipe(keyData) // wipe after the credential is initialized
cred, err := google.CredentialsFromJSON(ctx, keyData, scopes...)
```

---

## Secret Detection in Cloud Resources

Nimbus scans Lambda/Cloud Run/App Service environment variables for hardcoded secrets.
This rule lives in `cloud-misconfiguration-rules` but the detection logic is here:

```go
// internal/secrets/detect.go

// Patterns that suggest a hardcoded credential in an env var value
var secretPatterns = []*regexp.Regexp{
    regexp.MustCompile(`(?i)(password|passwd|pwd)\s*=\s*\S{8,}`),
    regexp.MustCompile(`(?i)(secret|api[_-]?key|auth[_-]?token)\s*=\s*\S{8,}`),
    regexp.MustCompile(`(AKIA|ASIA)[A-Z0-9]{16}`),  // AWS access key
    regexp.MustCompile(`[A-Za-z0-9+/]{40}`),         // generic base64 secret (broad)
    regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),       // GitHub PAT
    regexp.MustCompile(`sk-[A-Za-z0-9]{48}`),         // OpenAI API key
}

// ScanEnvVars checks a map of environment variable name→value for secret patterns.
// Returns a list of suspicious variable names (NOT their values — never log those).
func ScanEnvVars(envVars map[string]string) []string {
    var suspicious []string
    for name, value := range envVars {
        for _, pat := range secretPatterns {
            if pat.MatchString(value) {
                suspicious = append(suspicious, name) // name only, never value
                break
            }
        }
    }
    return suspicious
}
```

Important: when emitting a Finding for hardcoded secrets, include the **variable name** in
`RawEvidence`, never the **value**:

```go
findings = append(findings, model.Finding{
    RuleID:   "SECRETS-001",
    Severity: model.SeverityCritical,
    Title:    "Hardcoded secret detected in Lambda environment variable",
    RawEvidence: map[string]string{
        "variable_name": suspiciousVarName, // "DB_PASSWORD" — safe to include
        // NEVER: "variable_value": actualSecret
    },
})
```

---

## Credential Resolution Order for Nimbus CLI

The Nimbus CLI resolves credentials in this explicit order, documented for users:

```
--role-arn / --impersonate-sa      (explicit cross-account/cross-project)
  └──► $NIMBUS_AWS_PROFILE / --profile    (named profile)
         └──► $AWS_ACCESS_KEY_ID etc.     (explicit env vars)
                └──► ~/.aws/credentials  / gcloud ADC / az CLI
                       └──► Instance metadata / Workload Identity
```

Never prompt the user interactively for credentials. If no credentials can be resolved,
emit a clear error with the resolution chain and exit with code 2.

---

## Anti-Patterns — NEVER DO THIS

- **NEVER** `fmt.Sprintf("%+v", awsCfg)` or `fmt.Sprintf("%+v", gcpOpts)` in any log statement.
  These structs contain embedded credential interfaces that may print token values.
- **NEVER** include a `Finding.RawEvidence` key whose value is the actual secret,
  only the name of the variable or field where the secret was found.
- **NEVER** write AWS secret access keys, GCP tokens, or Azure client secrets to any log,
  even at `DEBUG` level. Use `slog.Debug("credential resolved", "type", "service_account")`.
- **NEVER** serialize the in-memory `NimbusNode.RawMetadata` directly to output without
  passing through `RedactFinding`. AWS API responses in `RawMetadata` often contain ARNs
  with account IDs.
- **NEVER** store credentials in global variables. Pass credential configs through
  function parameters and `context.Context` only.
- **NEVER** implement a `String()` or `MarshalJSON()` method on a struct that contains
  credential fields without explicitly excluding those fields.
- **NEVER** log the output of `os.Environ()` — it will contain cloud credentials if the
  user has set them as env vars.
