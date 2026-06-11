# Nimbus Mapper - Product Specification (spec.md)

> **Note for AI Agents:** This document is the ultimate source of truth (Spec as Source). All development, refactoring, and feature additions must be anchored to the rules defined here. If a behavior change is required, the human will update this file first.

## 1. Product Vision
**What we are building:** Nimbus Mapper is a lightning-fast, single-binary CLI tool (written in Go) that scans cloud environments (AWS, GCP, Azure) and generates an interactive network topology graph embedded in an offline HTML file.
**The problem it solves:** Inheriting undocumented cloud infrastructure is a critical pain point. Current solutions are commercial SaaS products that require access to the client's environments, creating privacy and security risks. Nimbus Mapper solves this by running 100% locally, without telemetry, passively reading the engineer's terminal credentials, and providing a tactical view tailored for both DevOps and Red Teamers.

## 2. User Flows
### 2.1. Transparent Authentication
- **Rule:** The user will NEVER input passwords, tokens, or secret keys directly into the Nimbus CLI via arguments.
- **Flow:** Nimbus must passively consume the operating system's default credential chain (e.g., `~/.aws/credentials` or environment variables like `AWS_PROFILE`, `gcloud auth application-default`, `AZURE_CONFIG_DIR`).

### 2.2. CLI Command Structure (The Nmap of the Cloud)
The tool utilizes a sub-command structure with flags inspired by network scanning methodologies.

**Standard Discovery Scans (Ping/Host Discovery equivalent):**
- Standard regional scan: `nimbus scan aws --profile production --region us-east-1`
- Global discovery: `nimbus scan aws --all-regions`
- Fast enumeration (List resources without deep routing/IAM parsing): `nimbus scan azure --fast`

**Targeting and Scoping (Port/Subnet targeting equivalent):**
- Scan specific VPC/VNet only: `nimbus scan gcp --vpc vpc-core-network`
- Scan by tags: `nimbus scan aws --tags "Environment=Production"`
- Exclude resources (avoiding honeypots/irrelevant data): `nimbus scan aws --exclude-tags "Type=Sandbox"`

**Red Team & Security Auditing (NSE / Vulnerability scanning equivalent):**
- Exposure map: `nimbus scan gcp --expose-only`
  - *Behavior:* The extraction engine filters out isolated internal resources and ONLY returns nodes that have a direct path to the internet (e.g., Public IPs, Ingress `0.0.0.0/0`, attached Internet Gateways).
- Blast radius analysis: `nimbus scan aws --blast-radius i-1234567890abcdef0`
  - *Behavior:* Maps the network topology strictly from the perspective of the compromised node. Shows what other subnets or databases this specific instance can reach.
- Security audit: `nimbus scan azure --audit`
  - *Behavior:* Highlights common misconfigurations on the graph (e.g., unencrypted disks, public storage buckets, permissive internal IAM roles attached to compute instances).

**Performance & Evasion (Timing templates `-T` equivalent):**
- `nimbus scan aws --timing stealth` (Adds artificial delays between API calls to avoid triggering CloudTrail/GuardDuty alerts).
- `nimbus scan aws --timing aggressive` (Max concurrency, useful when rate limits are not a concern and speed is paramount).

**Output Formats & TUI Behavior (`-o` equivalent):**
- `-oG <file.html>`: Generates the interactive embedded Graph (Default). Displays Bubbletea progress spinners during execution.
- `-oT` / `--table`: Bypasses HTML generation and prints a rich, color-coded ASCII tree or table directly in the terminal using Charmbracelet Lipgloss.
- `-oJ` / `--json` / `--csv`: **CRITICAL PIPELINE RULE.** If these flags are passed, the application MUST instantly disable all Bubbletea TUI elements, spinners, and structured logs. It must output ONLY raw, valid JSON/CSV to `stdout` so the tool can be safely piped into `jq` or CI/CD systems without formatting corruption.

### 2.3. Result Interaction (Frontend)
- **Flow:** The CLI finishes execution in seconds and prints: `"✅ Scan complete. Graph generated at: ./nimbus_map.html"`.
- Upon opening the file in a browser, the user sees a dark canvas (Deep Slate) with the topology.
- Clicking a node (e.g., an EC2 instance) triggers a static side panel displaying raw metadata (ID, attached IPs, Security Groups, IAM Roles, Tags).

## 3. Core Business Rules
- **Network Layer Isolation:** Security Groups and Firewalls are NOT floating nodes; they must be visually represented as the "edges" (lines/boundaries) that connect a compute node to the internet or to another node.
- **Cloud Immutability:** Nimbus is **READ-ONLY**. SDKs must be explicitly instantiated with `ReadOnlyAccess` equivalent configurations. Under no circumstances will Nimbus attempt to modify the cloud state.

## 4. Critical Edge Cases
Agents must handle these situations gracefully during development:

- **Edge Case 1: API Throttling (Rate Limits).**
  - *Problem:* Scanning a massive account with `--timing aggressive` will trigger HTTP 429 errors from AWS/GCP.
  - *Solution:* Implement a retry mechanism with *Exponential Backoff and Jitter* in all cloud API calls.
- **Edge Case 2: Massive Scale (The Spaghetti Graph).**
  - *Problem:* An Auto Scaling Group with 500 identical instances will crash the browser DOM.
  - *Solution:* Implement "Clustering" in the JSON generator. If there are more than 5 identical resources in the same subnet with the same IAM role, group them into a single visual node with a badge (e.g., `[EC2 Instances x500]`).
- **Edge Case 3: Partial Access Denied (HTTP 403).**
  - *Problem:* The engineer has permissions to read EC2 instances but not RDS databases.
  - *Solution:* The application **MUST NOT PANIC/CRASH**. It must log a warning in the CLI (`⚠️ Skipping RDS: Access Denied`), skip those resources, and generate the graph with the successfully retrieved data.
- **Edge Case 4: Nameless Resources.**
  - *Problem:* Many cloud resources lack a "Name" tag.
  - *Solution:* The frontend must perform an automatic fallback and display the unique resource ID (e.g., `i-0abcd1234efgh5678`) as the node's title.
