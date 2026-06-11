package tui

import (
	"math/rand"
	"time"
)

func RunDemo(eventCh chan<- DemoEvent) {
	send := func(line, phase, severity string, isFinding bool) {
		eventCh <- DemoEvent{
			Line:     line,
			Phase:    phase,
			Finding:  isFinding,
			Severity: severity,
		}
	}

	done := func() {
		eventCh <- DemoEvent{Done: true}
	}

	delay := func() {
		time.Sleep(time.Duration(300+rand.Intn(300)) * time.Millisecond)
	}

	delayLong := func() {
		time.Sleep(time.Duration(600+rand.Intn(400)) * time.Millisecond)
	}

	// Phase: Initialization
	send("", "Initializing cloud credential chains...", "", false)
	delay()
	send("AWS credential chain detected (profile: default)", "", "", false)
	delay()
	send("GCP application default credentials found (project: nimbus-gcp-prod)", "", "", false)
	delay()
	send("Azure CLI session active (subscription: nimbus-prod)", "", "", false)
	delayLong()
	send("Read-only mode confirmed for all providers", "", "", false)
	delay()

	// Phase: AWS
	send("", "Scanning AWS  us-east-1  (3 services, 12 resources)", "", false)
	delay()
	send("  • EC2 Instances: 3 found", "", "", false)
	delay()
	send("  • Security Groups: 3 found", "", "", false)
	delayLong()
	send("Security Group sg-prod-web allows SSH (22) from 0.0.0.0/0 — public internet can reach this instance",
		"", "CRITICAL", true)
	delay()
	send("Security Group sg-prod-web allows HTTP (80) from 0.0.0.0/0 — missing HTTPS redirect",
		"", "HIGH", true)
	delay()
	send("  • S3 Buckets: 2 found", "", "", false)
	delay()
	send("S3 bucket \"nimbus-prod-backups\" has public read access via bucket policy — all objects are world-readable",
		"", "CRITICAL", true)
	delay()
	send("  • RDS Instances: 1 found", "", "", false)
	delay()
	send("RDS instance rds-prod-db-01 has deletion protection disabled",
		"", "MEDIUM", true)
	delay()
	send("  • Analyzing IAM Roles...", "", "", false)
	delayLong()
	send("  • IAM Role \"nimbus-web-role\" has 3 attached policies", "", "", false)
	delay()
	send("  • VPC: nimbus-prod-vpc (10.0.0.0/16) — 3 subnets across web/app/db tiers", "", "", false)
	delayLong()

	// Phase: GCP
	send("", "Scanning GCP  us-central1  (2 services, 2 resources)", "", false)
	delay()
	send("  • Compute Instances: 1 found", "", "", false)
	delay()
	send("  • Instance gce-web-01 has public IP 35.123.45.1 — exposed to internet", "", "HIGH", true)
	delay()
	send("  • Cloud SQL Instances: 1 found", "", "", false)
	delay()
	send("  • VPC: gcp-prod-vpc — 1 subnet (10.128.0.0/20)", "", "", false)
	delayLong()

	// Phase: Azure
	send("", "Scanning Azure  eastus  (2 services, 2 resources)", "", false)
	delay()
	send("  • Virtual Machines: 1 found", "", "", false)
	delay()
	send("  • VM azure-web-01 is internal only — no public endpoint detected", "", "", false)
	delay()
	send("  • SQL Databases: 1 found", "", "", false)
	delay()
	send("  • VNet: azure-prod-vnet — 1 subnet (10.0.0.0/24)", "", "", false)
	delayLong()

	// Phase: Blast Radius
	send("", "Calculating Blast Radius — i-0a1b2c3d4e5f00001 (CRITICAL)", "", false)
	delay()
	send("  • Analyzing network paths from compromised web instance...", "", "", false)
	delayLong()
	send("  • Reachable targets: 4", "", "", false)
	delay()
	send("      → nimbus-web-02  (web, same SG, port 8080)", "", "", false)
	delay()
	send("      → nimbus-app-01  (app tier, port 8080)", "", "", false)
	delay()
	send("      → rds-prod-db-01 (database, port 3306)", "", "", false)
	delay()
	send("      → nimbus-prod-assets  (S3, via IAM role)", "", "", false)
	delayLong()
	send("  • Blast radius: WEB → APP → DATABASE (full lateral movement possible)", "", "", false)
	delayLong()

	// Phase: Graph generation
	send("", "Generating interactive security graph...", "", false)
	delay()
	send("  • Building topology: 22 nodes, 24 edges", "", "", false)
	delay()
	send("  • Embedding Cytoscape.js rendering engine", "", "", false)
	delay()
	send("  • Applying security exposure styling (Critical/Warning/Safe)", "", "", false)
	delayLong()
	send("  • Clustering nodes by provider and region", "", "", false)
	delay()

	// Phase: Complete
	send("Graph generated:  ./nimbus_map.html", "", "", false)
	send("Summary:  4 CRITICAL  2 HIGH  1 MEDIUM  0 LOW", "", "", false)
	delayLong()

	done()
}
