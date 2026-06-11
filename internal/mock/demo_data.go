package mock

import (
	"time"

	"github.com/yourusername/nimbus/internal/models"
)

func DemoGraph() *models.Graph {
	now := time.Date(2026, 6, 11, 10, 30, 0, 0, time.UTC)

	exposedFinding := models.Finding{
		ID:           "a1b2c3d4e5f6a1b2",
		RuleID:       "AWS-SG-001",
		Severity:     models.SeverityCritical,
		Provider:     "aws",
		AccountID:    "123456789012",
		Region:       "us-east-1",
		ResourceID:   "sg-0a1b2c3d4e5f00001",
		ResourceType: "security_group",
		Title:        "Security Group allows SSH from 0.0.0.0/0",
		Description:  "Security group sg-prod-web allows inbound SSH (port 22) from any IP address (0.0.0.0/0). This exposes the attached EC2 instance to brute-force attacks, unauthorized access, and potential compromise.",
		Remediation:  "Restrict SSH port 22 ingress to specific CIDR ranges (e.g., your office VPN CIDR). Use AWS Systems Manager Session Manager as an alternative to SSH. See: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html",
		References:   []string{"CIS AWS 5.1", "CIS AWS 5.2", "MITRE ATT&CK T1190"},
		RawEvidence: map[string]string{
			"cidr":              "0.0.0.0/0",
			"port":              "22",
			"protocol":          "tcp",
			"sg_id":             "sg-0a1b2c3d4e5f00001",
			"sg_name":           "sg-prod-web",
			"attached_instance": "i-0a1b2c3d4e5f00001",
		},
	}

	albHTTPFinding := models.Finding{
		ID:           "b2c3d4e5f6a1b2c3",
		RuleID:       "AWS-SG-001",
		Severity:     models.SeverityHigh,
		Provider:     "aws",
		AccountID:    "123456789012",
		Region:       "us-east-1",
		ResourceID:   "sg-0a1b2c3d4e5f00001",
		ResourceType: "security_group",
		Title:        "Security Group allows HTTP from 0.0.0.0/0",
		Description:  "Security group sg-prod-web allows inbound HTTP (port 80) from any IP address. Port 80 should redirect to HTTPS (port 443) to ensure encrypted traffic.",
		Remediation:  "Ensure HTTP (port 80) traffic is redirected to HTTPS (port 443) at the load balancer level. Consider restricting port 80 to a CDN edge if direct access is not required.",
		References:   []string{"CIS AWS 5.1", "CIS AWS 5.2"},
		RawEvidence: map[string]string{
			"cidr":     "0.0.0.0/0",
			"port":     "80",
			"protocol": "tcp",
			"sg_id":    "sg-0a1b2c3d4e5f00001",
		},
	}

	memoryDBFinding := models.Finding{
		ID:           "c3d4e5f6a1b2c3d4",
		RuleID:       "STOR-002",
		Severity:     models.SeverityMedium,
		Provider:     "aws",
		AccountID:    "123456789012",
		Region:       "us-east-1",
		ResourceID:   "rds-prod-db-01",
		ResourceType: "aws_rds_instance",
		Title:        "RDS instance does not have deletion protection enabled",
		Description:  "RDS instance 'rds-prod-db-01' has deletion protection disabled. A malicious actor with RDS delete permissions could permanently delete the production database.",
		Remediation:  "Enable deletion protection on the RDS instance via the AWS Console or CLI: `aws rds modify-db-instance --db-instance-identifier rds-prod-db-01 --deletion-protection --apply-immediately`",
		References:   []string{"CIS AWS 2.3.1"},
		RawEvidence: map[string]string{
			"deletion_protection": "false",
			"db_instance_id":      "rds-prod-db-01",
		},
	}

	publicS3Finding := models.Finding{
		ID:           "d4e5f6a1b2c3d4e5",
		RuleID:       "STOR-001",
		Severity:     models.SeverityCritical,
		Provider:     "aws",
		AccountID:    "123456789012",
		Region:       "us-east-1",
		ResourceID:   "nimbus-prod-backups",
		ResourceType: "aws_s3_bucket",
		Title:        "S3 bucket 'nimbus-prod-backups' has public read access",
		Description:  "S3 bucket 'nimbus-prod-backups' allows public read access via bucket policy. All objects in this bucket are readable by anyone on the internet.",
		Remediation:  "Remove the public read policy from the S3 bucket. Use AWS Block Public Access at account level. See: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
		References:   []string{"CIS AWS 2.1.5"},
		RawEvidence: map[string]string{
			"bucket_name":   "nimbus-prod-backups",
			"public_access": "true",
			"acl_enabled":   "true",
		},
	}

	return &models.Graph{
		Metadata: models.GraphMetadata{
			Version:       "v0.1.0-alpha",
			GeneratedAt:   now.Format(time.RFC3339),
			TotalNodes:    22,
			TotalEdges:    24,
			TotalFindings: 4,
			Providers:     []string{"aws", "gcp", "azure"},
		},
		Nodes: []models.Resource{
			// ===== AWS INFRASTRUCTURE =====
			{
				ID: "vpc-0a1b2c3d4e5f00001", ShortID: "vpc-prod",
				Type: models.NodeTypeVPC, Provider: "aws",
				AccountID: "123456789012", Region: "us-east-1",
				Name: "nimbus-prod-vpc", VPC: "vpc-0a1b2c3d4e5f00001",
				Tags:     map[string]string{"Environment": "Production", "Team": "Platform", "Terraform": "true"},
				Exposure: models.ExposureSafe,
			},
			{
				ID: "igw-0a1b2c3d4e5f00001", ShortID: "igw-prod",
				Type: models.NodeTypeInternetGateway, Provider: "aws",
				AccountID: "123456789012", Region: "us-east-1",
				Name: "nimbus-prod-igw", VPC: "vpc-0a1b2c3d4e5f00001",
				Tags:     map[string]string{"Environment": "Production", "Name": "nimbus-prod-igw"},
				Exposure: models.ExposureSafe,
			},
			{
				ID: "subnet-0a1b2c3d4e5f00001", ShortID: "subnet-web",
				Type: models.NodeTypeSubnet, Provider: "aws",
				AccountID: "123456789012", Region: "us-east-1",
				Name: "nimbus-prod-web-subnet", Subnet: "10.0.1.0/24", VPC: "vpc-0a1b2c3d4e5f00001",
				Tags:     map[string]string{"Environment": "Production", "Tier": "Web", "Type": "Public"},
				Exposure: models.ExposureSafe,
			},
			{
				ID: "subnet-0a1b2c3d4e5f00002", ShortID: "subnet-app",
				Type: models.NodeTypeSubnet, Provider: "aws",
				AccountID: "123456789012", Region: "us-east-1",
				Name: "nimbus-prod-app-subnet", Subnet: "10.0.2.0/24", VPC: "vpc-0a1b2c3d4e5f00001",
				Tags:     map[string]string{"Environment": "Production", "Tier": "Application", "Type": "Private"},
				Exposure: models.ExposureSafe,
			},
			{
				ID: "subnet-0a1b2c3d4e5f00003", ShortID: "subnet-db",
				Type: models.NodeTypeSubnet, Provider: "aws",
				AccountID: "123456789012", Region: "us-east-1",
				Name: "nimbus-prod-db-subnet", Subnet: "10.0.3.0/24", VPC: "vpc-0a1b2c3d4e5f00001",
				Tags:     map[string]string{"Environment": "Production", "Tier": "Database", "Type": "Private"},
				Exposure: models.ExposureSafe,
			},
			{
				ID: "sg-0a1b2c3d4e5f00001", ShortID: "sg-web",
				Type: models.NodeTypeSecurityGroup, Provider: "aws",
				AccountID: "123456789012", Region: "us-east-1",
				Name: "sg-prod-web", VPC: "vpc-0a1b2c3d4e5f00001",
				Tags:     map[string]string{"Environment": "Production", "Name": "sg-prod-web"},
				Exposure: models.ExposureCritical,
				Findings: []models.Finding{exposedFinding, albHTTPFinding},
			},
			{
				ID: "sg-0a1b2c3d4e5f00002", ShortID: "sg-app",
				Type: models.NodeTypeSecurityGroup, Provider: "aws",
				AccountID: "123456789012", Region: "us-east-1",
				Name: "sg-prod-app", VPC: "vpc-0a1b2c3d4e5f00001",
				Tags:     map[string]string{"Environment": "Production", "Name": "sg-prod-app"},
				Exposure: models.ExposureSafe,
			},
			{
				ID: "sg-0a1b2c3d4e5f00003", ShortID: "sg-db",
				Type: models.NodeTypeSecurityGroup, Provider: "aws",
				AccountID: "123456789012", Region: "us-east-1",
				Name: "sg-prod-db", VPC: "vpc-0a1b2c3d4e5f00001",
				Tags:     map[string]string{"Environment": "Production", "Name": "sg-prod-db"},
				Exposure: models.ExposureSafe,
			},
			{
				ID:      "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/0a1b2c3d4e5f",
				ShortID: "prod-alb",
				Type:    models.NodeTypeALB, Provider: "aws",
				AccountID: "123456789012", Region: "us-east-1",
				Name: "prod-alb", VPC: "vpc-0a1b2c3d4e5f00001",
				PublicIP:      "203.0.113.100",
				Subnet:        "10.0.1.0/24",
				Tags:          map[string]string{"Environment": "Production", "Name": "prod-alb", "Service": "web-frontend"},
				Exposure:      models.ExposureWarning,
				AttachedRules: []string{"sg-0a1b2c3d4e5f00001"},
			},
			{
				ID: "i-0a1b2c3d4e5f00001", ShortID: "i-0a1b2c3d4e5f00001",
				Type: models.NodeTypeEC2Instance, Provider: "aws",
				AccountID: "123456789012", Region: "us-east-1", Zone: "us-east-1a",
				Name: "nimbus-web-01", VPC: "vpc-0a1b2c3d4e5f00001",
				PublicIP: "203.0.113.1", PrivateIPs: []string{"10.0.1.10"},
				Subnet:        "10.0.1.0/24",
				IAMRole:       "arn:aws:iam::123456789012:instance-profile/nimbus-web-role",
				AttachedRules: []string{"sg-0a1b2c3d4e5f00001"},
				Tags:          map[string]string{"Environment": "Production", "Name": "nimbus-web-01", "Tier": "Web", "OS": "AmazonLinux2023"},
				Exposure:      models.ExposureCritical,
				Findings:      []models.Finding{exposedFinding},
			},
			{
				ID: "i-0a1b2c3d4e5f00002", ShortID: "i-0a1b2c3d4e5f00002",
				Type: models.NodeTypeEC2Instance, Provider: "aws",
				AccountID: "123456789012", Region: "us-east-1", Zone: "us-east-1b",
				Name: "nimbus-web-02", VPC: "vpc-0a1b2c3d4e5f00001",
				PrivateIPs:    []string{"10.0.1.11"},
				Subnet:        "10.0.1.0/24",
				IAMRole:       "arn:aws:iam::123456789012:instance-profile/nimbus-web-role",
				AttachedRules: []string{"sg-0a1b2c3d4e5f00001"},
				Tags:          map[string]string{"Environment": "Production", "Name": "nimbus-web-02", "Tier": "Web", "OS": "AmazonLinux2023"},
				Exposure:      models.ExposureSafe,
			},
			{
				ID: "i-0a1b2c3d4e5f00003", ShortID: "i-0a1b2c3d4e5f00003",
				Type: models.NodeTypeEC2Instance, Provider: "aws",
				AccountID: "123456789012", Region: "us-east-1", Zone: "us-east-1a",
				Name: "nimbus-app-01", VPC: "vpc-0a1b2c3d4e5f00001",
				PrivateIPs:    []string{"10.0.2.10"},
				Subnet:        "10.0.2.0/24",
				IAMRole:       "arn:aws:iam::123456789012:instance-profile/nimbus-app-role",
				AttachedRules: []string{"sg-0a1b2c3d4e5f00002"},
				Tags:          map[string]string{"Environment": "Production", "Name": "nimbus-app-01", "Tier": "Application", "OS": "AmazonLinux2023"},
				Exposure:      models.ExposureSafe,
			},
			{
				ID: "rds-prod-db-01", ShortID: "rds-prod-db-01",
				Type: models.NodeTypeRDSInstance, Provider: "aws",
				AccountID: "123456789012", Region: "us-east-1", Zone: "us-east-1a",
				Name: "nimbus-prod-db", VPC: "vpc-0a1b2c3d4e5f00001",
				PrivateIPs:    []string{"10.0.3.5"},
				Subnet:        "10.0.3.0/24",
				IAMRole:       "arn:aws:iam::123456789012:role/rds-monitoring-role",
				AttachedRules: []string{"sg-0a1b2c3d4e5f00003"},
				Tags:          map[string]string{"Environment": "Production", "Name": "nimbus-prod-db", "Engine": "MySQL 8.0", "Tier": "Database"},
				Exposure:      models.ExposureWarning,
				Findings:      []models.Finding{memoryDBFinding},
			},
			{
				ID: "arn:aws:s3:::nimbus-prod-assets", ShortID: "nimbus-prod-assets",
				Type: models.NodeTypeS3Bucket, Provider: "aws",
				AccountID: "123456789012", Region: "us-east-1",
				Name:     "nimbus-prod-assets",
				Tags:     map[string]string{"Environment": "Production", "Name": "nimbus-prod-assets", "DataClassification": "Public"},
				Exposure: models.ExposureSafe,
			},
			{
				ID: "arn:aws:s3:::nimbus-prod-backups", ShortID: "nimbus-prod-backups",
				Type: models.NodeTypeS3Bucket, Provider: "aws",
				AccountID: "123456789012", Region: "us-east-1",
				Name:     "nimbus-prod-backups",
				Tags:     map[string]string{"Environment": "Production", "Name": "nimbus-prod-backups", "DataClassification": "Confidential"},
				Exposure: models.ExposureCritical,
				Findings: []models.Finding{publicS3Finding},
			},

			// ===== GCP INFRASTRUCTURE =====
			{
				ID:      "projects/nimbus-gcp-prod/global/networks/gcp-prod-vpc",
				ShortID: "gcp-prod-vpc",
				Type:    models.NodeTypeGCPVPC, Provider: "gcp",
				AccountID: "nimbus-gcp-prod", Region: "us-central1",
				Name:     "gcp-prod-vpc",
				Tags:     map[string]string{"Environment": "Production", "Team": "Platform"},
				Exposure: models.ExposureSafe,
			},
			{
				ID:      "projects/nimbus-gcp-prod/zones/us-central1-a/instances/gce-web-01",
				ShortID: "gce-web-01",
				Type:    models.NodeTypeGCEInstance, Provider: "gcp",
				AccountID: "nimbus-gcp-prod", Region: "us-central1", Zone: "us-central1-a",
				Name: "gce-web-01", VPC: "projects/nimbus-gcp-prod/global/networks/gcp-prod-vpc",
				PublicIP: "198.51.100.1", PrivateIPs: []string{"10.128.0.2"},
				IAMRole:  "serviceAccount:web-sa@nimbus-gcp-prod.iam.gserviceaccount.com",
				Tags:     map[string]string{"Environment": "Production", "Name": "gce-web-01", "Tier": "Web"},
				Exposure: models.ExposureWarning,
			},
			{
				ID:      "projects/nimbus-gcp-prod/instances/gcp-prod-db",
				ShortID: "gcp-prod-db",
				Type:    models.NodeTypeCloudSQL, Provider: "gcp",
				AccountID: "nimbus-gcp-prod", Region: "us-central1",
				Name: "gcp-prod-db", VPC: "projects/nimbus-gcp-prod/global/networks/gcp-prod-vpc",
				PrivateIPs: []string{"10.128.0.5"},
				Tags:       map[string]string{"Environment": "Production", "Engine": "PostgreSQL 15"},
				Exposure:   models.ExposureSafe,
			},

			// ===== AZURE INFRASTRUCTURE =====
			{
				ID:      "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/nimbus-prod-rg/providers/Microsoft.Network/virtualNetworks/azure-prod-vnet",
				ShortID: "azure-prod-vnet",
				Type:    models.NodeTypeAzureVNet, Provider: "azure",
				AccountID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Region: "eastus",
				Name:     "azure-prod-vnet",
				Tags:     map[string]string{"Environment": "Production"},
				Exposure: models.ExposureSafe,
			},
			{
				ID:      "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/nimbus-prod-rg/providers/Microsoft.Compute/virtualMachines/azure-web-01",
				ShortID: "azure-web-01",
				Type:    models.NodeTypeAzureVM, Provider: "azure",
				AccountID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Region: "eastus",
				Name: "azure-web-01", VPC: "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/nimbus-prod-rg/providers/Microsoft.Network/virtualNetworks/azure-prod-vnet",
				PublicIP: "198.51.100.2", PrivateIPs: []string{"10.0.0.4"},
				IAMRole:  "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/nimbus-prod-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/azure-web-identity",
				Tags:     map[string]string{"Environment": "Production", "Name": "azure-web-01", "Tier": "Web", "OS": "Ubuntu 22.04"},
				Exposure: models.ExposureSafe,
			},
			{
				ID:      "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/nimbus-prod-rg/providers/Microsoft.Sql/servers/azure-prod-sql/databases/orders-db",
				ShortID: "azure-prod-sql",
				Type:    models.NodeTypeAzureSQL, Provider: "azure",
				AccountID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Region: "eastus",
				Name:     "azure-prod-sql",
				Tags:     map[string]string{"Environment": "Production", "Tier": "Database"},
				Exposure: models.ExposureSafe,
			},

			// ===== INTERNET NODE (for visualization) =====
			{
				ID: "internet", ShortID: "internet",
				Type: "internet", Provider: "global",
				Name:     "Internet",
				Tags:     map[string]string{},
				Exposure: models.ExposureSafe,
			},
		},
		Edges: []models.Edge{
			// VPC → Internet Gateway
			{SourceID: "vpc-0a1b2c3d4e5f00001", TargetID: "igw-0a1b2c3d4e5f00001", EdgeType: "attached_to"},
			// Internet → IGW (public ingress)
			{SourceID: "internet", TargetID: "igw-0a1b2c3d4e5f00001", EdgeType: "network_ingress", PortRange: "80-443", Protocol: "tcp"},
			// IGW → Public Subnet
			{SourceID: "igw-0a1b2c3d4e5f00001", TargetID: "subnet-0a1b2c3d4e5f00001", EdgeType: "network_ingress", PortRange: "0-65535", Protocol: "all"},
			// Public Subnet → ALB
			{SourceID: "subnet-0a1b2c3d4e5f00001", TargetID: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/0a1b2c3d4e5f", EdgeType: "network_ingress", PortRange: "80-443", Protocol: "tcp"},
			// ALB → Web Instance 1 (CRITICAL — SSH also exposed directly)
			{SourceID: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/0a1b2c3d4e5f", TargetID: "i-0a1b2c3d4e5f00001", EdgeType: "network_ingress", PortRange: "80", Protocol: "tcp"},
			{SourceID: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/0a1b2c3d4e5f", TargetID: "i-0a1b2c3d4e5f00001", EdgeType: "network_ingress", PortRange: "443", Protocol: "tcp"},
			// Internet → Web Instance 1 directly (CRITICAL: SSH exposed to 0.0.0.0/0)
			{SourceID: "internet", TargetID: "i-0a1b2c3d4e5f00001", EdgeType: "network_ingress", PortRange: "22", Protocol: "tcp"},
			// ALB → Web Instance 2
			{SourceID: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/0a1b2c3d4e5f", TargetID: "i-0a1b2c3d4e5f00002", EdgeType: "network_ingress", PortRange: "80", Protocol: "tcp"},
			{SourceID: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/0a1b2c3d4e5f", TargetID: "i-0a1b2c3d4e5f00002", EdgeType: "network_ingress", PortRange: "443", Protocol: "tcp"},
			// Web Instance 1 → App Instance
			{SourceID: "i-0a1b2c3d4e5f00001", TargetID: "i-0a1b2c3d4e5f00003", EdgeType: "network_ingress", PortRange: "8080", Protocol: "tcp"},
			// Web Instance 2 → App Instance
			{SourceID: "i-0a1b2c3d4e5f00002", TargetID: "i-0a1b2c3d4e5f00003", EdgeType: "network_ingress", PortRange: "8080", Protocol: "tcp"},
			// App Instance → RDS
			{SourceID: "i-0a1b2c3d4e5f00003", TargetID: "rds-prod-db-01", EdgeType: "network_ingress", PortRange: "3306", Protocol: "tcp"},
			// Security Group attachments
			{SourceID: "sg-0a1b2c3d4e5f00001", TargetID: "i-0a1b2c3d4e5f00001", EdgeType: "sg_attached"},
			{SourceID: "sg-0a1b2c3d4e5f00001", TargetID: "i-0a1b2c3d4e5f00002", EdgeType: "sg_attached"},
			{SourceID: "sg-0a1b2c3d4e5f00001", TargetID: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/0a1b2c3d4e5f", EdgeType: "sg_attached"},
			{SourceID: "sg-0a1b2c3d4e5f00002", TargetID: "i-0a1b2c3d4e5f00003", EdgeType: "sg_attached"},
			{SourceID: "sg-0a1b2c3d4e5f00003", TargetID: "rds-prod-db-01", EdgeType: "sg_attached"},
			// IAM role edges
			{SourceID: "i-0a1b2c3d4e5f00001", TargetID: "arn:aws:s3:::nimbus-prod-assets", EdgeType: "iam_can_read", ViaIdentity: "nimbus-web-role"},
			{SourceID: "i-0a1b2c3d4e5f00001", TargetID: "arn:aws:s3:::nimbus-prod-assets", EdgeType: "iam_can_write", ViaIdentity: "nimbus-web-role"},
			// GCP edges
			{SourceID: "projects/nimbus-gcp-prod/global/networks/gcp-prod-vpc", TargetID: "projects/nimbus-gcp-prod/zones/us-central1-a/instances/gce-web-01", EdgeType: "network_ingress", PortRange: "0-65535", Protocol: "tcp"},
			{SourceID: "internet", TargetID: "projects/nimbus-gcp-prod/zones/us-central1-a/instances/gce-web-01", EdgeType: "network_ingress", PortRange: "443", Protocol: "tcp"},
			{SourceID: "projects/nimbus-gcp-prod/zones/us-central1-a/instances/gce-web-01", TargetID: "projects/nimbus-gcp-prod/instances/gcp-prod-db", EdgeType: "network_ingress", PortRange: "5432", Protocol: "tcp"},
			// Azure edges
			{SourceID: "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/nimbus-prod-rg/providers/Microsoft.Network/virtualNetworks/azure-prod-vnet", TargetID: "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/nimbus-prod-rg/providers/Microsoft.Compute/virtualMachines/azure-web-01", EdgeType: "network_ingress", PortRange: "0-65535", Protocol: "tcp"},
			{SourceID: "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/nimbus-prod-rg/providers/Microsoft.Compute/virtualMachines/azure-web-01", TargetID: "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/nimbus-prod-rg/providers/Microsoft.Sql/servers/azure-prod-sql/databases/orders-db", EdgeType: "network_ingress", PortRange: "1433", Protocol: "tcp"},
		},
		Findings: []models.Finding{exposedFinding, albHTTPFinding, memoryDBFinding, publicS3Finding},
	}
}
