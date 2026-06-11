package models

import "encoding/json"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type ExposureLevel string

const (
	ExposureCritical ExposureLevel = "Critical"
	ExposureWarning  ExposureLevel = "Warning"
	ExposureSafe     ExposureLevel = "Safe"
)

type Resource struct {
	ID            string            `json:"id"`
	ShortID       string            `json:"shortId"`
	Type          string            `json:"type"`
	Provider      string            `json:"provider"`
	AccountID     string            `json:"accountId"`
	Region        string            `json:"region"`
	Zone          string            `json:"zone,omitempty"`
	Name          string            `json:"name"`
	PublicIP      string            `json:"publicIp,omitempty"`
	PrivateIPs    []string          `json:"privateIps,omitempty"`
	Subnet        string            `json:"subnet,omitempty"`
	VPC           string            `json:"vpc,omitempty"`
	IAMRole       string            `json:"iamRole,omitempty"`
	AttachedRules []string          `json:"attachedRules,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
	Exposure      ExposureLevel     `json:"exposure"`
	Findings      []Finding         `json:"findings,omitempty"`
	RawMetadata   json.RawMessage   `json:"-"`
}

type Finding struct {
	ID           string            `json:"id"`
	RuleID       string            `json:"ruleId"`
	Severity     Severity          `json:"severity"`
	Provider     string            `json:"provider"`
	AccountID    string            `json:"accountId"`
	Region       string            `json:"region"`
	ResourceID   string            `json:"resourceId"`
	ResourceType string            `json:"resourceType"`
	Title        string            `json:"title"`
	Description  string            `json:"description"`
	Remediation  string            `json:"remediation"`
	References   []string          `json:"references,omitempty"`
	RawEvidence  map[string]string `json:"rawEvidence,omitempty"`
}

type Edge struct {
	SourceID      string `json:"sourceId"`
	TargetID      string `json:"targetId"`
	PortRange     string `json:"portRange,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	EdgeType      string `json:"edgeType"`
	ViaIdentity   string `json:"viaIdentity,omitempty"`
	Bidirectional bool   `json:"bidirectional"`
}

type Graph struct {
	Metadata GraphMetadata `json:"metadata"`
	Nodes    []Resource    `json:"nodes"`
	Edges    []Edge        `json:"edges"`
	Findings []Finding     `json:"findings"`
}

type GraphMetadata struct {
	Version       string   `json:"version"`
	GeneratedAt   string   `json:"generatedAt"`
	TotalNodes    int      `json:"totalNodes"`
	TotalEdges    int      `json:"totalEdges"`
	TotalFindings int      `json:"totalFindings"`
	Providers     []string `json:"providers"`
}

const (
	NodeTypeEC2Instance     = "aws_ec2_instance"
	NodeTypeSecurityGroup   = "aws_security_group"
	NodeTypeS3Bucket        = "aws_s3_bucket"
	NodeTypeRDSInstance     = "aws_rds_instance"
	NodeTypeALB             = "aws_alb"
	NodeTypeInternetGateway = "aws_internet_gateway"
	NodeTypeVPC             = "aws_vpc"
	NodeTypeSubnet          = "aws_subnet"

	NodeTypeGCEInstance = "gcp_compute_instance"
	NodeTypeGCSBucket   = "gcp_storage_bucket"
	NodeTypeCloudSQL    = "gcp_cloud_sql"
	NodeTypeGCPVPC      = "gcp_vpc"

	NodeTypeAzureVM   = "azure_virtual_machine"
	NodeTypeAzureSQL  = "azure_sql_database"
	NodeTypeAzureVNet = "azure_vnet"
)
