package generator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/yourusername/nimbus/internal/models"
)

type CytoscapePayload struct {
	Elements CytoscapeElements `json:"elements"`
	Meta     ScanMeta          `json:"meta"`
}

type CytoscapeElements struct {
	Nodes []CytoscapeNode `json:"nodes"`
	Edges []CytoscapeEdge `json:"edges"`
}

type CytoscapeNode struct {
	Data CytoscapeNodeData `json:"data"`
}

type CytoscapeNodeData struct {
	ID            string           `json:"id"`
	Label         string           `json:"label"`
	Provider      string           `json:"provider"`
	Region        string           `json:"region"`
	Type          string           `json:"type"`
	ExposureLevel string           `json:"exposureLevel"`
	PublicIP      string           `json:"publicIp,omitempty"`
	FindingCount  int              `json:"findingCount"`
	Findings      []FindingSummary `json:"findings,omitempty"`
	Parent        string           `json:"parent,omitempty"`
}

type FindingSummary struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
}

type CytoscapeEdge struct {
	Data CytoscapeEdgeData `json:"data"`
}

type CytoscapeEdgeData struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	EdgeType string `json:"edgeType"`
	Label    string `json:"label,omitempty"`
}

type ScanMeta struct {
	Version       string   `json:"version"`
	GeneratedAt   string   `json:"generatedAt"`
	TotalNodes    int      `json:"totalNodes"`
	TotalFindings int      `json:"totalFindings"`
	Providers     []string `json:"providers"`
}

func ExportGraph(g *models.Graph, outputPath string) error {
	payload := buildPayload(g)

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal graph data: %w", err)
	}

	tmplBytes, err := WebFS.ReadFile("web/index.html")
	if err != nil {
		return fmt.Errorf("read template: %w", err)
	}

	cssBytes, err := WebFS.ReadFile("web/style.css")
	if err != nil {
		return fmt.Errorf("read style: %w", err)
	}

	jsBytes, err := WebFS.ReadFile("web/app.js")
	if err != nil {
		return fmt.Errorf("read app js: %w", err)
	}

	tmplData := struct {
		JSONPayload template.JS
		StyleCSS    template.CSS
		AppJS       template.JS
	}{
		JSONPayload: template.JS(jsonBytes),
		StyleCSS:    template.CSS(cssBytes),
		AppJS:       template.JS(jsBytes),
	}

	tmpl, err := template.New("graph").Parse(string(tmplBytes))
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, tmplData); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	return nil
}

func buildPayload(g *models.Graph) CytoscapePayload {
	providerSet := map[string]bool{}
	clusterSet := map[string]bool{}
	var nodes []CytoscapeNode
	var edges []CytoscapeEdge

	for _, r := range g.Nodes {
		providerSet[r.Provider] = true

		clusterID := "cluster-" + r.Provider + "-" + r.Region
		if !clusterSet[clusterID] {
			clusterSet[clusterID] = true
			regionLabel := r.Region
			if regionLabel == "" {
				regionLabel = "global"
			}
			nodes = append(nodes, CytoscapeNode{
				Data: CytoscapeNodeData{
					ID:       clusterID,
					Label:    strings.ToUpper(r.Provider) + " / " + regionLabel,
					Provider: r.Provider,
					Region:   regionLabel,
				},
			})
		}

		var findings []FindingSummary
		for _, f := range r.Findings {
			findings = append(findings, FindingSummary{
				Severity: string(f.Severity),
				Title:    f.Title,
			})
		}

		label := r.Name
		if label == "" {
			label = r.ShortID
		}
		if label == "" {
			parts := strings.Split(r.ID, "/")
			label = parts[len(parts)-1]
		}

		nodes = append(nodes, CytoscapeNode{
			Data: CytoscapeNodeData{
				ID:            r.ID,
				Label:         label,
				Provider:      r.Provider,
				Region:        r.Region,
				Type:          r.Type,
				ExposureLevel: string(r.Exposure),
				PublicIP:      r.PublicIP,
				FindingCount:  len(r.Findings),
				Findings:      findings,
				Parent:        clusterID,
			},
		})
	}

	for i, e := range g.Edges {
		edges = append(edges, CytoscapeEdge{
			Data: CytoscapeEdgeData{
				ID:       fmt.Sprintf("e-%d", i),
				Source:   e.SourceID,
				Target:   e.TargetID,
				EdgeType: e.EdgeType,
				Label:    e.PortRange,
			},
		})
	}

	providers := make([]string, 0, len(providerSet))
	for p := range providerSet {
		providers = append(providers, p)
	}

	totalFindings := len(g.Findings)
	if totalFindings == 0 {
		for _, n := range g.Nodes {
			totalFindings += len(n.Findings)
		}
	}

	return CytoscapePayload{
		Elements: CytoscapeElements{Nodes: nodes, Edges: edges},
		Meta: ScanMeta{
			Version:       g.Metadata.Version,
			GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
			TotalNodes:    len(g.Nodes),
			TotalFindings: totalFindings,
			Providers:     providers,
		},
	}
}
