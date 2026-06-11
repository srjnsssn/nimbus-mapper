---
name: cytoscape-embed-injector
description: >
  Rules for generating the Nimbus Mapper graph visualization output: a single portable
  offline HTML file with Cytoscape.js embedded. Covers go:embed asset bundling, safe JSON
  data injection into HTML templates, Cytoscape.js initialization and layout selection,
  clustering for large graphs (500+ nodes), node/edge styling by ExposureLevel and provider,
  the -oG flag behavior, and the optional --serve flag for live browser mode.
triggers:
  - "when generating or modifying the HTML graph output (-oG flag)"
  - "when working with go:embed for frontend assets"
  - "when injecting NimbusNode/NimbusEdge data into the HTML template"
  - "when configuring Cytoscape.js layouts, styles, or clustering"
  - "when the graph has performance issues with large node counts"
  - "when adding interactivity to the graph (tooltips, filters, click events)"
  - "when setting up or modifying the optional --serve flag"
---

# Skill: cytoscape-embed-injector

## Project Context

Nimbus Mapper produces a graph of cloud resources and their relationships.
The `-oG graph.html` flag generates a **single, self-contained HTML file** that:
- Works with no internet connection (Cytoscape.js and all CSS are inlined).
- Requires no local server — open directly in a browser via `file://`.
- Renders hundreds to thousands of cloud nodes with color-coded security status.
- Clusters nodes by provider/region to prevent visual chaos on large environments.

The Go binary owns the full pipeline: scan → normalize → serialize → inject → write file.
No external build step, no Node.js runtime, no separate frontend build.

---

## Asset Structure

```
internal/
  assets/
    web/
      index.html       ← master template with {{.JSONPayload}} placeholder
      app.js           ← Cytoscape.js (vendored, full bundle) + Nimbus graph logic
      style.css        ← graph styles + UI chrome
    assets.go          ← go:embed declaration
```

**All three files are committed to the repository as static files.**
Cytoscape.js is vendored (downloaded once, committed). No npm, no webpack, no build step.

```go
// internal/assets/assets.go

package assets

import "embed"

//go:embed web/index.html web/app.js web/style.css
var FS embed.FS

// Convenience accessors
func IndexHTML() []byte {
    b, _ := FS.ReadFile("web/index.html")
    return b
}
```

### Vendoring Cytoscape.js

Download the minified bundle once and commit it:
```bash
# Cytoscape.js core + required extensions
curl -o internal/assets/web/cytoscape.min.js \
  https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js

# For clustering:
curl -o internal/assets/web/cytoscape-cose-bilkent.min.js \
  https://cdn.jsdelivr.net/npm/cytoscape-cose-bilkent@4.1.0/cytoscape-cose-bilkent.min.js

# Inline these into app.js during vendor step, never reference CDN URLs at runtime
```

**After vendoring, update the `//go:embed` directive to include the vendored JS files.**

---

## HTML Template

The template has a single injection point: `{{.JSONPayload}}`.
It must be placed inside a `<script>` tag, not in an HTML attribute or data tag:

```html
<!-- internal/assets/web/index.html -->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Nimbus Mapper — Cloud Security Graph</title>
  <style>
    /* Inline style.css at build time OR load from same directory */
    body { margin: 0; background: #0f172a; font-family: system-ui, sans-serif; }
    #cy   { width: 100vw; height: 100vh; }
    #controls { position: fixed; top: 16px; left: 16px; z-index: 10; }
    /* ... full CSS in style.css ... */
  </style>
</head>
<body>
  <div id="controls">
    <input id="search" type="text" placeholder="Filter nodes…">
    <select id="severity-filter">
      <option value="all">All severities</option>
      <option value="critical">Critical only</option>
      <option value="high">High+</option>
    </select>
    <button id="fit-btn">Fit graph</button>
  </div>
  <div id="cy"></div>

  <!-- Vendored Cytoscape.js — no CDN reference -->
  <script>/* cytoscape.min.js inlined here by Go template renderer */</script>

  <!-- Injected scan data — MUST use json.Marshal, never fmt.Sprintf -->
  <script>
    const NIMBUS_DATA = {{.JSONPayload}};
  </script>

  <!-- Graph initialization logic -->
  <script src="app.js"></script>
</body>
</html>
```

**The placeholder `{{.JSONPayload}}` is replaced at runtime by the Go template engine,
not at build time.** The committed `index.html` contains the literal string `{{.JSONPayload}}`.

---

## Data Injection (Go Side)

```go
// internal/output/graph.go

package output

import (
    "bytes"
    "encoding/json"
    "html/template"
    "os"

    "github.com/your-org/nimbus-mapper/internal/assets"
    "github.com/your-org/nimbus-mapper/internal/model"
    "github.com/your-org/nimbus-mapper/internal/secrets"
)

// CytoscapePayload is the JSON structure consumed by app.js
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
    ID            string `json:"id"`
    Label         string `json:"label"`
    Provider      string `json:"provider"`      // "aws" | "gcp" | "azure"
    Region        string `json:"region"`
    Type          string `json:"type"`           // NodeType constant
    ExposureLevel string `json:"exposureLevel"`  // "Critical" | "Warning" | "Safe"
    PublicIP      string `json:"publicIp,omitempty"`
    FindingCount  int    `json:"findingCount"`
    // Parent for clustering: "cluster-aws-us-east-1"
    Parent        string `json:"parent,omitempty"`
}

type CytoscapeEdge struct {
    Data CytoscapeEdgeData `json:"data"`
}

type CytoscapeEdgeData struct {
    ID       string `json:"id"`
    Source   string `json:"source"`
    Target   string `json:"target"`
    EdgeType string `json:"edgeType"` // "network_ingress" | "iam_can_read" | ...
    Label    string `json:"label,omitempty"`
}

type ScanMeta struct {
    Version      string `json:"version"`
    GeneratedAt  string `json:"generatedAt"`
    TotalNodes   int    `json:"totalNodes"`
    TotalFindings int   `json:"totalFindings"`
    Providers    []string `json:"providers"`
}

// WriteGraphHTML generates the self-contained HTML graph file.
func WriteGraphHTML(result *pipeline.ScanResult, outputPath string, maskIDs bool) error {
    // 1. Build Cytoscape payload from scan result
    payload := buildCytoscapePayload(result, maskIDs)

    // 2. Serialize to JSON safely using encoding/json (NEVER fmt.Sprintf)
    jsonBytes, err := json.Marshal(payload)
    if err != nil {
        return fmt.Errorf("serializing graph data: %w", err)
    }

    // 3. Mark as safe HTML — json.Marshal produces valid JS object literal
    //    html/template would escape '<', '>', '&' inside JSON strings by default.
    //    Use template.JS() to prevent double-escaping of the JSON.
    tmplData := struct {
        JSONPayload template.JS
    }{
        JSONPayload: template.JS(jsonBytes),
    }

    // 4. Parse and execute the embedded template
    tmplContent := string(assets.IndexHTML())
    tmpl, err := template.New("graph").Parse(tmplContent)
    if err != nil {
        return fmt.Errorf("parsing graph template: %w", err)
    }

    var buf bytes.Buffer
    if err := tmpl.Execute(&buf, tmplData); err != nil {
        return fmt.Errorf("executing graph template: %w", err)
    }

    // 5. Write to file
    if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
        return fmt.Errorf("writing graph file to %s: %w", outputPath, err)
    }

    return nil
}
```

### Building the Cytoscape Payload from NimbusNodes

```go
func buildCytoscapePayload(result *pipeline.ScanResult, maskIDs bool) CytoscapePayload {
    var nodes []CytoscapeNode
    var edges []CytoscapeEdge

    // Add cluster parent nodes first (one per provider+region combination)
    clusters := map[string]bool{}
    for _, n := range result.Nodes {
        clusterID := "cluster-" + n.Provider + "-" + n.Region
        if !clusters[clusterID] {
            clusters[clusterID] = true
            nodes = append(nodes, CytoscapeNode{Data: CytoscapeNodeData{
                ID:       clusterID,
                Label:    n.Provider + " / " + n.Region,
                Provider: n.Provider,
            }})
        }
    }

    // Add resource nodes
    for _, n := range result.Nodes {
        resourceID := n.ID
        if maskIDs {
            resourceID = secrets.RedactString(n.ID, true)
        }
        nodes = append(nodes, CytoscapeNode{
            Data: CytoscapeNodeData{
                ID:            resourceID,
                Label:         labelForNode(n),
                Provider:      n.Provider,
                Region:        n.Region,
                Type:          n.Type,
                ExposureLevel: string(n.ExposureLevel),
                PublicIP:      n.PublicIP,
                FindingCount:  len(n.Findings),
                Parent:        "cluster-" + n.Provider + "-" + n.Region,
            },
        })
    }

    // Add edges
    for i, e := range result.Edges {
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

    return CytoscapePayload{
        Elements: CytoscapeElements{Nodes: nodes, Edges: edges},
        Meta: ScanMeta{
            Version:       version,
            GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
            TotalNodes:    len(result.Nodes),
            TotalFindings: len(result.Findings),
            Providers:     result.Providers(),
        },
    }
}

// labelForNode returns a short, human-readable label for a node.
func labelForNode(n model.NimbusNode) string {
    if n.Name != "" { return n.Name }
    if n.ShortID != "" { return n.ShortID }
    // Fallback: last segment of the full ID
    parts := strings.Split(n.ID, "/")
    return parts[len(parts)-1]
}
```

---

## Cytoscape.js Frontend (app.js)

```javascript
// internal/assets/web/app.js
// NIMBUS_DATA is injected by the Go template as a JS object (no JSON.parse needed)

(function() {
  'use strict';

  // ── Cytoscape Style Sheet ──────────────────────────────────────────────
  const NODE_STYLES = [
    // Cluster parent nodes (regions)
    {
      selector: ':parent',
      style: {
        'background-color': '#1e293b',
        'border-color': '#334155',
        'border-width': 1,
        'label': 'data(label)',
        'color': '#94a3b8',
        'font-size': '11px',
        'text-valign': 'top',
        'text-halign': 'center',
        'padding': '20px',
      }
    },
    // Default node style
    {
      selector: 'node',
      style: {
        'width': 36, 'height': 36,
        'label': 'data(label)',
        'font-size': '9px',
        'color': '#e2e8f0',
        'text-valign': 'bottom',
        'text-margin-y': 4,
        'background-color': '#334155',
        'border-width': 2,
        'border-color': '#475569',
      }
    },
    // ExposureLevel: Critical — red, pulsing border
    {
      selector: 'node[exposureLevel = "Critical"]',
      style: {
        'border-color': '#ef4444',
        'border-width': 3,
        'background-color': '#450a0a',
      }
    },
    // ExposureLevel: Warning — amber
    {
      selector: 'node[exposureLevel = "Warning"]',
      style: {
        'border-color': '#f59e0b',
        'border-width': 2,
        'background-color': '#451a03',
      }
    },
    // ExposureLevel: Safe — green
    {
      selector: 'node[exposureLevel = "Safe"]',
      style: {
        'border-color': '#22c55e',
        'border-width': 1,
        'background-color': '#052e16',
      }
    },
    // Provider shapes: AWS=rectangle, GCP=ellipse, Azure=diamond
    { selector: 'node[provider = "aws"]',   style: { 'shape': 'round-rectangle' } },
    { selector: 'node[provider = "gcp"]',   style: { 'shape': 'ellipse' } },
    { selector: 'node[provider = "azure"]', style: { 'shape': 'diamond' } },
    // Edges
    {
      selector: 'edge',
      style: {
        'width': 1.5,
        'line-color': '#475569',
        'target-arrow-color': '#475569',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'label': 'data(label)',
        'font-size': '8px',
        'color': '#94a3b8',
      }
    },
    // IAM edges: dashed purple
    {
      selector: 'edge[edgeType ^= "iam_"]',
      style: {
        'line-style': 'dashed',
        'line-color': '#a78bfa',
        'target-arrow-color': '#a78bfa',
      }
    },
    // Network edges: solid color by direction
    {
      selector: 'edge[edgeType = "network_ingress"]',
      style: { 'line-color': '#f87171', 'target-arrow-color': '#f87171' }
    },
  ];

  // ── Layout Selection ───────────────────────────────────────────────────
  // Choose layout based on node count for performance
  function pickLayout(nodeCount) {
    if (nodeCount > 500) {
      // Fast force-directed for large graphs
      return { name: 'cose-bilkent', animate: false, randomize: true,
               nodeDimensionsIncludeLabels: true, idealEdgeLength: 80 };
    }
    if (nodeCount > 100) {
      return { name: 'cose', animate: false, randomize: false,
               componentSpacing: 80 };
    }
    // Small graphs: breadthfirst grouped by cluster
    return { name: 'breadthfirst', animate: true, spacingFactor: 1.5,
             padding: 30, avoidOverlap: true };
  }

  // ── Initialize Cytoscape ───────────────────────────────────────────────
  const cy = cytoscape({
    container: document.getElementById('cy'),
    elements:  NIMBUS_DATA.elements,
    style:     NODE_STYLES,
    layout:    pickLayout(NIMBUS_DATA.meta.totalNodes),
    minZoom:   0.05,
    maxZoom:   3,
  });

  // ── Tooltip on hover ───────────────────────────────────────────────────
  cy.on('mouseover', 'node[!parent]', function(evt) {
    const node = evt.target;
    const d = node.data();
    if (d.parent) { // skip cluster parent nodes
      showTooltip(evt.renderedPosition, [
        `<strong>${d.label}</strong>`,
        `Type: ${d.type}`,
        `Provider: ${d.provider} / ${d.region}`,
        d.publicIp ? `Public IP: ${d.publicIp}` : null,
        `Findings: ${d.findingCount}`,
        `Exposure: ${d.exposureLevel}`,
      ].filter(Boolean).join('<br>'));
    }
  });
  cy.on('mouseout', 'node', hideTooltip);

  // ── Search / Filter ────────────────────────────────────────────────────
  document.getElementById('search').addEventListener('input', function(e) {
    const q = e.target.value.toLowerCase();
    cy.nodes('[?parent]').forEach(n => { // only leaf nodes
      const match = !q || n.data('label').toLowerCase().includes(q)
                      || n.data('type').toLowerCase().includes(q);
      n.style('display', match ? 'element' : 'none');
    });
  });

  document.getElementById('severity-filter').addEventListener('change', function(e) {
    const val = e.target.value;
    cy.nodes('[?parent]').forEach(n => {
      const level = n.data('exposureLevel');
      let show = true;
      if (val === 'critical') show = level === 'Critical';
      if (val === 'high')     show = level === 'Critical' || level === 'Warning';
      n.style('display', show ? 'element' : 'none');
    });
  });

  document.getElementById('fit-btn').addEventListener('click', () => cy.fit());

  // ── Tooltip helpers ────────────────────────────────────────────────────
  const tooltip = document.createElement('div');
  tooltip.id = 'tooltip';
  tooltip.style.cssText =
    'position:fixed;background:#1e293b;border:1px solid #334155;' +
    'color:#e2e8f0;padding:8px 12px;border-radius:6px;font-size:12px;' +
    'pointer-events:none;display:none;z-index:100;max-width:280px;line-height:1.5';
  document.body.appendChild(tooltip);

  function showTooltip(pos, html) {
    tooltip.innerHTML = html;
    tooltip.style.left = (pos.x + 12) + 'px';
    tooltip.style.top  = (pos.y + 12) + 'px';
    tooltip.style.display = 'block';
  }
  function hideTooltip() { tooltip.style.display = 'none'; }

})();
```

---

## Performance: Handling Large Graphs (500+ nodes)

When `NimbusData.meta.totalNodes > 500`, apply these strategies:

### Go side: reduce payload size
```go
func buildCytoscapePayload(result *pipeline.ScanResult, maskIDs bool) CytoscapePayload {
    totalNodes := len(result.Nodes)

    // For very large graphs (>500), omit edges between Safe nodes
    // to keep the JSON payload manageable
    var filteredEdges []model.NimbusEdge
    if totalNodes > 500 {
        for _, e := range result.Edges {
            srcNode := result.NodeByID(e.SourceID)
            dstNode := result.NodeByID(e.TargetID)
            // Only include edges involving at least one non-safe node
            if srcNode != nil && srcNode.ExposureLevel != model.ExposureSafe ||
               dstNode != nil && dstNode.ExposureLevel != model.ExposureSafe {
                filteredEdges = append(filteredEdges, e)
            }
        }
    } else {
        filteredEdges = result.Edges
    }
    // ... rest of payload building
}
```

### JS side: use `cose-bilkent` layout and disable animation
```javascript
// For graphs > 500 nodes, cose-bilkent is significantly faster than cose
// and must be pre-bundled in app.js (see vendoring section).
// Always set animate: false for initial layout on large graphs —
// animating 1000 nodes causes browser to freeze for several seconds.
```

### Warning banner for very large graphs
```go
// In WriteGraphHTML, after building the payload:
if len(result.Nodes) > 2000 {
    slog.Warn("graph has many nodes, HTML output may be slow to render in browser",
        "node_count", len(result.Nodes),
        "suggestion", "use --format json for programmatic processing instead")
}
```

---

## The --serve Flag (Optional Live Mode)

When `--serve` is passed, start a local HTTP server instead of writing a file.
This enables hot-reload and is faster for iterative exploration:

```go
// internal/output/serve.go

func ServeGraph(result *pipeline.ScanResult, port int, maskIDs bool) error {
    payload := buildCytoscapePayload(result, maskIDs)
    jsonBytes, _ := json.Marshal(payload)

    // Serve the embedded assets + inject data via query or template
    mux := http.NewServeMux()

    // Serve static assets from embed.FS
    mux.Handle("/static/", http.FileServer(http.FS(assets.FS)))

    // Main page: template with injected data
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        tmpl, _ := template.New("g").Parse(string(assets.IndexHTML()))
        tmpl.Execute(w, struct{ JSONPayload template.JS }{
            JSONPayload: template.JS(jsonBytes),
        })
    })

    addr := fmt.Sprintf("127.0.0.1:%d", port)
    slog.Info("serving nimbus graph", "url", "http://"+addr)
    // Open browser automatically
    openBrowser("http://" + addr)
    return http.ListenAndServe(addr, mux)
}
```

**Key constraints for `--serve`:**
- Always bind to `127.0.0.1`, never `0.0.0.0`. Security scanner output is sensitive data.
- Default port: `7777`. Allow override via `--port` flag.
- Never start the server in the default `-oG` flow — file output is the default.

---

## Anti-Patterns — NEVER DO THIS

- **NEVER** use `fmt.Sprintf` to build the `<script>` tag with JSON data:
  `fmt.Sprintf("const data = %s", jsonStr)`. This is an XSS vector if any resource name
  contains `</script>`. Always use `html/template` with `template.JS()`.
- **NEVER** reference a CDN URL (cdnjs, jsdelivr, unpkg) in the generated HTML.
  The output file must work on an air-gapped machine. All JS/CSS must be vendored and inlined.
- **NEVER** use `json.RawMessage` or raw byte slices for the `JSONPayload` template field.
  Use `template.JS` so the template engine handles escaping correctly.
- **NEVER** start `net/http.ListenAndServe` in the default `-oG` output path.
  File generation is the default. The server is an opt-in `--serve` flag.
- **NEVER** bind the `--serve` HTTP server to `0.0.0.0`. The graph contains sensitive
  infrastructure data. Always bind to `127.0.0.1` only.
- **NEVER** embed `node_modules/`, `package.json`, or any npm artifact via `//go:embed`.
  Cytoscape.js must be vendored as a single pre-built `.min.js` file.
- **NEVER** include `RawMetadata` from `NimbusNode` in the Cytoscape payload.
  It contains raw cloud API responses with account IDs, internal ARNs, and other
  sensitive data. Only include the normalized fields defined in `CytoscapeNodeData`.
- **NEVER** generate the graph with `animate: true` when the node count exceeds 200.
  Animating layouts in the browser blocks the main thread and appears frozen to the user.
