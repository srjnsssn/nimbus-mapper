# Nimbus Mapper - Visual Identity & Accessibility Guidelines (design.md)

## 1. Design Philosophy: "Terminal to Browser"
The UI must feel like a natural extension of a CLI environment. It prioritizes information density, raw data visibility, and rapid threat identification over decorative elements. Default to a strict Dark Mode.

## 2. Color Palette
Use these exact hex codes. No gradients, keep colors solid and utilitarian.

### Base Colors (Theme)
- **Background (Canvas):** `#0F172A` (Deep Slate - reduces eye strain in dark environments).
- **Surface (Panels/HUD):** `#1E293B` (Slightly lighter slate for floating menus).
- **Text Primary:** `#F8FAFC` (Off-white for high readability).
- **Text Secondary/Muted:** `#94A3B8` (For metadata, ARNs, and internal IDs).

### Semantic Colors (Status & Node Types)
Crucial for rapid Red Team/SysAdmin assessment:
- **Nimbus Accent (Brand):** `#0EA5E9` (Electric Blue - for active selections and neutral cloud resources like VPCs/Subnets).
- **Danger (Exposed/Public):** `#EF4444` (High-alert Red - for resources with 0.0.0.0/0 exposure or public IPs).
- **Warning (Misconfigured/Review):** `#F59E0B` (Amber - for missing encryption or permissive internal IAM roles).
- **Secure (Private/Isolated):** `#10B981` (Emerald Green - for internal, isolated resources).

## 3. Typography
Keep it strict. We rely on system fonts to avoid external dependencies or heavy payload sizes.

- **Data & IP Addresses (Monospace):** `ui-monospace, 'JetBrains Mono', 'Fira Code', 'Courier New', monospace`. 
  - *Rule:* ALL resource IDs, IP addresses, ports, and tags MUST use the monospace font to ensure character alignment and CLI familiarity.
- **Headings & UI Elements (Sans-Serif):** `system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`.
  - *Rule:* Use for panel titles, buttons, and high-level structural text.

## 4. Global Styles & UI Components
- **Borders:** `1px solid #334155`. Keep borders sharp and thin. No heavy, soft shadows.
- **Border Radius:** `4px` (Subtle rounding, avoid pill-shaped or highly rounded elements).
- **Shadows:** Use glowing effects exclusively to highlight active or critical nodes, not for structural depth (e.g., `box-shadow: 0 0 8px #EF4444` for an exposed node in focus).
- **Spacing:** Use a tight, 4px-based grid system (4px, 8px, 16px, 24px). Information density is paramount; do not waste screen real estate with massive padding.
- **Graph Nodes (Cytoscape.js):** Nodes must be geometrically distinct (e.g., squares for compute instances, circles for databases, diamonds for load balancers) to aid identification beyond just color.

## 5. Accessibility (A11y) Strict Rules
This tool must be fully usable by engineers with visual impairments or specific workflow constraints.

- **Color Reliance Prohibition:** NEVER use color as the sole indicator of status. If a node is "Danger/Red", it MUST also have a visual icon (like a warning triangle `⚠️` or an exclamation mark) or a distinct border style (e.g., dashed border) to ensure colorblind users can identify exposed infrastructure.
- **Contrast Ratios:** All text must meet the WCAG 2.1 AAA standard (at least 7:1 contrast ratio against its background). The provided palette adheres to this.
- **Keyboard Navigation:** The graph canvas and the floating HUD must be fully navigable via keyboard (`Tab` to cycle nodes, `Enter` to open node details, `Escape` to close panels).
- **Focus States:** Every interactive element must have a highly visible focus ring (e.g., `outline: 2px solid #0EA5E9; outline-offset: 2px;`).
- **ARIA Attributes:** Any dynamic HTML injected into the DOM (e.g., expanding a node's details in a sidebar) must announce its state changes to screen readers using `aria-live="polite"` and proper `aria-expanded` tags.
