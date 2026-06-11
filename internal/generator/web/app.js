(function () {
  'use strict';

  var data = nimbusData;

  function pickShape(type) {
    if (!type) return 'ellipse';
    var compute = ['aws_ec2_instance', 'gcp_compute_instance', 'azure_virtual_machine',
      'aws_lambda_function', 'gcp_cloud_run_service'];
    var database = ['aws_rds_instance', 'gcp_cloud_sql', 'azure_sql_database'];
    var network = ['aws_alb', 'aws_internet_gateway', 'aws_vpc', 'aws_subnet',
      'gcp_vpc', 'azure_vnet', 'internet'];
    var storage = ['aws_s3_bucket', 'gcp_storage_bucket', 'azure_storage_account'];
    if (database.indexOf(type) !== -1) return 'ellipse';
    if (network.indexOf(type) !== -1) return 'diamond';
    if (storage.indexOf(type) !== -1) return 'hexagon';
    if (compute.indexOf(type) !== -1) return 'round-rectangle';
    return 'round-rectangle';
  }

  function pickColor(level) {
    if (level === 'Critical') return { bg: '#450a0a', border: '#ef4444' };
    if (level === 'Warning')  return { bg: '#451a03', border: '#f59e0b' };
    return { bg: '#0f172a', border: '#22c55e' };
  }

  var nodeCount = 0;
  var clusterNodes = [];
  var leafNodes = [];

  data.elements.nodes.forEach(function (n) {
    if (n.data.parent) {
      leafNodes.push(n);
    } else {
      clusterNodes.push(n);
    }
    nodeCount++;
  });

  var NODE_STYLES = [
    {
      selector: ':parent',
      style: {
        'background-color': '#1e293b',
        'border-color': '#334155',
        'border-width': 1,
        label: 'data(label)',
        color: '#94a3b8',
        'font-size': '10px',
        'text-valign': 'top',
        'text-halign': 'center',
        'text-margin-y': 4,
        padding: 24,
        'font-weight': 600,
      },
    },
    {
      selector: 'node',
      style: {
        width: 32,
        height: 32,
        label: 'data(label)',
        'font-size': '8px',
        color: '#e2e8f0',
        'text-valign': 'bottom',
        'text-margin-y': 3,
        'background-color': '#334155',
        'border-width': 2,
        'border-color': '#475569',
        'font-family': 'system-ui, sans-serif',
      },
    },
    {
      selector: 'node[exposureLevel = "Critical"]',
      style: {
        'border-color': '#ef4444',
        'border-width': 3,
        'background-color': '#450a0a',
        'shadow-blur': 12,
        'shadow-color': '#ef4444',
        'shadow-opacity': 0.4,
        'shadow-offset-x': 0,
        'shadow-offset-y': 0,
      },
    },
    {
      selector: 'node[exposureLevel = "Warning"]',
      style: {
        'border-color': '#f59e0b',
        'border-width': 2,
        'background-color': '#451a03',
      },
    },
    {
      selector: 'node[exposureLevel = "Safe"]',
      style: {
        'border-color': '#22c55e',
        'border-width': 1,
        'background-color': '#052e16',
      },
    },
    {
      selector: 'node[type = "internet"]',
      style: {
        width: 48,
        height: 48,
        'background-color': '#0ea5e9',
        'border-color': '#0284c7',
        'border-width': 2,
        'font-size': '10px',
        color: '#f8fafc',
        'font-weight': 700,
      },
    },
    {
      selector: 'edge',
      style: {
        width: 1.5,
        'line-color': '#475569',
        'target-arrow-color': '#475569',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        label: 'data(label)',
        'font-size': '7px',
        color: '#64748b',
        'text-background-color': '#0f172a',
        'text-background-opacity': 0.8,
        'text-background-padding': 2,
      },
    },
    {
      selector: 'edge[edgeType = "network_ingress"]',
      style: {
        'line-color': '#ef4444',
        'target-arrow-color': '#ef4444',
        width: 2,
      },
    },
    {
      selector: 'edge[edgeType = "sg_attached"]',
      style: {
        'line-color': '#a78bfa',
        'target-arrow-color': '#a78bfa',
        width: 1.5,
        'line-style': 'dashed',
      },
    },
    {
      selector: 'edge[edgeType ^= "iam_"]',
      style: {
        'line-color': '#a78bfa',
        'target-arrow-color': '#a78bfa',
        'line-style': 'dotted',
        width: 1.5,
      },
    },
  ];

  function pickLayout(count) {
    if (count > 200) {
      return {
        name: 'concentric',
        animate: false,
        concentric: function (n) {
          if (n.data('exposureLevel') === 'Critical') return 3;
          if (n.data('exposureLevel') === 'Warning') return 2;
          return 1;
        },
        levelWidth: function () { return 2; },
        padding: 40,
      };
    }
    if (count > 50) {
      return { name: 'cose', animate: false, randomize: false, componentSpacing: 60, nodeRepulsion: 8000 };
    }
    return {
      name: 'breadthfirst',
      animate: true,
      animationDuration: 400,
      spacingFactor: 1.4,
      padding: 30,
      directed: true,
    };
  }

  var cy = cytoscape({
    container: document.getElementById('cy'),
    elements: data.elements,
    style: NODE_STYLES,
    layout: pickLayout(data.meta.totalNodes),
    minZoom: 0.05,
    maxZoom: 4,
    wheelSensitivity: 0.3,
  });

  // ── Tooltip ──────────────────────────────────────────────────────────

  var tooltip = document.getElementById('tooltip');
  if (!tooltip) {
    tooltip = document.createElement('div');
    tooltip.id = 'tooltip';
    document.body.appendChild(tooltip);
  }

  cy.on('mouseover', 'node:childless', function (evt) {
    var n = evt.target;
    var d = n.data();
    var html = '<strong>' + escapeHtml(d.label || d.id) + '</strong><br>';
    html += 'Type: ' + (d.type || 'unknown') + '<br>';
    html += 'Provider: ' + (d.provider || '-') + ' / ' + (d.region || '-') + '<br>';
    html += 'Exposure: ' + (d.exposureLevel || 'Safe') + '<br>';
    if (d.publicIp) html += 'Public IP: ' + escapeHtml(d.publicIp) + '<br>';
    html += 'Findings: ' + (d.findingCount || 0);
    tooltip.innerHTML = html;
    tooltip.style.display = 'block';
  });

  cy.on('mousemove', 'node:childless', function (evt) {
    var pos = evt.renderedPosition || evt.position;
    tooltip.style.left = (pos.x + 16) + 'px';
    tooltip.style.top = (pos.y + 16) + 'px';
  });

  cy.on('mouseout', 'node', function () {
    tooltip.style.display = 'none';
  });

  // ── Click to select ──────────────────────────────────────────────────

  cy.on('tap', 'node:childless', function (evt) {
    var n = evt.target;
    var d = n.data();
    showDetail(d);
    cy.$(':selected').unselect();
    n.select();
  });

  cy.on('tap', function (evt) {
    if (evt.target === cy) {
      cy.$(':selected').unselect();
      hideDetail();
    }
  });

  // ── Detail Panel ─────────────────────────────────────────────────────

  function showDetail(d) {
    var emptyEl = document.getElementById('detail-empty');
    var contentEl = document.getElementById('detail-content');
    if (emptyEl) emptyEl.style.display = 'none';
    if (contentEl) contentEl.style.display = 'block';

    setText('detail-name', d.label || d.id || 'Unknown');
    setText('detail-provider', d.provider || '-');
    setText('detail-region', d.region || '-');
    setText('detail-type', d.type || '-');
    setText('detail-id', d.id || '-');

    var badge = document.getElementById('detail-badge');
    if (badge) {
      var level = d.exposureLevel || 'Safe';
      badge.textContent = level;
      badge.className = '';
      if (level === 'Critical') badge.classList.add('badge-critical');
      else if (level === 'Warning') badge.classList.add('badge-warning');
      else badge.classList.add('badge-safe');
    }

    var pubIpRow = document.getElementById('detail-public-ip-row');
    if (pubIpRow) {
      if (d.publicIp) {
        setText('detail-public-ip', d.publicIp);
        pubIpRow.style.display = 'flex';
      } else {
        pubIpRow.style.display = 'none';
      }
    }

    var findingsEl = document.getElementById('detail-findings');
    if (findingsEl) {
      findingsEl.innerHTML = '';
      if (d.findings && d.findings.length > 0) {
        d.findings.sort(function (a, b) {
          var order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
          return (order[a.severity] || 99) - (order[b.severity] || 99);
        });
        d.findings.forEach(function (f) {
          var item = document.createElement('div');
          item.className = 'finding-item';
          var sev = document.createElement('span');
          sev.className = 'finding-severity sev-' + f.severity.toLowerCase();
          sev.textContent = f.severity;
          item.appendChild(sev);
          var title = document.createElement('div');
          title.className = 'finding-title';
          title.textContent = f.title;
          item.appendChild(title);
          findingsEl.appendChild(item);
        });
      } else {
        findingsEl.innerHTML = '<div class="finding-item" style="color:#64748b">No security findings</div>';
      }
    }
  }

  function hideDetail() {
    var emptyEl = document.getElementById('detail-empty');
    var contentEl = document.getElementById('detail-content');
    if (emptyEl) emptyEl.style.display = 'block';
    if (contentEl) contentEl.style.display = 'none';
  }

  function setText(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // ── Search ───────────────────────────────────────────────────────────

  var searchInput = document.getElementById('search-input');
  if (searchInput) {
    searchInput.addEventListener('input', function () {
      var q = this.value.toLowerCase().trim();
      cy.nodes(':childless').forEach(function (n) {
        var d = n.data();
        var match = !q ||
          (d.label && d.label.toLowerCase().indexOf(q) !== -1) ||
          (d.type && d.type.toLowerCase().indexOf(q) !== -1) ||
          (d.id && d.id.toLowerCase().indexOf(q) !== -1) ||
          (d.provider && d.provider.toLowerCase().indexOf(q) !== -1);
        n.style('display', match ? 'element' : 'none');
      });
    });
  }

  // ── Severity Filter ──────────────────────────────────────────────────

  var sevFilter = document.getElementById('severity-filter');
  if (sevFilter) {
    sevFilter.addEventListener('change', function () {
      var val = this.value;
      cy.nodes(':childless').forEach(function (n) {
        var level = n.data('exposureLevel') || 'Safe';
        var show = true;
        if (val === 'critical') show = level === 'Critical';
        else if (val === 'warning') show = level === 'Critical' || level === 'Warning';
        else if (val === 'safe') show = level === 'Safe';
        n.style('display', show ? 'element' : 'none');
      });
    });
  }

  // ── Zoom Controls ────────────────────────────────────────────────────

  var fitBtn = document.getElementById('btn-fit');
  if (fitBtn) fitBtn.addEventListener('click', function () { cy.fit(); });

  var resetBtn = document.getElementById('btn-reset');
  if (resetBtn) resetBtn.addEventListener('click', function () {
    cy.zoom(1);
    cy.center();
  });

  // ── Keyboard Navigation ──────────────────────────────────────────────

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      cy.$(':selected').unselect();
      hideDetail();
    }
    if (e.key === 'f' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      if (searchInput) searchInput.focus();
    }
  });

  // ── Stats Header ─────────────────────────────────────────────────────

  function updateStats() {
    var nodeCountEl = document.getElementById('node-count');
    if (nodeCountEl) nodeCountEl.textContent = 'Nodes: ' + (data.meta.totalNodes || 0);

    var findingCountEl = document.getElementById('finding-count');
    if (findingCountEl) findingCountEl.textContent = 'Findings: ' + (data.meta.totalFindings || 0);

    var provEl = document.getElementById('provider-tags');
    if (provEl && data.meta.providers) {
      provEl.textContent = data.meta.providers.join(' · ');
    }
  }
  updateStats();

  // ── Handle resize ────────────────────────────────────────────────────

  window.addEventListener('resize', function () {
    cy.resize();
  });

})();
