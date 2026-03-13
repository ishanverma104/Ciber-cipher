function stripHtml(html) {
  if (typeof html !== 'string') return html ?? '';
  const tmp = document.createElement('div');
  tmp.innerHTML = html;
  return tmp.textContent || tmp.innerText || '';
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safeText(value, fallback = '-') {
  if (value === undefined || value === null || value === '') return fallback;
  return escapeHtml(value);
}

function safeToken(value) {
  if (value === undefined || value === null) return '';
  return String(value).toLowerCase().replace(/[^a-z0-9_-]/g, '');
}

function csvEscape(value) {
  const s = String(value ?? '');
  if (/[",\n]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function downloadCsv(dt, filename, headers) {
  const rows = dt.rows().data().toArray();
  const lines = [];
  if (headers && headers.length) {
    lines.push(headers.map(csvEscape).join(','));
  }
  for (const row of rows) {
    lines.push(row.map(cell => csvEscape(stripHtml(cell))).join(','));
  }
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

let originalData = [];
let fimData = [];
let logsDT = null;
let fimDT = null;
let complianceDT = null;
let complianceData = [];
let networkData = [];
let networkDT = null;
let agentConfig = { agents: {}, settings: {} };

function parseAgentsYaml(text) {
  const agents = {};
  const settings = {};
  let section = null;
  let currentAgent = null;

  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.replace(/\s+#.*$/, '');
    if (!line.trim()) continue;

    if (!line.startsWith(' ') && line.endsWith(':')) {
      const topKey = line.slice(0, -1).trim();
      if (topKey === 'agents' || topKey === 'settings') {
        section = topKey;
        currentAgent = null;
      } else {
        section = null;
        currentAgent = null;
      }
      continue;
    }

    if (section === 'agents') {
      const agentMatch = line.match(/^  ([A-Za-z0-9_-]+):\s*$/);
      if (agentMatch) {
        currentAgent = agentMatch[1];
        if (!agents[currentAgent]) agents[currentAgent] = {};
        continue;
      }

      const agentPropMatch = line.match(/^    ([A-Za-z0-9_-]+):\s*(.*)$/);
      if (agentPropMatch && currentAgent) {
        const key = agentPropMatch[1];
        let value = agentPropMatch[2].trim();
        value = value.replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1');
        agents[currentAgent][key] = value;
      }
    }

    if (section === 'settings') {
      const settingMatch = line.match(/^  ([A-Za-z0-9_-]+):\s*(.*)$/);
      if (settingMatch) {
        const key = settingMatch[1];
        let value = settingMatch[2].trim();
        value = value.replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1');
        settings[key] = value;
      }
    }
  }

  return { agents, settings };
}

function loadAgentsConfig() {
  return fetch('../config/agents.yaml', { cache: 'no-store' })
    .then(res => res.ok ? res.text() : Promise.reject(new Error('Failed to load agents.yaml')))
    .then(text => {
      agentConfig = parseAgentsYaml(text);
      return agentConfig;
    });
}

function setVulnStatus(state, text) {
  const pill = document.getElementById('vulnStatusPill');
  const statusText = document.getElementById('vulnStatusText');
  if (!pill || !statusText) return;
  pill.classList.remove('running', 'success', 'error');
  if (state) pill.classList.add(state);
  pill.textContent = state ? state.toUpperCase() : 'Idle';
  statusText.textContent = text || '';
}

function buildVulnTriggerUrl() {
  const hostSelect = document.getElementById('vulnHostSelect');
  const pathInput = document.getElementById('vulnEndpointPath');
  const overrideInput = document.getElementById('vulnEndpointUrl');
  if (!hostSelect || !pathInput || !overrideInput) return '';

  const overrideUrl = overrideInput.value.trim();
  if (overrideUrl) return overrideUrl;

  const selectedAgent = hostSelect.value;
  const agent = agentConfig.agents[selectedAgent];
  if (!agent || !agent.ip) return '';

  const protocol = agentConfig.settings.protocol || 'http';
  const port = agentConfig.settings.default_port || '80';
  let path = pathInput.value.trim() || '/vuln-scan/trigger';
  if (!path.startsWith('/')) path = `/${path}`;
  return `${protocol}://${agent.ip}:${port}${path}`;
}

function setupVulnScanUI() {
  const hostSelect = document.getElementById('vulnHostSelect');
  const pathInput = document.getElementById('vulnEndpointPath');
  const overrideInput = document.getElementById('vulnEndpointUrl');
  const methodSelect = document.getElementById('vulnEndpointMethod');
  const runBtn = document.getElementById('runVulnScanBtn');
  const logEl = document.getElementById('vulnScanLog');

  // Never let vuln UI initialization break other dashboard modules.
  if (!hostSelect || !pathInput || !overrideInput || !methodSelect || !runBtn || !logEl) {
    return;
  }

  const savedPath = localStorage.getItem('vuln_scan_path');
  const savedOverride = localStorage.getItem('vuln_scan_override_url');
  const savedMethod = localStorage.getItem('vuln_scan_method');
  const savedHost = localStorage.getItem('vuln_scan_host');

  if (savedPath) pathInput.value = savedPath;
  if (savedOverride) overrideInput.value = savedOverride;
  if (savedMethod) methodSelect.value = savedMethod;

  function updateStatusPreview() {
    const url = buildVulnTriggerUrl();
    if (!url) {
      setVulnStatus('', 'Select a host to begin.');
      return;
    }
    setVulnStatus('', `Ready to trigger: ${url}`);
  }

  loadAgentsConfig()
    .then(config => {
      hostSelect.innerHTML = '';
      const agentNames = Object.keys(config.agents);
      if (agentNames.length === 0) {
        hostSelect.innerHTML = '<option value="">No agents configured</option>';
        return;
      }
      hostSelect.appendChild(new Option('Select a host', ''));
      agentNames.forEach(name => {
        const desc = config.agents[name].description || '';
        const label = desc ? `${name} (${desc})` : name;
        const option = new Option(label, name);
        hostSelect.appendChild(option);
      });
      if (savedHost && config.agents[savedHost]) {
        hostSelect.value = savedHost;
      }
      updateStatusPreview();
    })
    .catch(err => {
      hostSelect.innerHTML = '<option value="">Failed to load agents</option>';
      setVulnStatus('error', 'Could not load agents.yaml. Check dashboard access to engine/config/agents.yaml.');
      logEl.textContent = `Error loading agents.yaml: ${err.message}`;
    });

  [hostSelect, pathInput, overrideInput, methodSelect].forEach(el => {
    el.addEventListener('change', () => {
      localStorage.setItem('vuln_scan_path', pathInput.value.trim());
      localStorage.setItem('vuln_scan_override_url', overrideInput.value.trim());
      localStorage.setItem('vuln_scan_method', methodSelect.value);
      if (hostSelect.value) localStorage.setItem('vuln_scan_host', hostSelect.value);
      updateStatusPreview();
    });
  });

  runBtn.addEventListener('click', async () => {
    const url = buildVulnTriggerUrl();
    if (!url) {
      setVulnStatus('error', 'Select a valid host or set a full override URL.');
      return;
    }

    const method = methodSelect.value || 'POST';
    setVulnStatus('running', `Triggering scan via ${method} ${url}`);
    runBtn.disabled = true;
    logEl.textContent = `Triggering scan...\n${new Date().toLocaleString()}\nURL: ${url}\nMethod: ${method}\n`;

    try {
      const response = await fetch(url, {
        method,
        mode: 'cors',
        headers: { 'Content-Type': 'application/json' }
      });

      const contentType = response.headers.get('content-type') || '';
      let bodyText = '';
      if (contentType.includes('application/json')) {
        const data = await response.json();
        bodyText = JSON.stringify(data, null, 2);
      } else {
        bodyText = await response.text();
      }

      if (!response.ok) {
        setVulnStatus('error', `Scan trigger failed (HTTP ${response.status}).`);
      } else {
        setVulnStatus('success', 'Scan triggered successfully.');
      }
      logEl.textContent += `\nResponse (${response.status}):\n${bodyText || '(empty response)'}\n`;
    } catch (err) {
      setVulnStatus('error', 'Failed to reach agent. Check URL, CORS, and connectivity.');
      logEl.textContent += `\nError:\n${err.message}\n`;
    } finally {
      runBtn.disabled = false;
    }
  });
}

// Prevent blocking browser popups from DataTables; keep diagnostics in console.
if (window.jQuery && $.fn && $.fn.dataTable && $.fn.dataTable.ext) {
  $.fn.dataTable.ext.errMode = 'none';
  $(document).on('error.dt', function(e, settings, techNote, message) {
    if (e && typeof e.preventDefault === 'function') {
      e.preventDefault();
    }
    console.error(`DataTables warning (tn/${techNote})`, message, settings);
  });
}

function classifySeverity(msg) {
  msg = (msg || '').toLowerCase();
  if (msg.includes('fail') || msg.includes('denied') || msg.includes('error') || msg.includes('authentication failure')) return 'error';
  if (msg.includes('warning') || msg.includes('invalid') || msg.includes('incorrect')) return 'warning';
  if (msg.includes('session opened') || msg.includes('accepted') || msg.includes('connected')) return 'info';
  if ((msg.includes('root') || msg.includes('sudo')) && msg.includes('opened')) return 'critical';
  return 'info';
}

function updateStats(data) {
  const total = data.length;
  const critical = data.filter(d => d.severity === 'critical').length;
  const error = data.filter(d => d.severity === 'error').length;
  const warning = data.filter(d => d.severity === 'warning').length;
  const hosts = new Set(data.map(d => d.hostname)).size;

  document.getElementById('statTotal').textContent = total.toLocaleString();
  document.getElementById('statCritical').textContent = critical.toLocaleString();
  document.getElementById('statError').textContent = error.toLocaleString();
  document.getElementById('statWarning').textContent = warning.toLocaleString();
  document.getElementById('statHosts').textContent = hosts.toLocaleString();
}

function updateThreatSidebar(data) {
  const threatCounts = {};
  data.forEach(d => {
    if (d.mitre && d.mitre.length > 0) {
      d.mitre.forEach(m => {
        const key = `${m.technique_id}: ${m.technique_name}`;
        threatCounts[key] = (threatCounts[key] || 0) + 1;
      });
    }
  });

  const sorted = Object.entries(threatCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  const list = document.getElementById('threatList');
  list.innerHTML = '';

  if (sorted.length === 0) {
    list.innerHTML = '<li class="threat-item"><div class="technique">No threats detected</div></li>';
    return;
  }

  sorted.forEach(([tech, count]) => {
    const li = document.createElement('li');
    li.className = 'threat-item high';
    li.innerHTML = `
      <div class="technique">${tech}</div>
      <div class="count">${count} event${count > 1 ? 's' : ''}</div>
    `;
    li.addEventListener('click', () => {
      document.getElementById('searchInput').value = tech.split(':')[0];
      applyFilters();
    });
    list.appendChild(li);
  });
}

function updateHostGrid(data) {
  const hosts = Array.from(new Set(data.map(d => d.hostname)));
  const grid = document.getElementById('hostGrid');
  grid.innerHTML = '';

  hosts.forEach(host => {
    const hostData = data.filter(d => d.hostname === host);
    const critical = hostData.filter(d => d.severity === 'critical').length;
    const total = hostData.length;

    const card = document.createElement('div');
    card.className = 'host-card';
    card.dataset.host = host;

    let badgeClass = 'badge-success';
    let badgeText = 'OK';
    if (critical > 0) { badgeClass = 'badge-critical'; badgeText = `${critical} CRIT`; }
    else if (hostData.some(d => d.severity === 'error')) { badgeClass = 'badge-error'; badgeText = 'Errors'; }
    else if (hostData.some(d => d.severity === 'warning')) { badgeClass = 'badge-warning'; badgeText = 'Warn'; }

    card.innerHTML = `
      <div class="name" title="${host}">${host}</div>
      <div class="stats">${total} events</div>
      <span class="badge ${badgeClass}">${badgeText}</span>
    `;

    card.addEventListener('click', () => {
      document.querySelectorAll('.host-card').forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      document.getElementById('hostFilter').value = host;
      applyFilters();
    });

    grid.appendChild(card);
  });
}

function applyFilters() {
  const host = document.getElementById('hostFilter').value;
  const search = document.getElementById('searchInput').value.toLowerCase();
  const newestFilter = document.getElementById('newestFilter');
  const newestFirst = newestFilter ? newestFilter.checked : true;
  const checked = {};
  document.querySelectorAll('.severity-checkboxes input:checked').forEach(cb => {
    checked[cb.value] = true;
  });

  // Create a fresh copy to avoid mutating originalData
  let filtered = [...originalData];
  if (host !== 'all') filtered = filtered.filter(d => d.hostname === host);
  if (search) filtered = filtered.filter(d =>
    d.message.toLowerCase().includes(search) ||
    d.process.toLowerCase().includes(search)
  );
  filtered = filtered.filter(d => checked[d.severity]);

  // Sort by timestamp (newest first by default)
  if (newestFirst) {
    filtered.sort((a, b) => new Date(b.timestamp_utc) - new Date(a.timestamp_utc));
  } else {
    filtered.sort((a, b) => new Date(a.timestamp_utc) - new Date(b.timestamp_utc));
  }

  renderTimeline(filtered);
  renderSeverityPie(filtered);
  renderLogsTable(filtered);
}

function setupFilters() {
  const hostFilter = document.getElementById('hostFilter');
  hostFilter.innerHTML = '<option value="all">All Hosts</option>';

  const hosts = Array.from(new Set(originalData.map(d => d.hostname)));
  hosts.forEach(h => {
    const opt = document.createElement('option');
    opt.value = h;
    opt.textContent = h;
    hostFilter.appendChild(opt);
  });

  hostFilter.addEventListener('change', applyFilters);

  document.getElementById('searchInput').addEventListener('input', applyFilters);
  document.querySelectorAll('.severity-checkboxes input').forEach(cb => {
    cb.addEventListener('change', applyFilters);
  });

  const newestFilter = document.getElementById('newestFilter');
  if (newestFilter) {
    newestFilter.addEventListener('change', applyFilters);
    newestFilter.addEventListener('click', function() {
      setTimeout(applyFilters, 10);
    });
  }

  document.getElementById('clearFilters').addEventListener('click', () => {
    document.getElementById('searchInput').value = '';
    document.getElementById('hostFilter').value = 'all';
    document.getElementById('newestFilter').checked = true;
    document.querySelectorAll('.severity-checkboxes input').forEach(cb => cb.checked = true);
    document.querySelectorAll('.host-card').forEach(c => c.classList.remove('active'));
    applyFilters();
  });
}

function setupNavSearch() {
  const input = document.getElementById('navSearchInput');
  const resultsEl = document.getElementById('navSearchResults');
  if (!input || !resultsEl) return;

  const sections = [
    { label: 'Overview Stats', tab: 'timelineTab', target: 'statsGrid', keywords: ['overview', 'stats', 'total'] },
    { label: 'Top Detected Threats', tab: 'timelineTab', target: 'threatsSection', keywords: ['threats', 'mitre', 'techniques'] },
    { label: 'Host Summary', tab: 'timelineTab', target: 'hostSummarySection', keywords: ['hosts', 'host summary'] },
    { label: 'Timeline Logs', tab: 'timelineTab', target: 'timelineTab', keywords: ['timeline', 'logs', 'events'] },
    { label: 'GeoIP Map', tab: 'geoipTab', target: 'geoipMap', keywords: ['geoip', 'map', 'global', 'threat intel'] },
    { label: 'FIM Events', tab: 'fimTab', target: 'fimTab', keywords: ['fim', 'file integrity'] },
    { label: 'Compliance', tab: 'complianceTab', target: 'complianceTab', keywords: ['compliance', 'pci', 'gdpr', 'hipaa', 'nist', 'soc2', 'iso'] },
    { label: 'Network', tab: 'networkTab', target: 'networkTab', keywords: ['network', 'firewall', 'ids'] },
    { label: 'Vulnerability Scan', tab: 'vulnScanTab', target: 'vulnScanTab', keywords: ['vulnerability', 'vuln', 'scan', 'scanner'] },
    { label: 'Additional Sources', tab: 'additionalTab', target: 'additionalTab', keywords: ['additional', 'sources'] },
    { label: 'Apache Logs', tab: 'additionalTab', target: 'apacheSource', source: 'apache', keywords: ['apache', 'httpd'] },
    { label: 'Nginx Logs', tab: 'additionalTab', target: 'nginxSource', source: 'nginx', keywords: ['nginx'] },
    { label: 'Docker Logs', tab: 'additionalTab', target: 'dockerSource', source: 'docker', keywords: ['docker', 'containers'] },
    { label: 'Kubernetes Logs', tab: 'additionalTab', target: 'kubernetesSource', source: 'kubernetes', keywords: ['kubernetes', 'k8s'] }
  ];

  let activeIndex = -1;
  let currentResults = [];

  function tokenMatch(text, tokens) {
    return tokens.every(token => text.includes(token));
  }

  function filterSections(query) {
    const q = query.trim().toLowerCase();
    if (!q) return sections;
    const tokens = q.split(/\s+/).filter(Boolean);
    return sections.filter(section => {
      const haystack = [section.label, ...(section.keywords || [])].join(' ').toLowerCase();
      return tokenMatch(haystack, tokens);
    });
  }

  function renderResults(list) {
    currentResults = list.slice(0, 8);
    activeIndex = -1;
    if (currentResults.length === 0) {
      resultsEl.innerHTML = '<div class="nav-search-item"><span>No matches</span><span class="nav-search-meta">Try another term</span></div>';
      resultsEl.classList.add('active');
      return;
    }
    resultsEl.innerHTML = currentResults.map((item, index) => `
      <div class="nav-search-item" data-index="${index}">
        <span>${item.label}</span>
        <span class="nav-search-meta">${item.tab ? 'Tab' : 'Section'}</span>
      </div>
    `).join('');
    resultsEl.classList.add('active');
  }

  function clearResults() {
    resultsEl.classList.remove('active');
    resultsEl.innerHTML = '';
    activeIndex = -1;
  }

  function navigateTo(item) {
    if (!item) return;
    if (typeof showTab === 'function' && item.tab) {
      showTab(item.tab);
    }
    if (typeof showAdditionalSource === 'function' && item.source) {
      showAdditionalSource(item.source);
    }
    const target = document.getElementById(item.target);
    if (target) {
      setTimeout(() => {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 60);
    }
  }

  function setActive(index) {
    const items = resultsEl.querySelectorAll('.nav-search-item');
    items.forEach(el => el.classList.remove('active'));
    if (index >= 0 && index < items.length) {
      items[index].classList.add('active');
      activeIndex = index;
    }
  }

  input.addEventListener('input', () => {
    renderResults(filterSections(input.value));
  });

  input.addEventListener('focus', () => {
    renderResults(filterSections(input.value));
  });

  input.addEventListener('keydown', (e) => {
    if (!resultsEl.classList.contains('active')) return;
    const max = currentResults.length - 1;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive(activeIndex < max ? activeIndex + 1 : 0);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive(activeIndex > 0 ? activeIndex - 1 : max);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const pick = activeIndex >= 0 ? currentResults[activeIndex] : currentResults[0];
      navigateTo(pick);
      clearResults();
    } else if (e.key === 'Escape') {
      clearResults();
    }
  });

  resultsEl.addEventListener('mousedown', (e) => {
    const itemEl = e.target.closest('.nav-search-item');
    if (!itemEl) return;
    const index = Number(itemEl.dataset.index);
    const item = currentResults[index];
    navigateTo(item);
    clearResults();
  });

  document.addEventListener('click', (e) => {
    if (!resultsEl.contains(e.target) && e.target !== input) {
      clearResults();
    }
  });
}

setupNavSearch();

function renderTimeline(data) {
  d3.select('#timeline').html('');

  if (data.length === 0) {
    d3.select('#timeline').append('div')
      .attr('class', 'empty-state')
      .html('<svg viewBox="0 0 24 24" fill="currentColor"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-7 14l-5-5 1.41-1.41L12 14.17l4.59-4.58L18 11l-6 6z"/></svg><p>No events match your filters</p>');
    document.getElementById('timelineCount').textContent = 'Showing 0 events';
    return;
  }

  const width = Math.min(1200, window.innerWidth - 400);
  const height = 280;
  const margin = { top: 30, right: 30, bottom: 50, left: 130 };

  const xExtent = d3.extent(data, d => d.timestampDate);
  const durationMs = xExtent[1] - xExtent[0] || 1;
  const binSizeMs = Math.max(60 * 1000, Math.floor(durationMs / 50));

  const thresholds = [];
  let current = +xExtent[0];
  while (current < +xExtent[1]) {
    thresholds.push(current);
    current += binSizeMs;
  }
  thresholds.push(+xExtent[1]);

  const x = d3.scaleTime()
    .domain(xExtent)
    .range([margin.left, width - margin.right]);

  const svg = d3.select('#timeline')
    .append('svg')
    .attr('width', width)
    .attr('height', height);

  const tooltip = d3.select('body')
    .append('div')
    .attr('class', 'tooltip')
    .style('opacity', 0);

  const severityLevels = ['info', 'warning', 'error', 'critical'];
  const colorMap = {
    info: '#198754',
    warning: '#ffc107',
    error: '#dc3545',
    critical: '#9c27b0'
  };

  const bins = d3.bin()
    .value(d => d.timestampDate.getTime())
    .thresholds(thresholds)(data);

  const stackedData = bins.map(bin => {
    const counts = {};
    severityLevels.forEach(s => counts[s] = 0);
    bin.forEach(log => counts[log.severity]++);
    return {
      x0: new Date(bin.x0),
      x1: new Date(bin.x1),
      total: bin.length,
      bin,
      ...counts
    };
  });

  const y = d3.scaleLinear()
    .domain([0, d3.max(stackedData, d => d.total) || 1])
    .range([height - margin.bottom, margin.top]);

  svg.append('g')
    .attr('transform', `translate(0, ${height - margin.bottom})`)
    .call(d3.axisBottom(x).ticks(8))
    .selectAll('text')
    .style('fill', 'var(--text-secondary)')
    .style('font-size', '11px');

  svg.append('g')
    .attr('transform', `translate(${margin.left}, 0)`)
    .call(d3.axisLeft(y).ticks(5))
    .selectAll('text')
    .style('fill', 'var(--text-secondary)')
    .style('font-size', '11px');

  svg.selectAll('.domain, .tick line').style('stroke', 'var(--border-color)');

  svg.append('text')
    .attr('x', width / 2)
    .attr('y', height - 10)
    .attr('text-anchor', 'middle')
    .style('fill', 'var(--text-secondary)')
    .style('font-size', '11px')
    .text('Time');

  const legend = svg.append('g')
    .attr('transform', `translate(${margin.left}, 15)`);

  severityLevels.forEach((sev, i) => {
    const g = legend.append('g').attr('transform', `translate(${i * 100}, 0)`);
    g.append('rect').attr('width', 12).attr('height', 12).attr('fill', colorMap[sev]).attr('rx', 2);
    g.append('text').attr('x', 16).attr('y', 10).text(sev.charAt(0).toUpperCase() + sev.slice(1))
      .style('fill', 'var(--text-secondary)').style('font-size', '11px');
  });

  stackedData.forEach(d => {
    let yOffset = 0;
    severityLevels.forEach(sev => {
      const count = d[sev];
      if (count === 0) return;

      const barHeight = y(0) - y(count);
      const yTop = y(d.total - yOffset);
      const barWidth = Math.max(3, x(d.x1) - x(d.x0) - 1);

      svg.append('rect')
        .attr('x', x(d.x0))
        .attr('y', yTop)
        .attr('width', barWidth)
        .attr('height', barHeight)
        .attr('fill', colorMap[sev])
        .attr('rx', 2)
        .style('cursor', 'pointer')
        .on('mouseover', (e) => {
          const sampleLogs = d.bin.filter(l => l.severity === sev).slice(0, 8).map(log => {
            const mitreHtml = log.mitre && log.mitre.length > 0
              ? log.mitre.map(m => `<div style="margin:4px 0 4px 10px;padding:4px 8px;background:rgba(13,110,253,0.1);border-radius:4px;"><strong>${m.technique_id}</strong> ${m.technique_name}</div>`).join('')
              : '';
            return `<div style="padding:6px;margin:4px 0;border-left:2px solid ${colorMap[sev]};background:var(--bg-primary);">
              <strong>${log.timestamp_local}</strong> • ${log.hostname}<br/>
              <span style="color:var(--text-secondary)">${log.process}${log.pid ? ' [' + log.pid + ']' : ''}</span><br/>
              ${log.message.substring(0, 100)}${log.message.length > 100 ? '...' : ''}
              ${mitreHtml}
            </div>`;
          }).join('');

          tooltip.transition().duration(150).style('opacity', 0.95);
          tooltip.html(`<strong style="color:${colorMap[sev]}">${sev.toUpperCase()}</strong>: ${count} events<br/>${sampleLogs}${count > 8 ? '<em>...more</em>' : ''}`)
            .style('left', (e.pageX + 15) + 'px')
            .style('top', (e.pageY - 28) + 'px');
        })
        .on('mouseout', () => tooltip.transition().duration(200).style('opacity', 0));

      yOffset += count;
    });
  });

  document.getElementById('timelineCount').textContent = `Showing ${data.length.toLocaleString()} events`;
}

function renderSeverityPie(data) {
  d3.select('#severity-pie svg').remove();
  d3.select('#severity-pie .pie-legend').remove();

  if (data.length === 0) {
    d3.select('#severity-pie').append('div')
      .attr('class', 'empty-state')
      .style('padding', '40px 20px')
      .html('<p style="color: var(--text-secondary);">No data to display</p>');
    return;
  }

  const severityCounts = {};
  const severityLevels = ['info', 'warning', 'error', 'critical'];
  const colorMap = {
    info: '#198754',
    warning: '#ffc107',
    error: '#dc3545',
    critical: '#9c27b0'
  };

  severityLevels.forEach(sev => severityCounts[sev] = 0);
  data.forEach(d => {
    if (severityCounts[d.severity] !== undefined) {
      severityCounts[d.severity]++;
    }
  });

  const pieData = severityLevels
    .filter(sev => severityCounts[sev] > 0)
    .map(sev => ({
      severity: sev,
      count: severityCounts[sev],
      percentage: ((severityCounts[sev] / data.length) * 100).toFixed(1)
    }));

  const width = 280;
  const height = 240;
  const radius = Math.min(width, height) / 2 - 20;

  const svg = d3.select('#severity-pie')
    .append('svg')
    .attr('width', width)
    .attr('height', height)
    .append('g')
    .attr('transform', `translate(${width / 2}, ${height / 2 - 10})`);

  const pie = d3.pie()
    .value(d => d.count)
    .sort(null);

  const arc = d3.arc()
    .innerRadius(0)
    .outerRadius(radius);

  const tooltip = d3.select('body')
    .append('div')
    .attr('class', 'tooltip')
    .style('opacity', 0);

  const arcs = svg.selectAll('arc')
    .data(pie(pieData))
    .enter()
    .append('g')
    .attr('class', 'arc');

  arcs.append('path')
    .attr('d', arc)
    .attr('fill', d => colorMap[d.data.severity])
    .attr('stroke', 'var(--bg-card)')
    .attr('stroke-width', 2)
    .style('cursor', 'pointer')
    .on('mouseover', function(e, d) {
      d3.select(this).transition().duration(200).attr('transform', 'scale(1.05)');
      tooltip.transition().duration(200).style('opacity', 0.95);
      tooltip.html(`<strong>${d.data.severity.toUpperCase()}</strong><br/>Count: ${d.data.count}<br/>Percentage: ${d.data.percentage}%`)
        .style('left', (e.pageX + 10) + 'px')
        .style('top', (e.pageY - 28) + 'px');
    })
    .on('mouseout', function() {
      d3.select(this).transition().duration(200).attr('transform', 'scale(1)');
      tooltip.transition().duration(200).style('opacity', 0);
    })
    .on('click', function(e, d) {
      document.querySelectorAll('.severity-checkboxes input').forEach(cb => {
        cb.checked = cb.value === d.data.severity;
      });
      applyFilters();
    });

  const legend = d3.select('#severity-pie')
    .append('div')
    .attr('class', 'pie-legend');

  pieData.forEach(d => {
    const item = legend.append('div')
      .attr('class', 'pie-legend-item');
    item.append('div')
      .attr('class', 'pie-legend-color')
      .style('background-color', colorMap[d.severity]);
    item.append('span')
      .text(`${d.severity}: ${d.count} (${d.percentage}%)`);
  });
}

function renderLogsTable(data) {
  if (!logsDT) {
    logsDT = $('#logs-table').DataTable({
      destroy: true,
      pageLength: 15,
      order: [[0, 'desc']],
      lengthMenu: [[10, 15, 25, 50], [10, 15, 25, 50]]
    });
  }

  const rows = data.map(d => {
    const mitreHtml = d.mitre && d.mitre.length > 0
      ? d.mitre.map(m => `<span class="mitre-tag" title="${m.tactic}: ${m.description}">${m.technique_id}</span>`).join('')
      : '';

    return [
      `<span data-sort="${d.timestampDate.getTime()}">${d.timestamp_local}</span>`,
      d.hostname,
      `${d.process}${d.pid ? ` [${d.pid}]` : ''}`,
      `<span title="${d.message}">${d.message.substring(0, 80)}${d.message.length > 80 ? '...' : ''}</span>`,
      `<span class="severity-badge ${d.severity}">${d.severity}</span>`,
      mitreHtml
    ];
  });

  logsDT.clear();
  logsDT.rows.add(rows);
  logsDT.draw();
}

function renderFIMTable(data) {
  if (!fimDT) {
    fimDT = $('#fim-table').DataTable({
      destroy: true,
      pageLength: 15,
      order: [[0, 'desc']]
    });
  }

  const rows = data.map(d => {
    const hash = d.new && d.new.hash ? d.new.hash : '-';
    return [
      `<span data-sort="${new Date(d.timestamp_utc).getTime()}">${new Date(d.timestamp_utc).toLocaleString()}</span>`,
      d.hostname,
      `<span title="${d.path}">${d.path.length > 60 ? '...' + d.path.slice(-57) : d.path}</span>`,
      `<span class="fim-change ${d.change}">${d.change}</span>`,
      `<span class="hash-display" title="Click to copy">${hash.substring(0, 16)}...</span>`
    ];
  });

  fimDT.clear();
  fimDT.rows.add(rows);
  fimDT.draw();

  document.getElementById('fimCount').textContent = `Showing ${data.length} FIM events`;
}

function renderCompliancePie(data) {
  const container = d3.select('#compliance-pie');
  container.html('');
  
  // Count violations per framework
  const counts = {};
  data.forEach(d => {
    if (d.compliance && d.compliance.length > 0) {
      d.compliance.forEach(c => {
        counts[c] = (counts[c] || 0) + 1;
      });
    }
  });
  
  if (Object.keys(counts).length === 0) {
    container.append('div')
      .attr('class', 'empty-state')
      .html('<svg viewBox="0 0 24 24" fill="currentColor"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-7 14l-5-5 1.41-1.41L12 14.17l4.59-4.58L18 11l-6 6z"/></svg><p>No compliance violations detected</p>');
    return;
  }
  
  const width = Math.min(400, window.innerWidth - 400);
  const height = 280;
  const radius = Math.min(width, height) / 2 - 20;
  
  const colors = {
    'PCI_DSS': '#e74c3c',
    'GDPR': '#3498db',
    'HIPAA': '#9b59b6',
    'SOC2': '#f39c12',
    'NIST': '#1abc9c',
    'ISO_27001': '#e91e63'
  };
  
  const pieData = Object.entries(counts).map(([name, value]) => ({ name, value }));
  
  const svg = container.append('svg')
    .attr('width', width)
    .attr('height', height)
    .append('g')
    .attr('transform', `translate(${width/2}, ${height/2})`);
  
  const pie = d3.pie().value(d => d.value).sort(null);
  const arc = d3.arc().innerRadius(radius * 0.4).outerRadius(radius);
  
  const arcs = svg.selectAll('arc')
    .data(pie(pieData))
    .enter()
    .append('g');
  
  arcs.append('path')
    .attr('d', arc)
    .attr('fill', d => colors[d.data.name] || '#95a5a6')
    .attr('stroke', '#fff')
    .attr('stroke-width', 2)
    .style('cursor', 'pointer')
    .on('click', (event, d) => {
      filterByCompliance(d.data.name);
    });
  
  arcs.append('text')
    .attr('transform', d => `translate(${arc.centroid(d)})`)
    .attr('text-anchor', 'middle')
    .attr('font-size', '12px')
    .attr('fill', '#fff')
    .attr('font-weight', 'bold')
    .text(d => `${d.data.name}: ${d.data.value}`);
}

function renderComplianceTable(data) {
  if (!complianceDT) {
    complianceDT = $('#compliance-table').DataTable({
      destroy: true,
      pageLength: 15,
      order: [[0, 'desc']]
    });
  }
  
  const rows = data.map(d => {
    const complianceBadges = d.compliance ? d.compliance.map(c => 
      `<span class="compliance-badge compliance-${c.toLowerCase()}">${c}</span>`
    ).join(' ') : '-';
    
    return [
      `<span data-sort="${new Date(d.timestamp_utc).getTime()}">${new Date(d.timestamp_utc).toLocaleString()}</span>`,
      d.hostname,
      d.process,
      `<span title="${d.message}">${d.message.length > 80 ? '...' + d.message.slice(-77) : d.message}</span>`,
      complianceBadges
    ];
  });
  
  complianceDT.clear();
  complianceDT.rows.add(rows);
  complianceDT.draw();
  
  document.getElementById('complianceCount').textContent = `Showing ${data.length} compliance events`;
}

function normalizeComplianceEvent(event, source) {
  return {
    timestamp_utc: event.timestamp_utc || new Date().toISOString(),
    hostname: event.hostname || 'unknown',
    process: event.process || event.log_type || source,
    message: event.message || event.description || event.raw_log || `${source} event`,
    compliance: Array.isArray(event.compliance) ? event.compliance : []
  };
}

function updateComplianceData() {
  const sources = [
    { events: originalData, source: 'security' },
    { events: networkData, source: 'network' },
    { events: apacheData, source: 'apache' },
    { events: nginxData, source: 'nginx' },
    { events: dockerData, source: 'docker' },
    { events: k8sData, source: 'kubernetes' }
  ];

  const merged = [];
  sources.forEach(({ events, source }) => {
    if (!Array.isArray(events)) return;
    events.forEach(event => {
      if (Array.isArray(event.compliance) && event.compliance.length > 0) {
        merged.push(normalizeComplianceEvent(event, source));
      }
    });
  });

  complianceData = merged;

  const activeFrameworkBtn = document.querySelector('.compliance-filter .btn-primary');
  const activeFramework = activeFrameworkBtn ? activeFrameworkBtn.dataset.framework : 'all';
  filterByCompliance(activeFramework || 'all');
}

function filterByCompliance(framework) {
  if (framework === 'all') {
    renderComplianceTable(complianceData);
    renderCompliancePie(complianceData);
  } else {
    const filtered = complianceData.filter(d => d.compliance && d.compliance.includes(framework));
    renderComplianceTable(filtered);
    renderCompliancePie(filtered);
  }
  
  // Update button states
  document.querySelectorAll('.compliance-filter button').forEach(btn => {
    btn.classList.remove('btn-primary');
    btn.classList.add('btn-secondary');
    if (btn.dataset.framework === framework || (framework === 'all' && btn.dataset.framework === 'all')) {
      btn.classList.remove('btn-secondary');
      btn.classList.add('btn-primary');
    }
  });
}

// Compliance filter button handlers
document.querySelectorAll('.compliance-filter button').forEach(btn => {
  btn.addEventListener('click', () => {
    filterByCompliance(btn.dataset.framework);
  });
});

document.getElementById('downloadComplianceCsv').addEventListener('click', () => {
  if (complianceDT) downloadCsv(complianceDT, 'compliance_violations.csv', ['Time', 'Host', 'Process', 'Message', 'Compliance']);
});

document.getElementById('downloadLogsCsv').addEventListener('click', () => {
  if (logsDT) downloadCsv(logsDT, 'timeline_logs.csv', ['Time', 'Host', 'Process', 'Message', 'Severity', 'MITRE']);
});

document.getElementById('downloadFimCsv').addEventListener('click', () => {
  if (fimDT) downloadCsv(fimDT, 'fim_logs.csv', ['Time', 'Host', 'File', 'Change', 'Hash']);
});

document.getElementById('downloadNetworkCsv').addEventListener('click', () => {
  if (networkDT) downloadCsv(networkDT, 'network_logs.csv', ['Time', 'Host', 'Type', 'Source IP', 'Dest IP', 'Port', 'Action', 'Description', 'Severity']);
});

// Network Tab Functions
function renderNetworkStats(data) {
  const stats = document.getElementById('networkStats');
  const total = data.length;
  const firewall = data.filter(d => d.log_type === 'firewall').length;
  const ids = data.filter(d => d.log_type === 'ids').length;
  const critical = data.filter(d => d.severity === 'critical').length;
  
  stats.innerHTML = `
    <div class="network-stat"><div class="count">${total}</div><div class="label">Total Events</div></div>
    <div class="network-stat"><div class="count">${firewall}</div><div class="label">Firewall</div></div>
    <div class="network-stat"><div class="count">${ids}</div><div class="label">IDS Alerts</div></div>
    <div class="network-stat"><div class="count">${critical}</div><div class="label">Critical</div></div>
  `;
}

function renderNetworkAttackers(data) {
  const container = d3.select('#network-attackers');
  container.html('');
  
  // Count attackers
  const attackers = {};
  data.forEach(d => {
    if (d.source_ip && !d.source_ip.startsWith('10.') && !d.source_ip.startsWith('192.168.') && !d.source_ip.startsWith('172.')) {
      attackers[d.source_ip] = (attackers[d.source_ip] || 0) + 1;
    }
  });
  
  const topAttackers = Object.entries(attackers)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);
  
  if (topAttackers.length === 0) return;
  
  const width = Math.min(400, window.innerWidth - 400);
  const height = 200;
  const margin = { top: 20, right: 20, bottom: 60, left: 100 };
  
  const svg = container.append('svg')
    .attr('width', width)
    .attr('height', height);
  
  const x = d3.scaleLinear()
    .domain([0, d3.max(topAttackers, d => d[1])])
    .range([margin.left, width - margin.right]);
  
  const y = d3.scaleBand()
    .domain(topAttackers.map(d => d[0]))
    .range([margin.top, height - margin.bottom])
    .padding(0.2);
  
  svg.selectAll('rect')
    .data(topAttackers)
    .enter()
    .append('rect')
    .attr('x', x(0))
    .attr('y', d => y(d[0]))
    .attr('width', d => x(d[1]) - x(0))
    .attr('height', y.bandwidth())
    .attr('fill', '#dc3545');
  
  svg.selectAll('text')
    .data(topAttackers)
    .enter()
    .append('text')
    .attr('x', d => x(d[1]) + 5)
    .attr('y', d => y(d[0]) + y.bandwidth() / 2)
    .attr('dy', '0.35em')
    .attr('fill', '#dc3545')
    .attr('font-size', '12px')
    .text(d => d[1]);
  
  svg.append('g')
    .attr('transform', `translate(0,${height - margin.bottom})`)
    .call(d3.axisBottom(x).ticks(5));
  
  svg.append('g')
    .attr('transform', `translate(${margin.left},0)`)
    .call(d3.axisLeft(y));
  
  container.insert('h3', ':first-child').text('Top Attackers').style('margin', '10px 0');
}

function renderNetworkTable(data) {
  if (!networkDT) {
    networkDT = $('#network-table').DataTable({
      destroy: true,
      pageLength: 15,
      order: [[0, 'desc']]
    });
  }
  
  const rows = data.map(d => [
    new Date(d.timestamp_utc).toLocaleString(),
    d.hostname,
    `<span class="log-type-${d.log_type}">${d.log_type.toUpperCase()}</span>`,
    d.source_ip || '-',
    d.destination_ip || '-',
    d.destination_port || '-',
    d.action || '-',
    d.description || d.raw_log?.substring(0, 50) || '-',
    `<span class="severity-${d.severity}">${d.severity.toUpperCase()}</span>`
  ]);
  
  networkDT.clear();
  networkDT.rows.add(rows);
  networkDT.draw();
  
  document.getElementById('networkCount').textContent = `Showing ${data.length} network events`;
}

function filterNetwork(type) {
  let filtered = networkData;
  if (type !== 'all') {
    filtered = networkData.filter(d => d.log_type === type);
  }
  
  renderNetworkAttackers(filtered);
  renderNetworkTable(filtered);
  
  document.querySelectorAll('.network-filter button').forEach(btn => {
    btn.classList.remove('btn-primary');
    btn.classList.add('btn-secondary');
    if (btn.dataset.type === type) {
      btn.classList.remove('btn-secondary');
      btn.classList.add('btn-primary');
    }
  });
}

document.querySelectorAll('.network-filter button').forEach(btn => {
  btn.addEventListener('click', () => filterNetwork(btn.dataset.type));
});

document.getElementById('refreshBtn').addEventListener('click', () => {
  location.reload();
});

d3.json('../processed-data/events-security-processed.json').then(data => {
  originalData = data.map(d => ({
    ...d,
    timestampDate: new Date(d.timestamp_utc),
    timestamp_local: new Date(d.timestamp_utc).toLocaleString(),
    severity: classifySeverity(d.message)
  }));
  
  // Default sort: newest first
  originalData.sort((a, b) => b.timestampDate - a.timestampDate);

  updateStats(originalData);
  updateThreatSidebar(originalData);
  updateHostGrid(originalData);
  setupFilters();
  renderTimeline(originalData);
  renderSeverityPie(originalData);
  renderLogsTable(originalData);
  updateComplianceData();

  document.getElementById('lastUpdated').textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
}).catch(console.error);

d3.json('../processed-data/events-fim-processed.json').then(data => {
  fimData = data;
  renderFIMTable(fimData);
}).catch(err => {
  console.log('No FIM data available');
});

d3.json('../processed-data/events-network-processed.json').then(data => {
  if (data.events) {
    networkData = data.events;
    renderNetworkStats(networkData);
    renderNetworkAttackers(networkData);
    renderNetworkTable(networkData);
    updateComplianceData();
  }
}).catch(err => {
  console.log('No network data available');
});

document.addEventListener('click', (e) => {
  if (e.target.classList.contains('hash-display')) {
    const hash = e.target.textContent;
    navigator.clipboard.writeText(hash);
    const original = e.target.textContent;
    e.target.textContent = 'Copied!';
    setTimeout(() => e.target.textContent = original, 1000);
  }
});

// Additional Sources Data Variables
let apacheData = [];
let nginxData = [];
let dockerData = [];
let k8sData = {};

// Show additional source subsection
function showAdditionalSource(source) {
  document.querySelectorAll('.source-content').forEach(c => c.classList.remove('active'));
  document.querySelectorAll('.source-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(source + 'Source').classList.add('active');
  document.querySelector(`[data-source="${source}"]`).classList.add('active');
}

// Render Apache stats and table
function renderApacheStats(data) {
  const stats = document.getElementById('apacheStats');
  const critical = data.filter(d => d.severity === 'critical').length;
  const high = data.filter(d => d.severity === 'high').length;
  const medium = data.filter(d => d.severity === 'medium').length;
  const access = data.filter(d => d.log_type === 'apache_access').length;
  const error = data.filter(d => d.log_type === 'apache_error').length;
  
  stats.innerHTML = `
    <div class="source-stat"><div class="value">${data.length}</div><div class="label">Total Events</div></div>
    <div class="source-stat"><div class="value">${critical}</div><div class="label">Critical</div></div>
    <div class="source-stat"><div class="value">${high}</div><div class="label">High</div></div>
    <div class="source-stat"><div class="value">${medium}</div><div class="label">Medium</div></div>
    <div class="source-stat"><div class="value">${access}</div><div class="label">Access</div></div>
    <div class="source-stat"><div class="value">${error}</div><div class="label">Error</div></div>
  `;
  
  document.getElementById('apacheCount').textContent = `Showing ${data.length} Apache events`;
}

// Render Nginx stats and table
function renderNginxStats(data) {
  const stats = document.getElementById('nginxStats');
  const critical = data.filter(d => d.severity === 'critical').length;
  const high = data.filter(d => d.severity === 'high').length;
  const medium = data.filter(d => d.severity === 'medium').length;
  const access = data.filter(d => d.log_type === 'nginx_access').length;
  const error = data.filter(d => d.log_type === 'nginx_error').length;
  
  stats.innerHTML = `
    <div class="source-stat"><div class="value">${data.length}</div><div class="label">Total Events</div></div>
    <div class="source-stat"><div class="value">${critical}</div><div class="label">Critical</div></div>
    <div class="source-stat"><div class="value">${high}</div><div class="label">High</div></div>
    <div class="source-stat"><div class="value">${medium}</div><div class="label">Medium</div></div>
    <div class="source-stat"><div class="value">${access}</div><div class="label">Access</div></div>
    <div class="source-stat"><div class="value">${error}</div><div class="label">Error</div></div>
  `;
  
  document.getElementById('nginxCount').textContent = `Showing ${data.length} Nginx events`;
}

// Render Docker stats and table
function renderDockerStats(data) {
  const stats = document.getElementById('dockerStats');
  const critical = data.filter(d => d.severity === 'critical').length;
  const high = data.filter(d => d.severity === 'high').length;
  const medium = data.filter(d => d.severity === 'medium').length;
  const container = data.filter(d => d.log_type === 'docker_container').length;
  const daemon = data.filter(d => d.log_type === 'docker_daemon').length;
  
  stats.innerHTML = `
    <div class="source-stat"><div class="value">${data.length}</div><div class="label">Total Events</div></div>
    <div class="source-stat"><div class="value">${critical}</div><div class="label">Critical</div></div>
    <div class="source-stat"><div class="value">${high}</div><div class="label">High</div></div>
    <div class="source-stat"><div class="value">${medium}</div><div class="label">Medium</div></div>
    <div class="source-stat"><div class="value">${container}</div><div class="label">Container</div></div>
    <div class="source-stat"><div class="value">${daemon}</div><div class="label">Daemon</div></div>
  `;
  
  document.getElementById('dockerCount').textContent = `Showing ${data.length} Docker events`;
}

// Render K8s stats and table
function renderK8sStats(data) {
  const stats = document.getElementById('k8sStats');
  const critical = data.filter(d => d.severity === 'critical').length;
  const high = data.filter(d => d.severity === 'high').length;
  const medium = data.filter(d => d.severity === 'medium').length;
  const audit = data.filter(d => d.log_type === 'k8s_audit').length;
  const pod = data.filter(d => d.log_type === 'k8s_pod').length;
  
  stats.innerHTML = `
    <div class="source-stat"><div class="value">${data.length}</div><div class="label">Total Events</div></div>
    <div class="source-stat"><div class="value">${critical}</div><div class="label">Critical</div></div>
    <div class="source-stat"><div class="value">${high}</div><div class="label">High</div></div>
    <div class="source-stat"><div class="value">${medium}</div><div class="label">Medium</div></div>
    <div class="source-stat"><div class="value">${audit}</div><div class="label">Audit</div></div>
    <div class="source-stat"><div class="value">${pod}</div><div class="label">Pod</div></div>
  `;
  
  document.getElementById('k8sCount').textContent = `Showing ${data.length} Kubernetes events`;
}

// Load Apache data
d3.json('../processed-data/events-apache-processed.json').then(data => {
  if (data.events) {
    apacheData = data.events;
    updateComplianceData();
    renderApacheStats(apacheData);
    
    if ($.fn.DataTable.isDataTable('#apache-table')) {
      $('#apache-table').DataTable().destroy();
    }
    
    $('#apache-table').DataTable({
      data: apacheData,
      columns: [
        { data: 'timestamp_utc', render: (d) => new Date(d).toLocaleString() },
        { data: 'hostname', defaultContent: '-', render: (d) => safeText(d) },
        { data: 'log_type', defaultContent: '-', render: (d) => {
          const token = safeToken(d);
          return token ? `<span class="log-type-${token}">${safeText(d)}</span>` : '-';
        } },
        { data: 'source_ip', defaultContent: '-', render: (d) => safeText(d) },
        { data: 'request_url', defaultContent: '-', render: (d) => safeText(d) },
        { data: 'http_status', defaultContent: '-', render: (d) => safeText(d) },
        { data: 'description', defaultContent: '-', render: (d) => safeText(d) },
        { data: 'severity', defaultContent: '-', render: (d) => {
          const token = safeToken(d);
          return token ? `<span class="severity-${token}">${safeText(d)}</span>` : '-';
        } }
      ],
      order: [[0, 'desc']],
      pageLength: 25
    });
  }
}).catch(err => {
  console.log('No Apache data available');
});

// Load Nginx data
d3.json('../processed-data/events-nginx-processed.json').then(data => {
  if (data.events) {
    nginxData = data.events;
    updateComplianceData();
    renderNginxStats(nginxData);
    
    if ($.fn.DataTable.isDataTable('#nginx-table')) {
      $('#nginx-table').DataTable().destroy();
    }
    
    $('#nginx-table').DataTable({
      data: nginxData,
      columns: [
        { data: 'timestamp_utc', render: (d) => new Date(d).toLocaleString() },
        { data: 'hostname', defaultContent: '-', render: (d) => safeText(d) },
        { data: 'log_type', defaultContent: '-', render: (d) => {
          const token = safeToken(d);
          return token ? `<span class="log-type-${token}">${safeText(d)}</span>` : '-';
        } },
        { data: 'source_ip', defaultContent: '-', render: (d) => safeText(d) },
        { data: 'request_url', defaultContent: '-', render: (d) => safeText(d) },
        { data: 'http_status', defaultContent: '-', render: (d) => safeText(d) },
        { data: 'description', defaultContent: '-', render: (d) => safeText(d) },
        { data: 'severity', defaultContent: '-', render: (d) => {
          const token = safeToken(d);
          return token ? `<span class="severity-${token}">${safeText(d)}</span>` : '-';
        } }
      ],
      order: [[0, 'desc']],
      pageLength: 25
    });
  }
}).catch(err => {
  console.log('No Nginx data available');
});

// Load Docker data
d3.json('../processed-data/events-docker-processed.json').then(data => {
  if (data.events) {
    dockerData = data.events;
    updateComplianceData();
    renderDockerStats(dockerData);
    
    if ($.fn.DataTable.isDataTable('#docker-table')) {
      $('#docker-table').DataTable().destroy();
    }
    
    $('#docker-table').DataTable({
      data: dockerData,
      columns: [
        { data: 'timestamp_utc', render: (d) => new Date(d).toLocaleString() },
        { data: 'hostname', defaultContent: '-' },
        { data: 'log_type', defaultContent: '-', render: (d) => d ? `<span class="log-type-${d}">${d}</span>` : '-' },
        { data: 'container_name', defaultContent: '-' },
        { data: 'image_name', defaultContent: '-' },
        { data: 'description', defaultContent: '-' },
        { data: 'severity', defaultContent: '-', render: (d) => d ? `<span class="severity-${d}">${d}</span>` : '-' }
      ],
      order: [[0, 'desc']],
      pageLength: 25
    });
  }
}).catch(err => {
  console.log('No Docker data available');
});

// Load Kubernetes data
d3.json('../processed-data/events-kubernetes-processed.json').then(data => {
  if (data.events) {
    k8sData = data.events;
    updateComplianceData();
    renderK8sStats(k8sData);
    
    if ($.fn.DataTable.isDataTable('#kubernetes-table')) {
      $('#kubernetes-table').DataTable().destroy();
    }
    
    $('#kubernetes-table').DataTable({
      data: k8sData,
      columns: [
        { data: 'timestamp_utc', render: (d) => new Date(d).toLocaleString() },
        { data: 'hostname', defaultContent: '-' },
        { data: 'log_type', defaultContent: '-', render: (d) => d ? `<span class="log-type-${d}">${d}</span>` : '-' },
        { data: 'namespace', defaultContent: '-' },
        { data: 'pod_name', defaultContent: '-' },
        { data: 'description', defaultContent: '-' },
        { data: 'severity', defaultContent: '-', render: (d) => d ? `<span class="severity-${d}">${d}</span>` : '-' }
      ],
      order: [[0, 'desc']],
      pageLength: 25
    });
  }
}).catch(err => {
  console.log('No Kubernetes data available');
});

// Download CSV handlers for Additional Sources
document.getElementById('downloadApacheCsv')?.addEventListener('click', () => {
  if (apacheData.length > 0) downloadCsv(apacheData, 'apache_logs.csv', ['Time', 'Host', 'Type', 'Source IP', 'URL', 'Status', 'Description', 'Severity']);
});

document.getElementById('downloadNginxCsv')?.addEventListener('click', () => {
  if (nginxData.length > 0) downloadCsv(nginxData, 'nginx_logs.csv', ['Time', 'Host', 'Type', 'Source IP', 'URL', 'Status', 'Description', 'Severity']);
});

document.getElementById('downloadDockerCsv')?.addEventListener('click', () => {
  if (dockerData.length > 0) downloadCsv(dockerData, 'docker_logs.csv', ['Time', 'Host', 'Type', 'Container', 'Image', 'Description', 'Severity']);
});

document.getElementById('downloadK8sCsv')?.addEventListener('click', () => {
  if (k8sData.length > 0) downloadCsv(k8sData, 'kubernetes_logs.csv', ['Time', 'Host', 'Type', 'Namespace', 'Pod', 'Description', 'Severity']);
});

try {
  setupVulnScanUI();
} catch (err) {
  console.error('Vulnerability Scan UI failed to initialize:', err);
}
