// Helpers for CSV generation
function stripHtml(html) {
  if (typeof html !== 'string') return html ?? '';
  const tmp = document.createElement('div');
  tmp.innerHTML = html;
  return tmp.textContent || tmp.innerText || '';
}

function csvEscape(value) {
  const s = String(value ?? '');
  if (/[",\n]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function downloadCsvFromCurrentPage(dt, filename, headers) {
  // Get only rows shown on current page
  const pageRows = dt.rows({ page: 'current' }).data().toArray();
  const lines = [];

  if (headers && headers.length) {
    lines.push(headers.map(csvEscape).join(','));
  }

  for (const row of pageRows) {
    // Row can contain HTML; strip it
    const cleaned = row.map(cell => csvEscape(stripHtml(cell)));
    lines.push(cleaned.join(','));
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

// ===================== MAIN ======================
d3.json("../data/parsed_logs.json").then(data => {
  const originalData = data.map(d => {
    const date = new Date(d.timestamp_utc);
    return {
      ...d,
      timestampDate: date,
      timestamp_local: date.toLocaleString(),
      severity: classifySeverity(d.message)
    };
  });

  const hosts = Array.from(new Set(originalData.map(d => d.hostname)));

  const hostFilter = document.getElementById("hostFilter");
  hostFilter.innerHTML = '<option value="all">All Hosts</option>';
  hosts.forEach(h => {
    const opt = document.createElement("option");
    opt.value = h;
    opt.innerText = h;
    hostFilter.appendChild(opt);
  });

  hostFilter.addEventListener("change", () => {
    renderTimeline(hostFilter.value);
    renderLogs(hostFilter.value);
  });

  renderTimeline("all");
  renderLogs("all");

  function classifySeverity(msg) {
    msg = (msg || '').toLowerCase();
    if (msg.includes("fail") || msg.includes("denied") || msg.includes("error")) return "error";
    if (msg.includes("warning") || msg.includes("invalid")) return "warning";
    if (msg.includes("session opened") || msg.includes("accepted")) return "info";
    if (msg.includes("root") && msg.includes("opened")) return "critical";
    return "info";
  }

  function renderTimeline(filterHost) {
    const filtered = filterHost === "all"
      ? originalData
      : originalData.filter(d => d.hostname === filterHost);

    d3.select("#timeline").html("");

    if (filtered.length === 0) {
      d3.select("#timeline").append("div").text("No data for selected host.");
      return;
    }

    const width = 1400;
    const height = 300;
    const margin = { top: 20, right: 20, bottom: 50, left: 120 };

    const xExtent = d3.extent(filtered, d => d.timestampDate);
    const durationMs = xExtent[1] - xExtent[0] || 1;
    const approxBinCount = 100;
    const binSizeMs = Math.max(60 * 1000, Math.floor(durationMs / approxBinCount));

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

    const svg = d3.select("#timeline")
      .append("svg")
      .attr("width", width)
      .attr("height", height);

    const tooltip = d3.select("body")
      .append("div")
      .attr("class", "tooltip")
      .style("opacity", 0);

    const severityLevels = ["info", "warning", "error", "critical"];
    const colorMap = {
      info: "#4caf50",
      warning: "#ff9800",
      error: "#f44336",
      critical: "#9c27b0"
    };

    const bins = d3.bin()
      .value(d => d.timestampDate.getTime())
      .thresholds(thresholds)(filtered);

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

    svg.append("g")
      .attr("transform", `translate(0, ${height - margin.bottom})`)
      .call(d3.axisBottom(x).ticks(10));

    svg.append("g")
      .attr("transform", `translate(${margin.left}, 0)`)
      .call(d3.axisLeft(y).ticks(6));

    // Draw stacked bars with full hover detail (including MITRE)
    stackedData.forEach(d => {
      let yOffset = 0;
      severityLevels.forEach(sev => {
        const count = d[sev];
        if (count === 0) return;

        const barHeight = y(0) - y(count);
        const yTop = y(d.total - yOffset);
        const barWidth = Math.max(2, x(d.x1) - x(d.x0) - 1); // ensure visible width

        svg.append("rect")
          .attr("x", x(d.x0))
          .attr("y", yTop)
          .attr("width", barWidth)
          .attr("height", barHeight)
          .attr("fill", colorMap[sev])
          .on("mouseover", (e) => {
            const sampleLogs = d.bin
              .filter(l => l.severity === sev)
              .slice(0, 5)
              .map(log => {
                const mitreHtml = log.mitre && log.mitre.length > 0
                  ? log.mitre.map(m =>
                      `<div style="margin-left:10px;">
                        <strong>${m.technique_id} - ${m.technique_name}</strong><br/>
                        <em>${m.tactic}</em>: ${m.description}
                      </div>`).join("")
                  : "<div style='margin-left:10px;'><i>No MITRE match</i></div>";

                return `
                  <div style="margin-bottom:6px;">
                    <strong>${log.timestamp_local}</strong><br/>
                    ${log.hostname} \u2022 ${log.process}${log.pid ? ` [${log.pid}]` : ""}<br/>
                    ${log.message}<br/>
                    ${mitreHtml}
                  </div>
                `;
              }).join("");

            tooltip.transition().duration(200).style("opacity", 0.95);
            tooltip.html(`
              <strong>${sev.toUpperCase()}</strong> logs: ${count}<br/>
              ${sampleLogs}${count > 5 ? "<em>...more</em>" : ""}
            `)
              .style("left", (e.pageX + 10) + "px")
              .style("top", (e.pageY - 28) + "px");
          })
          .on("mouseout", () => tooltip.transition().duration(500).style("opacity", 0));

        yOffset += count;
      });
    });
  }

  function renderLogs(filterHost) {
    const filtered = filterHost === "all"
      ? originalData
      : originalData.filter(d => d.hostname === filterHost);

    const sorted = filtered.sort((a, b) => b.timestampDate - a.timestampDate);

    const rows = sorted.map(d => [
      d.timestamp_local,
      d.hostname,
      `${d.process}${d.pid ? ` [${d.pid}]` : ""}`,
      d.message,
      d.mitre && d.mitre.length > 0
        ? d.mitre.map(m => `${m.technique_id}: ${m.technique_name}`).join("<br/>")
        : ""
    ]);

    // expose DataTable instance globally so the Download button can access it
    window.logsDT = $('#logs-table').DataTable({
      destroy: true,
      pageLength: 10,
      order: [[0, 'desc']]
    });

    window.logsDT.clear();
    window.logsDT.rows.add(rows);
    window.logsDT.draw();
  }

  // Wire up CSV download for Timeline logs (current page only)
  document.getElementById('download-logs-csv').addEventListener('click', () => {
    if (!window.logsDT) return;
    downloadCsvFromCurrentPage(window.logsDT, 'timeline_logs_page.csv', [
      'Time', 'Host', 'Process [PID]', 'Message', 'MITRE Techniques'
    ]);
  });

}).catch(console.error);

// ============= FIM Logs =============
d3.json("../data/parsed_fim_logs.json").then(fimData => {
  // Build rows
  const rows = fimData.map(d => [
    new Date(d.timestamp_utc).toLocaleString(),
    d.hostname,
    d.path,
    d.change,
    d.new && d.new.hash ? d.new.hash : "-"
  ]);

  // Expose FIM table instance globally for CSV export
  window.fimDT = $('#fim-table').DataTable({
    destroy: true,
    pageLength: 10,
    order: [[0, 'desc']]
  });

  window.fimDT.clear();
  window.fimDT.rows.add(rows);
  window.fimDT.draw();

  // Wire up CSV download for FIM (current page only)
  document.getElementById('download-fim-csv').addEventListener('click', () => {
    if (!window.fimDT) return;
    downloadCsvFromCurrentPage(window.fimDT, 'fim_logs_page.csv', [
      'Time', 'Host', 'File', 'Change Type', 'Hash (New)'
    ]);
  });

}).catch(err => {
  console.error("FIM data error:", err);
});


// ============= Security Alerts =============
async function loadAlerts() {
  try {
    const response = await fetch('../api/alerts_api.py');
    const data = await response.json();
    renderAlertsTable(data.alerts || []);
    updateAlertStats(data.alerts || []);
  } catch (err) {
    console.error("Error loading alerts:", err);
    // Fallback: empty alerts for now
    renderAlertsTable([]);
    updateAlertStats([]);
  }
}

function renderAlertsTable(alerts) {
  const rows = alerts.map(a => {
    const severityClass = `alert-${a.severity?.toLowerCase() || 'low'}`;
    const status = a.status || 'open';
    return [
      new Date(a.timestamp).toLocaleString(),
      `<span class="alert-badge ${severityClass}">${a.severity || 'LOW'}</span>`,
      a.title || '',
      a.source_ip || '-',
      a.hostname || '-',
      status,
      `<button onclick="acknowledgeAlert(${a.id})">ACK</button> 
       <button onclick="closeAlert(${a.id})">Close</button>`
    ];
  });

  if (window.alertsDT) {
    window.alertsDT.destroy();
  }

  window.alertsDT = $('#alerts-table').DataTable({
    destroy: true,
    pageLength: 10,
    order: [[0, 'desc']]
  });

  window.alertsDT.clear();
  window.alertsDT.rows.add(rows);
  window.alertsDT.draw();
}

function updateAlertStats(alerts) {
  const stats = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  alerts.forEach(a => {
    const sev = a.severity?.toUpperCase() || 'LOW';
    if (stats[sev] !== undefined) stats[sev]++;
  });

  document.getElementById('statCritical').textContent = stats.CRITICAL;
  document.getElementById('statHigh').textContent = stats.HIGH;
  document.getElementById('statMedium').textContent = stats.MEDIUM;
  document.getElementById('statLow').textContent = stats.LOW;
}

window.acknowledgeAlert = async function(alertId) {
  try {
    await fetch(`/api/alerts/${alertId}/acknowledge`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({acknowledged_by: 'analyst'})
    });
    loadAlerts();
  } catch (err) {
    alert('Failed to acknowledge alert');
  }
};

window.closeAlert = async function(alertId) {
  try {
    await fetch(`/api/alerts/${alertId}/close`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'}
    });
    loadAlerts();
  } catch (err) {
    alert('Failed to close alert');
  }
};

document.getElementById('runDetection')?.addEventListener('click', async () => {
  try {
    const response = await fetch('/api/detect', {method: 'POST'});
    const result = await response.json();
    alert(`Detection complete. Generated ${result.alerts_generated} alerts.`);
    loadAlerts();
  } catch (err) {
    alert('Detection failed');
  }
});

document.getElementById('download-alerts-csv')?.addEventListener('click', () => {
  if (!window.alertsDT) return;
  downloadCsvFromCurrentPage(window.alertsDT, 'alerts_page.csv', [
    'Time', 'Severity', 'Title', 'Source IP', 'Hostname', 'Status'
  ]);
});

// Initialize alerts tab when DOM ready
document.addEventListener('DOMContentLoaded', () => {
  // Slight delay to ensure API is ready
  setTimeout(loadAlerts, 500);
});
