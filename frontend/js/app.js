// Frontend Application Logic for AI WAF Admin Dashboard

const API_BASE = ""; // Relative path to FastAPI backend

// Tab Navigation
function switchTab(tabId) {
  document.querySelectorAll(".tab-content").forEach(el => el.classList.remove("active"));
  document.querySelectorAll(".nav-link").forEach(el => el.classList.remove("active"));

  const targetTab = document.getElementById(tabId);
  const targetLink = document.querySelector(`[data-tab="${tabId}"]`);

  if (targetTab) targetTab.classList.add("active");
  if (targetLink) targetLink.classList.add("active");

  const titles = {
    "tab-overview": "Security Overview",
    "tab-traffic": "Live Network Traffic",
    "tab-threats": "Threat Detection & Injections",
    "tab-performance": "Model Performance & Benchmarks",
    "tab-fn": "False Negative Management",
    "tab-inspector": "WAF Payload Inspector / Lab"
  };
  const titleEl = document.getElementById("page-title");
  if (titleEl && titles[tabId]) titleEl.innerText = titles[tabId];

  if (tabId === "tab-overview") loadStats();
  if (tabId === "tab-traffic") loadTraffic();
  if (tabId === "tab-threats") loadThreats();
  if (tabId === "tab-performance") loadPerformanceMetrics();
  if (tabId === "tab-fn") loadFalseNegatives();
}

document.querySelectorAll(".nav-link").forEach(link => {
  link.addEventListener("click", () => {
    const tab = link.getAttribute("data-tab");
    if (tab) switchTab(tab);
  });
});

// Load Overview Statistics
async function loadStats() {
  try {
    const res = await fetch(`${API_BASE}/stats`);
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById("stat-total").innerText = data.total_requests.toLocaleString();
    document.getElementById("stat-benign").innerText = data.benign_count.toLocaleString();
    document.getElementById("stat-malicious").innerText = data.malicious_count.toLocaleString();
    document.getElementById("stat-rate").innerText = `${(data.detection_rate * 100).toFixed(1)}%`;

    // Threat distribution cards
    const grid = document.getElementById("threat-category-grid");
    grid.innerHTML = "";
    const dist = data.threat_distribution || {};
    const keys = Object.keys(dist);

    if (keys.length === 0) {
      grid.innerHTML = `<div style="color: var(--text-muted); font-size: 13px;">No attack categories logged yet.</div>`;
    } else {
      for (const [k, v] of Object.entries(dist)) {
        if (k === "none") continue;
        const card = document.createElement("div");
        card.className = "stat-card";
        card.innerHTML = `
          <div class="stat-label" style="text-transform: uppercase;">${k.replace("_", " ")}</div>
          <div class="stat-value" style="color: var(--red-primary);">${v}</div>
        `;
        grid.appendChild(card);
      }
    }

    // Also populate overview recent table
    loadRecentOverview();
  } catch (err) {
    console.error("Failed to fetch stats:", err);
  }
}

// Recent logs on overview
async function loadRecentOverview() {
  try {
    const res = await fetch(`${API_BASE}/logs?limit=5`);
    if (!res.ok) return;
    const logs = await res.json();
    const tbody = document.getElementById("overview-recent-table");
    tbody.innerHTML = "";

    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No requests recorded yet. Try testing a payload in the Inspector!</td></tr>`;
      return;
    }

    logs.forEach(item => {
      const isMal = item.prediction === "MALICIOUS";
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${new Date(item.timestamp).toLocaleTimeString()}</td>
        <td><span class="badge badge-method">${item.method}</span></td>
        <td style="font-family: var(--font-mono);">${escapeHtml(item.path)}</td>
        <td><span class="badge ${isMal ? 'badge-malicious' : 'badge-benign'}">${item.prediction}</span></td>
        <td>${(item.confidence * 100).toFixed(1)}%</td>
        <td><span style="color: ${item.action_taken === 'BLOCKED' ? 'var(--red-primary)' : 'var(--green-primary)'}; font-weight: 600;">${item.action_taken}</span></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error(e);
  }
}

// Load Live Traffic Table
async function loadTraffic() {
  try {
    const filterType = document.getElementById("filter-traffic-type").value;
    let url = `${API_BASE}/logs?limit=50`;
    if (filterType) url += `&prediction=${filterType}`;

    const res = await fetch(url);
    if (!res.ok) return;
    const logs = await res.json();
    const tbody = document.getElementById("live-traffic-table");
    tbody.innerHTML = "";

    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted);">No records found.</td></tr>`;
      return;
    }

    logs.forEach(item => {
      const isMal = item.prediction === "MALICIOUS";
      const snippet = item.body || item.query_params || item.path;
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>#${item.id}</td>
        <td>${new Date(item.timestamp).toLocaleTimeString()}</td>
        <td><span class="badge badge-method">${item.method}</span></td>
        <td style="font-family: var(--font-mono);">${escapeHtml(item.path)}</td>
        <td><span class="code-snippet" title="${escapeHtml(snippet)}">${escapeHtml(snippet)}</span></td>
        <td><span class="badge ${isMal ? 'badge-malicious' : 'badge-benign'}">${item.prediction}</span></td>
        <td>${(item.confidence * 100).toFixed(1)}%</td>
        <td>${item.latency_ms} ms</td>
        <td><span style="color: ${item.action_taken === 'BLOCKED' ? 'var(--red-primary)' : 'var(--green-primary)'}; font-weight: 600;">${item.action_taken}</span></td>
        <td>
          <button class="btn btn-outline" style="padding: 2px 8px; font-size: 11px;" onclick="openReviewModal(${item.id}, '${item.prediction}')">Review</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Traffic load error:", err);
  }
}

// Load Threats Table
async function loadThreats() {
  try {
    const res = await fetch(`${API_BASE}/logs?prediction=MALICIOUS&limit=50`);
    if (!res.ok) return;
    const logs = await res.json();
    const tbody = document.getElementById("threats-table");
    tbody.innerHTML = "";
    document.getElementById("threats-badge-count").innerText = `${logs.length} Blocked`;

    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No security attacks recorded yet.</td></tr>`;
      return;
    }

    logs.forEach(item => {
      const tr = document.createElement("tr");
      const snippet = item.body || item.query_params || item.path;
      tr.innerHTML = `
        <td>${new Date(item.timestamp).toLocaleTimeString()}</td>
        <td><span class="badge badge-malicious">${item.threat_category.replace("_", " ")}</span></td>
        <td><span class="badge badge-method">${item.method}</span> <span style="font-family: var(--font-mono);">${escapeHtml(item.path)}</span></td>
        <td><span class="code-snippet">${escapeHtml(snippet)}</span></td>
        <td>${(item.confidence * 100).toFixed(1)}%</td>
        <td><span style="color: var(--red-primary); font-weight: 600;">${item.action_taken}</span></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error(err);
  }
}

// Load False Negatives Review
async function loadFalseNegatives() {
  try {
    const res = await fetch(`${API_BASE}/feedback/queue`);
    if (!res.ok) return;
    const items = await res.json();
    const tbody = document.getElementById("fn-review-table");
    tbody.innerHTML = "";
    document.getElementById("fn-count-badge").innerText = `${items.length} Flagged`;

    if (items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No false negatives currently recorded.</td></tr>`;
      return;
    }

    items.forEach(item => {
      const tr = document.createElement("tr");
      const snippet = item.body || item.query_params || item.path;
      tr.innerHTML = `
        <td>#${item.id}</td>
        <td>${new Date(item.timestamp).toLocaleTimeString()}</td>
        <td><span class="badge badge-method">${item.method}</span> ${escapeHtml(item.path)}</td>
        <td><span class="code-snippet">${escapeHtml(snippet)}</span></td>
        <td style="color: var(--red-primary); font-size: 12px;">Missed attack flagged by admin</td>
        <td><span class="badge badge-malicious">QUEUED FOR RETRAINING</span></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error(e);
  }
}

// Load Performance Metrics (from benchmark report)
async function loadPerformanceMetrics() {
  try {
    const res = await fetch(`${API_BASE}/metrics/benchmark`);
    if (!res.ok) return;
    const data = await res.json();
    const benchmark = data.baseline || data.distilbert;
    if (!benchmark || !benchmark.metrics) return;

    const m = benchmark.metrics;
    document.getElementById("perf-accuracy").innerText = `${(m.accuracy * 100).toFixed(1)}%`;
    document.getElementById("perf-precision").innerText = `${(m.precision * 100).toFixed(1)}%`;
    document.getElementById("perf-recall").innerText = `${(m.recall * 100).toFixed(1)}%`;
    document.getElementById("perf-f1").innerText = m.f1_score.toFixed(3);
    document.getElementById("perf-fnr").innerText = `${(m.false_negative_rate * 100).toFixed(2)}%`;
    document.getElementById("perf-fpr").innerText = `${(m.false_positive_rate * 100).toFixed(2)}%`;

    const cm = m.confusion_matrix;
    if (cm) {
      document.getElementById("cm-tn").innerText = cm.true_negatives;
      document.getElementById("cm-fp").innerText = cm.false_positives;
      document.getElementById("cm-fn").innerText = cm.false_negatives;
      document.getElementById("cm-tp").innerText = cm.true_positives;
    }
  } catch (e) {
    console.error("Performance load error:", e);
  }
}

// Feedback Modal Handlers
function openReviewModal(logId, currentPred) {
  document.getElementById("modal-log-id").value = logId;
  document.getElementById("modal-original-pred").innerText = currentPred;
  document.getElementById("modal-notes").value = "";
  document.getElementById("modal-review").style.display = "flex";
}

function closeReviewModal() {
  document.getElementById("modal-review").style.display = "none";
}

document.getElementById("feedback-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const logId = parseInt(document.getElementById("modal-log-id").value);
  const corrected = document.getElementById("modal-correct-label").value;
  const notes = document.getElementById("modal-notes").value;

  try {
    const res = await fetch(`${API_BASE}/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        log_id: logId,
        corrected_label: corrected,
        notes: notes
      })
    });
    if (res.ok) {
      alert("Feedback saved successfully!");
      closeReviewModal();
      loadTraffic();
      loadStats();
    } else {
      alert("Error submitting feedback.");
    }
  } catch (err) {
    alert(`Error: ${err}`);
  }
});

// WAF Inspector & Quick Presets
const PRESETS = {
  sqli: {
    method: "POST",
    path: "/api/v1/auth/login",
    query: "",
    body: '{"username": "admin\' OR \'1\'=\'1", "password": "any"}'
  },
  xss: {
    method: "POST",
    path: "/api/v1/comments",
    query: "",
    body: '{"author": "attacker", "content": "<script>alert(document.cookie)</script>"}'
  },
  traversal: {
    method: "GET",
    path: "/api/v1/download",
    query: "file=../../../../etc/passwd",
    body: ""
  },
  cmdi: {
    method: "POST",
    path: "/api/v1/ping",
    query: "",
    body: '{"host": "127.0.0.1; cat /etc/passwd"}'
  },
  benign: {
    method: "GET",
    path: "/api/v1/products",
    query: "search=wireless+noise+cancelling+headphones&page=1&limit=20",
    body: ""
  }
};

function loadPreset(type) {
  const p = PRESETS[type];
  if (!p) return;
  document.getElementById("insp-method").value = p.method;
  document.getElementById("insp-path").value = p.path;
  document.getElementById("insp-query").value = p.query;
  document.getElementById("insp-body").value = p.body;
}

document.getElementById("inspector-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = document.getElementById("btn-inspect-submit");
  btn.disabled = true;
  btn.innerText = "Inspecting...";

  const payload = {
    method: document.getElementById("insp-method").value,
    path: document.getElementById("insp-path").value,
    query_params: document.getElementById("insp-query").value,
    body: document.getElementById("insp-body").value,
    headers: { "user-agent": "WAF-Inspector-Console/1.0" }
  };

  try {
    const res = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error("Inspection API returned error");
    const data = await res.json();
    const pred = data.prediction_result;

    const outBox = document.getElementById("inspector-output");
    outBox.style.display = "block";

    const badge = document.getElementById("insp-badge-result");
    const isMal = pred.is_malicious;
    badge.className = `badge ${isMal ? 'badge-malicious' : 'badge-benign'}`;
    badge.innerText = pred.action_taken;

    document.getElementById("insp-res-pred").innerText = pred.prediction;
    document.getElementById("insp-res-pred").style.color = isMal ? 'var(--red-primary)' : 'var(--green-primary)';
    document.getElementById("insp-res-conf").innerText = `${(pred.confidence * 100).toFixed(1)}%`;
    document.getElementById("insp-res-lat").innerText = `${pred.latency_ms} ms`;
    document.getElementById("insp-res-rec").innerText = data.recommendation;
    document.getElementById("insp-res-model").innerText = pred.model_used;

    const findingsDiv = document.getElementById("insp-findings-list");
    if (data.findings && data.findings.length > 0) {
      findingsDiv.innerHTML = `<strong>Detected Attack Patterns:</strong><ul style="margin-left: 20px; margin-top: 6px;">` +
        data.findings.map(f => `<li style="color: var(--red-primary);">[${f.severity}] <strong>${f.category}:</strong> ${f.explanation} (<code>${escapeHtml(f.matched_snippet)}</code>)</li>`).join("") +
        `</ul>`;
    } else {
      findingsDiv.innerHTML = `<span style="color: var(--green-primary);">Clean: No suspicious signature or injection patterns detected.</span>`;
    }

    // Refresh overview stats and logs in the background
    loadStats();
  } catch (err) {
    alert(`Error: ${err}`);
  } finally {
    btn.disabled = false;
    btn.innerText = "Inspect Request";
  }
});

// Helper for HTML escaping
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Initial Load & Event Listeners
document.getElementById("btn-refresh").addEventListener("click", () => {
  loadStats();
  loadTraffic();
});

document.getElementById("filter-traffic-type").addEventListener("change", () => {
  loadTraffic();
});

// Start initial load
loadStats();
loadPerformanceMetrics();
