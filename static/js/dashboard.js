/**
 * SBOM Dependency Risk Analyzer — Dashboard JavaScript
 * Vanilla JS, no framework dependencies.
 * All data comes from real backend API responses.
 */

"use strict";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const state = {
  selectedFile: null,
  currentScanId: null,
  scans: [],
};

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------
const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];

function showPage(name) {
  $$(".page").forEach(p => p.classList.remove("active"));
  $$(".nav-item").forEach(n => n.classList.remove("active"));
  const page = $(`#page-${name}`);
  if (page) page.classList.add("active");
  const nav = $(`.nav-item[data-page="${name}"]`);
  if (nav) nav.classList.add("active");
}

function showAlert(el, msg, type = "error") {
  el.textContent = msg;
  el.className = `alert alert-${type} visible`;
}

function hideAlert(el) {
  el.className = "alert";
  el.textContent = "";
}

function setLoading(btn, loading, text = "Scan Dependencies") {
  if (loading) {
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Scanning…`;
  } else {
    btn.disabled = false;
    btn.innerHTML = text;
  }
}

function escHtml(str) {
  if (!str) return "—";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function severityBadge(sev) {
  const s = (sev || "unknown").toLowerCase();
  return `<span class="sev-badge sev-${s}">${escHtml(sev || "Unknown")}</span>`;
}

function gradeClass(grade) {
  const g = (grade || "").toLowerCase();
  return `risk-${g || "a"}`;
}

function formatDate(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function shortenVulnId(id) {
  if (!id) return "—";
  // Return just the GHSA or CVE id
  const m = id.match(/(GHSA-[\w-]+|CVE-\d{4}-\d+)/);
  return m ? m[1] : id;
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------
function initNav() {
  $$(".nav-item").forEach(item => {
    item.addEventListener("click", () => {
      const page = item.dataset.page;
      if (page === "history") loadHistory();
      showPage(page);
    });
  });
}

// ---------------------------------------------------------------------------
// Upload & Scan (Page: scan)
// ---------------------------------------------------------------------------
function initUpload() {
  const zone    = $("#upload-zone");
  const input   = $("#file-input");
  const fileBox = $("#selected-file");
  const fileName= $("#selected-file-name");
  const removeBtn = $("#remove-file");
  const scanBtn = $("#scan-btn");
  const alert   = $("#scan-alert");

  // Click-to-select
  zone.addEventListener("click", () => input.click());
  input.addEventListener("change", () => {
    if (input.files[0]) selectFile(input.files[0]);
  });

  // Drag-and-drop
  zone.addEventListener("dragover", e => { e.preventDefault(); zone.classList.add("drag-over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
  zone.addEventListener("drop", e => {
    e.preventDefault();
    zone.classList.remove("drag-over");
    if (e.dataTransfer.files[0]) selectFile(e.dataTransfer.files[0]);
  });

  removeBtn.addEventListener("click", e => {
    e.stopPropagation();
    clearFile();
  });

  scanBtn.addEventListener("click", () => runScan());

  function selectFile(file) {
    const ext = file.name.split(".").pop().toLowerCase();
    if (!["txt", "json"].includes(ext)) {
      showAlert(alert, "Only requirements.txt and package.json files are supported.", "error");
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      showAlert(alert, "File is too large. Maximum upload size is 2 MB.", "error");
      return;
    }
    hideAlert(alert);
    state.selectedFile = file;
    fileName.textContent = file.name;
    fileBox.classList.add("visible");
    zone.style.display = "none";
    scanBtn.disabled = false;
  }

  function clearFile() {
    state.selectedFile = null;
    input.value = "";
    fileBox.classList.remove("visible");
    zone.style.display = "";
    scanBtn.disabled = true;
    hideAlert(alert);
  }

  async function runScan() {
    if (!state.selectedFile) return;
    hideAlert(alert);
    setLoading(scanBtn, true);

    const formData = new FormData();
    formData.append("file", state.selectedFile);

    try {
      const res = await fetch("/api/scan", { method: "POST", body: formData });
      const data = await res.json();

      if (!res.ok) {
        showAlert(alert, data.error || `Scan failed (HTTP ${res.status}).`, "error");
        return;
      }

      // Success — go to results page
      state.currentScanId = data.scan_id;
      renderResults(data);
      showPage("results");
      clearFile();
    } catch (err) {
      showAlert(alert, "Network error — could not reach the server.", "error");
    } finally {
      setLoading(scanBtn, false, "Scan Dependencies");
    }
  }
}

// ---------------------------------------------------------------------------
// Results page
// ---------------------------------------------------------------------------
function renderResults(data) {
  // Header
  $("#result-filename").textContent = data.filename || "—";
  $("#result-ecosystem").textContent = data.ecosystem || "—";
  $("#result-date").textContent = formatDate(data.scanned_at);
  $("#result-scan-id").textContent = `#${data.scan_id}`;

  // Risk badge
  const grade = (data.risk_grade || "A");
  const badge = $("#risk-badge");
  badge.className = `risk-badge ${gradeClass(grade)}`;
  badge.innerHTML = `<span class="score">${data.risk_score ?? 0}</span><span class="grade">${grade}</span>`;

  // Risk info
  $("#risk-category").textContent = data.risk_category || "—";
  $("#risk-score-label").textContent = data.score_label || "Custom Project Risk Score (not CVSS)";

  // Insufficient coverage warning
  const warn = $("#coverage-warning");
  warn.style.display = data.insufficient_coverage ? "flex" : "none";

  // Counts
  const vc = data.vulnerability_counts || {};
  $("#stat-critical").textContent = vc.critical ?? 0;
  $("#stat-high").textContent = vc.high ?? 0;
  $("#stat-medium").textContent = vc.medium ?? 0;
  $("#stat-low").textContent = vc.low ?? 0;
  $("#stat-unknown").textContent = vc.unknown ?? 0;
  $("#stat-total-vulns").textContent = vc.total ?? 0;
  $("#stat-total-deps").textContent = data.total_deps ?? 0;
  $("#stat-scanned").textContent = data.scanned_deps ?? 0;
  $("#stat-skipped").textContent = data.skipped_deps ?? 0;
  $("#stat-errors").textContent = data.error_deps ?? 0;

  // Export buttons
  const exportSuffix = `/${data.scan_id}`;
  $("#btn-export-pdf").onclick = () => window.location.href = `/api/scan${exportSuffix}/export/pdf`;
  $("#btn-export-csv").onclick = () => window.location.href = `/api/scan${exportSuffix}/export/csv`;
  $("#btn-view-sbom").onclick = () => window.open(`/api/scan/${data.scan_id}/sbom`, "_blank");
  $("#btn-delete-scan").onclick = () => deleteScan(data.scan_id);

  // Vulnerability table
  renderVulnTable(data.vulnerabilities || []);
}

function renderVulnTable(vulns) {
  const tbody = $("#vuln-tbody");
  if (!vulns.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-state">
      <p>No vulnerabilities found in scanned dependencies.</p>
    </td></tr>`;
    return;
  }
  tbody.innerHTML = vulns.map(v => `
    <tr>
      <td>${escHtml(v.package_name)}</td>
      <td><code>${escHtml(v.version)}</code></td>
      <td class="vuln-id">${escHtml(shortenVulnId(v.vuln_id))}</td>
      <td>${severityBadge(v.severity)}</td>
      <td>${v.cvss_score != null ? v.cvss_score.toFixed(1) : "—"}</td>
      <td>${v.fixed_version ? `<code>${escHtml(v.fixed_version)}</code>` : "—"}</td>
      <td style="max-width:220px; font-size:12px; color:var(--text-muted)">${escHtml(v.recommendation)}</td>
    </tr>
  `).join("");
}

// ---------------------------------------------------------------------------
// Scan History (Page: history)
// ---------------------------------------------------------------------------
async function loadHistory() {
  const container = $("#history-list");
  const alert     = $("#history-alert");
  container.innerHTML = `<div style="color:var(--text-muted); font-size:13px">Loading…</div>`;
  hideAlert(alert);

  try {
    const res  = await fetch("/api/scans");
    const data = await res.json();

    if (!res.ok) {
      showAlert(alert, data.error || "Failed to load scan history.", "error");
      container.innerHTML = "";
      return;
    }

    if (!data.length) {
      container.innerHTML = `<div class="empty-state">
        <p>No scans yet. Upload a dependency file to get started.</p>
      </div>`;
      return;
    }

    container.innerHTML = data.map(scan => {
      const grade = scan.risk_grade || "A";
      const cat   = scan.risk_grade_label || "—";
      return `
        <div class="history-item" data-scan-id="${scan.id}">
          <div class="history-info">
            <div class="history-filename">${escHtml(scan.filename)}</div>
            <div class="history-meta">${escHtml(scan.ecosystem)} · ${formatDate(scan.created_at)} · ${scan.total_deps} deps</div>
          </div>
          <div class="history-score">
            <div class="num" style="color:var(--grade-${grade.toLowerCase()})">${scan.risk_score ?? 0}</div>
            <div style="font-size:11px; color:var(--text-muted)">${escHtml(cat)}</div>
          </div>
        </div>`;
    }).join("");

    // Click to load a scan
    $$(".history-item").forEach(item => {
      item.addEventListener("click", async () => {
        const id = item.dataset.scanId;
        await loadScanDetail(id);
      });
    });

  } catch (err) {
    showAlert(alert, "Network error loading history.", "error");
    container.innerHTML = "";
  }
}

async function loadScanDetail(scanId) {
  try {
    const res  = await fetch(`/api/scan/${scanId}`);
    const data = await res.json();
    if (!res.ok) { alert(data.error || "Could not load scan."); return; }

    // Merge risk grade from summary if API doesn't return it
    const grade = data.risk_grade || "A";
    const enriched = {
      ...data,
      risk_grade: grade,
      risk_category: data.risk_grade_label || "—",
      score_label: "Custom Project Risk Score (not CVSS)",
      vulnerability_counts: countVulns(data.vulnerabilities || []),
      scanned_at: data.created_at,
      insufficient_coverage: (data.scanned_deps === 0 && (data.skipped_deps + data.error_deps) > 0),
    };
    state.currentScanId = scanId;
    renderResults(enriched);
    showPage("results");
  } catch (err) {
    alert("Network error loading scan detail.");
  }
}

function countVulns(vulns) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0 };
  vulns.forEach(v => {
    if (!v.vuln_id) return;
    const s = (v.severity || "unknown").toLowerCase();
    if (counts[s] !== undefined) counts[s]++;
    else counts.unknown++;
    counts.total++;
  });
  return counts;
}

// ---------------------------------------------------------------------------
// Delete scan
// ---------------------------------------------------------------------------
async function deleteScan(scanId) {
  if (!confirm(`Delete scan #${scanId}? This cannot be undone.`)) return;
  try {
    const res = await fetch(`/api/scan/${scanId}`, { method: "DELETE" });
    if (res.ok) {
      showPage("scan");
    } else {
      const d = await res.json();
      alert(d.error || "Could not delete scan.");
    }
  } catch (err) {
    alert("Network error deleting scan.");
  }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  initNav();
  initUpload();
  showPage("scan");
  // Disable scan button until file chosen
  const scanBtn = $("#scan-btn");
  if (scanBtn) scanBtn.disabled = true;
});
