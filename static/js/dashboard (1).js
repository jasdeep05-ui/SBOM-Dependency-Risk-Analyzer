/* SBOM & Dependency Risk Analyzer — dashboard logic (vanilla JS, no dependencies) */
(function () {
  "use strict";

  /* ------------------------------------------------------------------ *
   * Config & helpers
   * ------------------------------------------------------------------ */
  var MAX_BYTES = 2 * 1024 * 1024;
  var SEVS = ["Critical", "High", "Medium", "Low", "Unknown"];
  var SEV_WEIGHT = { Critical: 10, High: 5, Medium: 2, Low: 1, Unknown: 0 };
  var SEV_GLYPH = { Critical: "C", High: "H", Medium: "M", Low: "L", Unknown: "?" };
  var SEV_VAR = {
    Critical: "var(--sev-critical)", High: "var(--sev-high)", Medium: "var(--sev-medium)",
    Low: "var(--sev-low)", Unknown: "var(--sev-unknown)"
  };
  var GRADE = {
    A: { label: "Safe", color: "var(--grade-a)" }, B: { label: "Low Risk", color: "var(--grade-b)" },
    C: { label: "Moderate", color: "var(--grade-c)" }, D: { label: "High Risk", color: "var(--grade-d)" },
    F: { label: "Critical", color: "var(--grade-f)" }
  };

  var $ = function (id) { return document.getElementById(id); };
  var state = { scanId: null, scan: null, vulns: [], coverage: null, filter: {}, query: "", sort: { key: "sev", dir: 1 }, open: {}, sbom: null };

  function esc(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function normSev(s) {
    var t = String(s || "").toLowerCase();
    if (t === "critical") return "Critical";
    if (t === "high") return "High";
    if (t === "medium" || t === "moderate") return "Medium";
    if (t === "low") return "Low";
    return "Unknown";
  }
  function gradeFor(score) {
    return score >= 80 ? "F" : score >= 60 ? "D" : score >= 40 ? "C" : score >= 20 ? "B" : "A";
  }
  function fmtDate(s) {
    if (!s) return "";
    var d = new Date(s);
    return isNaN(d) ? String(s) : d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
  }
  function toast(msg, type) {
    var el = document.createElement("div");
    el.className = "toast " + (type || "");
    el.textContent = msg;
    $("toasts").appendChild(el);
    setTimeout(function () { el.remove(); }, 3800);
  }
  function api(url, opts) {
    return fetch(url, opts).then(function (r) {
      return r.text().then(function (t) {
        var data = null;
        try { data = t ? JSON.parse(t) : null; } catch (e) { /* non-JSON body */ }
        if (!r.ok) throw new Error((data && data.error) || ("Request failed (" + r.status + ")"));
        return data;
      });
    });
  }
  function show(view) {
    ["viewUpload", "viewPipeline", "viewResults"].forEach(function (v) { $(v).classList.toggle("hidden", v !== view); });
    $("topActions").classList.toggle("hidden", view !== "viewResults");
    if (view !== "viewResults") $("crumb").textContent = view === "viewUpload" ? "New scan" : "Scanning…";
  }

  /* ------------------------------------------------------------------ *
   * Theme & sidebar
   * ------------------------------------------------------------------ */
  (function initTheme() {
    var saved = null;
    try { saved = localStorage.getItem("sbom-theme"); } catch (e) {}
    if (saved) document.documentElement.setAttribute("data-theme", saved);
  })();
  $("themeBtn").onclick = function () {
    var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("sbom-theme", next); } catch (e) {}
  };
  $("menuBtn").onclick = function () { $("sidebar").classList.toggle("collapsed"); };
  if (window.innerWidth <= 820) $("sidebar").classList.add("collapsed");

  /* ------------------------------------------------------------------ *
   * Upload + pipeline
   * ------------------------------------------------------------------ */
  var STEPS = [
    ["Parsing dependencies", "Reading names and version specifiers"],
    ["Generating SBOM", "Building a CycloneDX 1.5 document"],
    ["Querying OSV", "Checking exact versions against the vulnerability database"],
    ["Scoring risk", "Classifying severity and computing the project score"]
  ];
  var pipeTimer = null;

  function renderSteps(active, allDone) {
    $("steps").innerHTML = STEPS.map(function (s, i) {
      var cls = allDone || i < active ? "done" : i === active ? "active" : "";
      return '<div class="step ' + cls + '"><div class="step-ico">' + (cls === "done" ? "✓" : "") + '</div><div><div class="step-name">' +
        esc(s[0]) + '</div><div class="step-desc">' + esc(s[1]) + "</div></div></div>";
    }).join("");
  }
  function startPipeline(name) {
    $("pipeFile").textContent = name;
    show("viewPipeline");
    var i = 0;
    renderSteps(0);
    clearInterval(pipeTimer);
    // Steps advance on a timer while the single POST is in flight; step 3 (OSV) holds until the response arrives.
    pipeTimer = setInterval(function () { if (i < 2) { i++; renderSteps(i); } }, 700);
  }
  function stopPipeline() { clearInterval(pipeTimer); }

  function validate(file) {
    var n = (file.name || "").toLowerCase();
    if (!/\.(txt|json)$/.test(n)) return "Only .txt (requirements.txt) and .json (package.json) files are supported.";
    if (file.size > MAX_BYTES) return "File is larger than the 2 MB limit.";
    if (file.size === 0) return "File is empty.";
    return null;
  }
  function submit(file) {
    var err = validate(file);
    if (err) { toast(err, "error"); return; }
    var fd = new FormData();
    fd.append("file", file);
    startPipeline(file.name);
    api("/api/scan", { method: "POST", body: fd }).then(function (res) {
      stopPipeline();
      renderSteps(4, true);
      var id = res && (res.scan_id || res.id || (res.scan && res.scan.id));
      toast("Scan complete", "ok");
      setTimeout(function () { loadHistory(); if (id != null) openScan(id); else show("viewUpload"); }, 500);
    }).catch(function (e) {
      stopPipeline();
      show("viewUpload");
      toast(e.message, "error");
    });
  }

  var dz = $("dropzone"), fi = $("fileInput");
  dz.onclick = function () { fi.click(); };
  dz.onkeydown = function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fi.click(); } };
  fi.onchange = function () { if (fi.files[0]) submit(fi.files[0]); fi.value = ""; };
  ["dragenter", "dragover"].forEach(function (ev) { dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add("drag"); }); });
  ["dragleave", "drop"].forEach(function (ev) { dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.remove("drag"); }); });
  dz.addEventListener("drop", function (e) { var f = e.dataTransfer.files[0]; if (f) submit(f); });

  var SAMPLE_REQ = "requests==2.19.0\nflask==0.12.2\ndjango==2.2.0\npyyaml==5.3\njinja2==2.10\nurllib3==1.24.1\nnumpy>=1.20\npandas\nclick==8.1.7\n";
  var SAMPLE_PKG = JSON.stringify({
    name: "sample-app", version: "1.0.0",
    dependencies: { lodash: "4.17.15", express: "4.16.0", minimist: "1.2.0", axios: "^0.21.0", "@angular/core": "11.0.0" },
    devDependencies: { jest: "26.0.0", webpack: "*" }
  }, null, 2);
  $("sampleReqBtn").onclick = function () { submit(new File([SAMPLE_REQ], "requirements.txt", { type: "text/plain" })); };
  $("samplePkgBtn").onclick = function () { submit(new File([SAMPLE_PKG], "package.json", { type: "application/json" })); };
  $("newScanBtn").onclick = function () { state.scanId = null; location.hash = "analyzer"; markActive(); show("viewUpload"); };

  /* ------------------------------------------------------------------ *
   * History
   * ------------------------------------------------------------------ */
  function loadHistory() {
    return api("/api/scans").then(function (data) {
      var list = Array.isArray(data) ? data : (data && (data.scans || data.items)) || [];
      state.history = list;
      var box = $("history");
      if (!list.length) { box.innerHTML = '<div class="faint" style="padding:10px 12px;font-size:13px">No scans yet. Upload a file to get started.</div>'; return; }
      box.innerHTML = list.map(function (s) {
        var g = (s.risk_grade || gradeFor(s.risk_score || 0)).toString().charAt(0).toUpperCase();
        var col = (GRADE[g] || {}).color || "var(--text-dim)";
        return '<button class="hist-item" data-id="' + esc(s.id) + '"><span class="grade-badge" style="--g:' + col + '">' + esc(g) +
          '</span><span class="hist-meta"><div class="hist-name">' + esc(s.filename) + '</div><div class="hist-date">' +
          esc(fmtDate(s.created_at)) + " · " + esc(s.ecosystem || "") + "</div></span></button>";
      }).join("");
      markActive();
    }).catch(function () { $("history").innerHTML = '<div class="faint" style="padding:10px 12px;font-size:13px">Could not load history.</div>'; });
  }
  function markActive() {
    document.querySelectorAll(".hist-item").forEach(function (b) { b.classList.toggle("active", String(b.dataset.id) === String(state.scanId)); });
  }
  $("history").addEventListener("click", function (e) {
    var b = e.target.closest(".hist-item");
    if (b) { openScan(b.dataset.id); if (window.innerWidth <= 820) $("sidebar").classList.add("collapsed"); }
  });

  /* ------------------------------------------------------------------ *
   * Open + normalise a scan
   * ------------------------------------------------------------------ */
  function openScan(id) {
    state.scanId = id; state.sbom = null; state.filter = {}; state.query = ""; state.open = {};
    $("search").value = "";
    location.hash = "scan=" + id;
    markActive();
    show("viewResults");
    $("resultsSkeleton").style.display = "grid";
    $("resultsBody").classList.add("hidden");
    switchTab("overview");
    api("/api/scan/" + encodeURIComponent(id)).then(function (data) {
      normalise(data);
      render();
      $("resultsSkeleton").style.display = "none";
      $("resultsBody").classList.remove("hidden");
      $("crumb").textContent = state.scan.filename || ("Scan #" + id);
      $("exportPdf").href = "/api/scan/" + encodeURIComponent(id) + "/export/pdf";
      $("exportCsv").href = "/api/scan/" + encodeURIComponent(id) + "/export/csv";
    }).catch(function (e) { toast(e.message, "error"); show("viewUpload"); });
  }

  function normalise(data) {
    var scan = (data && data.scan) || data || {};
    var rows = (data && data.vulnerabilities) || scan.vulnerabilities || [];
    var vulns = [], pkgStatus = {};
    rows.forEach(function (r) {
      var key = (r.package_name || r.name) + "@" + (r.version || "");
      var status = r.scan_status || "scanned";
      if (!pkgStatus[key] || status === "scan_error") pkgStatus[key] = { status: status, version_type: r.version_type, name: r.package_name || r.name, version: r.version, error: r.error_message };
      if (r.vuln_id && status === "scanned") {
        vulns.push({
          pkg: r.package_name || r.name, version: r.version || "", version_type: r.version_type || "exact",
          id: r.vuln_id, sev: normSev(r.severity), cvss: r.cvss_score, vector: r.cvss_vector,
          title: r.title || "", desc: r.description || "", fixed: r.fixed_version || "", rec: r.recommendation || ""
        });
      }
    });
    var cov = { scanned: 0, skipped: 0, error: 0, skippedList: [], errorList: [] };
    Object.keys(pkgStatus).forEach(function (k) {
      var p = pkgStatus[k];
      if (p.status === "scan_error") { cov.error++; cov.errorList.push(p); }
      else if (/^skipped/.test(p.status)) { cov.skipped++; cov.skippedList.push(p); }
      else cov.scanned++;
    });
    // Prefer server-side totals when present (they also count clean packages that have no rows).
    if (scan.scanned_deps != null) cov.scanned = scan.scanned_deps;
    if (scan.skipped_deps != null) cov.skipped = scan.skipped_deps;
    if (scan.error_deps != null) cov.error = scan.error_deps;
    cov.total = scan.total_deps != null ? scan.total_deps : cov.scanned + cov.skipped + cov.error;

    var counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 };
    vulns.forEach(function (v) { counts[v.sev]++; });
    var raw = counts.Critical * 10 + counts.High * 5 + counts.Medium * 2 + counts.Low;
    var score = scan.risk_score != null ? Number(scan.risk_score) : Math.min(raw, 100);
    var grade = (scan.risk_grade || gradeFor(score)).toString().charAt(0).toUpperCase();

    state.scan = scan; state.vulns = vulns; state.counts = counts; state.cov = cov; state.score = score; state.grade = grade;
  }

  /* ------------------------------------------------------------------ *
   * Render: hero
   * ------------------------------------------------------------------ */
  function render() {
    renderGauge(); renderStats(); renderCoverage(); renderFixes(); renderDonut(); renderHbar();
    renderFilters(); renderHead(); renderTable();
    $("vulnCount").textContent = state.vulns.length;
  }

  function renderGauge() {
    var g = GRADE[state.grade] || GRADE.A, score = Math.max(0, Math.min(100, state.score));
    var len = Math.PI * 100; // semicircle radius 100
    var insufficient = state.cov.scanned === 0 && state.cov.total > 0;
    $("gaugeCard").style.setProperty("--gc", g.color);
    $("gaugeCard").innerHTML =
      '<div class="card-title" style="justify-content:center;width:100%"><span class="tip" data-tip="A weighted count of findings (Critical 10, High 5, Medium 2, Low 1), capped at 100. It is a project-defined score, not a CVSS score. Unknown-severity findings are excluded.">Custom Project Risk Score (not CVSS)</span></div>' +
      '<div class="gauge"><svg viewBox="0 0 240 130"><path class="gauge-track" d="M20 120 A100 100 0 0 1 220 120"/>' +
      '<path class="gauge-fill" id="gaugeFill" d="M20 120 A100 100 0 0 1 220 120" stroke-dasharray="' + len + '" stroke-dashoffset="' + len + '"/></svg>' +
      '<div class="gauge-center"><div class="gauge-score">' + (insufficient ? "—" : Math.round(score)) + '</div></div></div>' +
      '<div class="gauge-grade"><span class="letter">' + esc(insufficient ? "?" : state.grade) + "</span>" + esc(insufficient ? "Insufficient coverage" : g.label) + "</div>" +
      '<div class="gauge-caption">' + (insufficient ? "No packages could be scanned, so this is not a clean result." : "Score reflects scanned packages only. See coverage below.") + "</div>";
    requestAnimationFrame(function () { requestAnimationFrame(function () {
      var f = $("gaugeFill"); if (f && !insufficient) f.style.strokeDashoffset = len * (1 - score / 100);
    }); });
  }

  function renderStats() {
    var total = Math.max(1, state.vulns.length);
    $("stats").innerHTML = SEVS.map(function (s) {
      var n = state.counts[s];
      return '<div class="card stat ' + (s === "Critical" && n > 0 ? "crit-glow" : "") + '" style="--c:' + SEV_VAR[s] + '">' +
        '<div class="stat-top"><span class="sev-glyph">' + SEV_GLYPH[s] + "</span>" + s + "</div>" +
        '<div class="stat-num">' + n + '</div><div class="stat-bar"><i data-w="' + Math.round((n / total) * 100) + '"></i></div></div>';
    }).join("");
    requestAnimationFrame(function () { document.querySelectorAll(".stat-bar i").forEach(function (i) { i.style.width = i.dataset.w + "%"; }); });
  }

  function renderCoverage() {
    var c = state.cov, t = Math.max(1, c.total);
    var warn = c.skipped > 0 || c.error > 0;
    function seg(n, col) { return '<i style="width:' + (n / t * 100) + "%;background:" + col + '"></i>'; }
    function item(n, label, col) { return '<span class="cov-item"><span class="cov-dot" style="background:' + col + '"></span><b>' + n + "</b> " + label + "</span>"; }
    $("coverage").innerHTML = '<div class="coverage ' + (warn ? "warn" : "") + '"><strong>Scan coverage</strong>' +
      '<div class="cov-bar">' + seg(c.scanned, "var(--grade-a)") + seg(c.skipped, "var(--sev-medium)") + seg(c.error, "var(--sev-critical)") + "</div>" +
      item(c.scanned, "scanned", "var(--grade-a)") + item(c.skipped, "skipped (range / unpinned)", "var(--sev-medium)") + item(c.error, "errors", "var(--sev-critical)") +
      "</div>" +
      (warn ? '<div class="faint" style="font-size:12px;margin-top:6px">Skipped and errored packages are <b>not</b> reflected in the score. Pin exact versions to include them.</div>' : "");
  }

  /* ------------------------------------------------------------------ *
   * Render: overview
   * ------------------------------------------------------------------ */
  function renderFixes() {
    var groups = {};
    state.vulns.forEach(function (v) {
      var k = v.pkg + "@" + v.version;
      var g = groups[k] || (groups[k] = { pkg: v.pkg, version: v.version, fixes: [], counts: { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 }, weight: 0, unfixed: 0 });
      g.counts[v.sev]++; g.weight += SEV_WEIGHT[v.sev];
      if (v.fixed) g.fixes.push(v.fixed); else g.unfixed++;
    });
    var list = Object.keys(groups).map(function (k) { return groups[k]; }).filter(function (g) { return g.fixes.length; })
      .sort(function (a, b) { return b.weight - a.weight; }).slice(0, 5);
    var box = $("fixList");
    if (!list.length) {
      box.innerHTML = '<div class="empty" style="padding:20px"><div class="big">✓</div><h3>' + (state.vulns.length ? "No upgrade paths available" : "No known vulnerabilities in " + state.cov.scanned + " scanned packages") +
        '</h3><div>' + (state.vulns.length ? "None of the findings list a fixed version yet." : "Skipped or errored packages are not covered by this result.") + "</div></div>";
      return;
    }
    box.innerHTML = list.map(function (g, i) {
      var target = maxVersion(g.fixes);
      var chips = SEVS.filter(function (s) { return g.counts[s]; }).map(function (s) {
        return '<span class="mini" style="--c:' + SEV_VAR[s] + '"><span class="sev-glyph" style="width:16px;height:16px;font-size:10px">' + SEV_GLYPH[s] + "</span>" + g.counts[s] + "</span>";
      }).join("");
      return '<div class="fix"><div class="fix-rank">' + (i + 1) + '</div><div class="fix-main"><div class="fix-title mono">' + esc(g.pkg) + " " + esc(g.version) +
        '<span class="fix-arrow">→</span>' + esc(target) + '</div><div class="fix-clears">' + chips +
        '<span class="faint" style="font-size:12px">cleared by upgrading</span></div></div>' +
        '<button class="btn sm" data-copy="' + esc(g.pkg + " " + target) + '">Copy</button></div>';
    }).join("");
  }
  function maxVersion(list) {
    function parts(v) { return String(v).split(/[.\-+]/).map(function (x) { var n = parseInt(x, 10); return isNaN(n) ? 0 : n; }); }
    return list.slice().sort(function (a, b) {
      var A = parts(a), B = parts(b);
      for (var i = 0; i < Math.max(A.length, B.length); i++) { var d = (B[i] || 0) - (A[i] || 0); if (d) return d; }
      return 0;
    })[0];
  }

  function renderDonut() {
    var total = state.vulns.length, R = 70, C = 2 * Math.PI * R, off = 0, arcs = "";
    if (!total) { $("donut").innerHTML = '<div class="empty" style="padding:20px"><div class="big">🛡</div><h3>Nothing to chart</h3><div>No vulnerabilities were found.</div></div>'; return; }
    SEVS.forEach(function (s) {
      var n = state.counts[s]; if (!n) return;
      var len = (n / total) * C;
      arcs += '<circle cx="85" cy="85" r="' + R + '" fill="none" stroke="' + SEV_VAR[s] + '" stroke-width="22" stroke-dasharray="' + len + " " + (C - len) + '" stroke-dashoffset="' + (-off) + '"/>';
      off += len;
    });
    $("donut").innerHTML = '<div class="donut-wrap"><div class="donut"><svg viewBox="0 0 170 170"><circle cx="85" cy="85" r="' + R + '" fill="none" stroke="var(--border)" stroke-width="22"/>' + arcs +
      '</svg><div class="donut-center"><div><b>' + total + "</b><span>findings</span></div></div></div>" +
      '<div class="legend">' + SEVS.map(function (s) { return '<div style="--c:' + SEV_VAR[s] + '"><i></i>' + s + "<b>" + state.counts[s] + "</b></div>"; }).join("") + "</div></div>";
  }

  function renderHbar() {
    var by = {};
    state.vulns.forEach(function (v) { var o = by[v.pkg] || (by[v.pkg] = { n: 0, c: { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 } }); o.n++; o.c[v.sev]++; });
    var rows = Object.keys(by).map(function (k) { return { name: k, o: by[k] }; }).sort(function (a, b) { return b.o.n - a.o.n; }).slice(0, 8);
    if (!rows.length) { $("hbar").innerHTML = '<div class="empty" style="padding:20px"><h3>No vulnerable packages</h3></div>'; return; }
    var max = rows[0].o.n;
    $("hbar").innerHTML = '<div class="hbar">' + rows.map(function (r) {
      return '<div class="hbar-row"><div class="hbar-name mono" title="' + esc(r.name) + '">' + esc(r.name) + '</div><div class="hbar-track" style="width:' + (r.o.n / max * 100) + '%">' +
        SEVS.map(function (s) { return r.o.c[s] ? '<i style="width:' + (r.o.c[s] / r.o.n * 100) + "%;background:" + SEV_VAR[s] + '"></i>' : ""; }).join("") +
        '</div><div class="hbar-val">' + r.o.n + "</div></div>";
    }).join("") + "</div>";
  }

  /* ------------------------------------------------------------------ *
   * Render: vulnerability table
   * ------------------------------------------------------------------ */
  var COLS = [
    ["sev", "Severity"], ["pkg", "Package"], ["version", "Version"], ["id", "Advisory"], ["cvss", "CVSS"], ["fixed", "Fixed in"]
  ];
  function renderFilters() {
    $("sevFilters").innerHTML = SEVS.map(function (s) {
      return '<button class="chip ' + (state.filter[s] ? "on" : "") + '" data-sev="' + s + '" style="--c:' + SEV_VAR[s] + '"><span class="dot"></span>' + s + " " + state.counts[s] + "</button>";
    }).join("");
  }
  function renderHead() {
    $("thead").innerHTML = COLS.map(function (c) {
      var arrow = state.sort.key === c[0] ? '<span class="arr">' + (state.sort.dir > 0 ? "▲" : "▼") + "</span>" : "";
      return '<th data-key="' + c[0] + '">' + c[1] + arrow + "</th>";
    }).join("");
  }
  function visibleRows() {
    var anyFilter = SEVS.some(function (s) { return state.filter[s]; }), q = state.query.toLowerCase();
    var rows = state.vulns.filter(function (v) {
      if (anyFilter && !state.filter[v.sev]) return false;
      if (q && (v.pkg + " " + v.id + " " + v.title + " " + v.desc).toLowerCase().indexOf(q) < 0) return false;
      return true;
    });
    var k = state.sort.key, d = state.sort.dir;
    rows.sort(function (a, b) {
      var x, y;
      if (k === "sev") { x = SEVS.indexOf(a.sev); y = SEVS.indexOf(b.sev); }
      else if (k === "cvss") { x = Number(a.cvss) || 0; y = Number(b.cvss) || 0; d = -state.sort.dir; }
      else { x = String(a[k] || "").toLowerCase(); y = String(b[k] || "").toLowerCase(); }
      return x < y ? -d : x > y ? d : 0;
    });
    return rows;
  }
  function renderTable() {
    var rows = visibleRows();
    $("rowCount").textContent = rows.length + " of " + state.vulns.length + " shown";
    if (!rows.length) {
      $("tbody").innerHTML = '<tr><td colspan="6"><div class="empty"><div class="big">' + (state.vulns.length ? "🔍" : "✓") + "</div><h3>" +
        (state.vulns.length ? "No results match your filters" : "No known vulnerabilities found") + "</h3><div>" +
        (state.vulns.length ? "Try clearing the search or severity filters." : "This only covers the " + state.cov.scanned + " package(s) that were scanned. Check the coverage bar above for skipped or errored items.") + "</div></div></td></tr>";
      return;
    }
    $("tbody").innerHTML = rows.map(function (v) {
      var key = v.pkg + "|" + v.version + "|" + v.id, open = state.open[key];
      var tr = '<tr class="vrow sev-' + v.sev.toLowerCase() + (open ? " open" : "") + '" style="--c:' + SEV_VAR[v.sev] + '" data-key="' + esc(key) + '">' +
        '<td data-label="Severity"><span class="sev-pill"><span class="sev-glyph">' + SEV_GLYPH[v.sev] + "</span>" + v.sev + "</span></td>" +
        '<td data-label="Package" class="mono">' + esc(v.pkg) + "</td>" +
        '<td data-label="Version" class="mono">' + esc(v.version) + "</td>" +
        '<td data-label="Advisory" class="mono">' + esc(v.id) + (v.title ? '<div class="dim" style="font-family:var(--font-ui);font-size:12px;margin-top:2px">' + esc(v.title.slice(0, 90)) + "</div>" : "") + "</td>" +
        '<td data-label="CVSS" class="mono">' + (v.cvss != null ? esc(v.cvss) : "—") + "</td>" +
        '<td data-label="Fixed in" class="mono">' + (v.fixed ? esc(v.fixed) : '<span class="faint">none listed</span>') + "</td></tr>";
      if (open) {
        tr += '<tr class="detail"><td colspan="6"><div class="detail-grid"><div><h4>Description</h4><p>' + esc(v.desc || v.title || "No description provided.") +
          "</p><h4>Recommendation</h4><p>" + esc(v.rec || (v.fixed ? "Upgrade " + v.pkg + " to " + v.fixed + " or later." : "No fixed version is listed. Monitor the advisory and consider an alternative package.")) +
          '</p></div><div><h4>CVSS vector</h4><p class="cvss-vec mono">' + (v.vector ? esc(v.vector) : "Not provided") + "</p><h4>Reference</h4><p>" +
          (/^(CVE|GHSA|PYSEC|OSV)/i.test(v.id) ? '<a href="https://osv.dev/vulnerability/' + encodeURIComponent(v.id) + '" target="_blank" rel="noopener noreferrer">' + esc(v.id) + " on osv.dev ↗</a>" : esc(v.id)) +
          "</p></div></div></td></tr>";
      }
      return tr;
    }).join("");
  }

  $("sevFilters").addEventListener("click", function (e) {
    var b = e.target.closest("[data-sev]"); if (!b) return;
    state.filter[b.dataset.sev] = !state.filter[b.dataset.sev]; renderFilters(); renderTable();
  });
  $("thead").addEventListener("click", function (e) {
    var th = e.target.closest("th"); if (!th) return;
    var k = th.dataset.key;
    state.sort = { key: k, dir: state.sort.key === k ? -state.sort.dir : 1 };
    renderHead(); renderTable();
  });
  $("tbody").addEventListener("click", function (e) {
    var tr = e.target.closest("tr.vrow"); if (!tr) return;
    var k = tr.dataset.key; state.open[k] = !state.open[k]; renderTable();
  });
  $("search").addEventListener("input", function (e) { state.query = e.target.value; renderTable(); });
  document.addEventListener("keydown", function (e) {
    var tag = (document.activeElement || {}).tagName;
    if (e.key === "/" && tag !== "INPUT" && tag !== "TEXTAREA") { e.preventDefault(); switchTab("vulns"); $("search").focus(); }
    if (e.key === "Escape" && document.activeElement === $("search")) { $("search").blur(); }
  });

  /* ------------------------------------------------------------------ *
   * Tabs
   * ------------------------------------------------------------------ */
  function switchTab(name) {
    document.querySelectorAll(".tab").forEach(function (t) { t.classList.toggle("on", t.dataset.tab === name); });
    ["overview", "vulns", "sbom"].forEach(function (n) { $("tab-" + n).classList.toggle("hidden", n !== name); });
    if (name === "sbom") loadSbom();
  }
  document.querySelector(".tabs").addEventListener("click", function (e) { var t = e.target.closest(".tab"); if (t) switchTab(t.dataset.tab); });

  /* ------------------------------------------------------------------ *
   * SBOM explorer
   * ------------------------------------------------------------------ */
  function loadSbom() {
    if (state.sbom || state.scanId == null) { if (state.sbom) renderSbom(); return; }
    $("sbomList").innerHTML = '<div class="skel" style="height:60px"></div><div class="skel" style="height:60px"></div><div class="skel" style="height:60px"></div>';
    api("/api/scan/" + encodeURIComponent(state.scanId) + "/sbom").then(function (data) {
      state.sbom = typeof data === "string" ? JSON.parse(data) : data;
      renderSbom();
    }).catch(function (e) { $("sbomList").innerHTML = '<div class="empty"><h3>Could not load SBOM</h3><div>' + esc(e.message) + "</div></div>"; });
  }
  function renderSbom() {
    var comps = (state.sbom && state.sbom.components) || [];
    $("compCount").textContent = comps.length;
    if (!comps.length) { $("sbomList").innerHTML = '<div class="empty"><h3>No components</h3></div>'; }
    else $("sbomList").innerHTML = comps.map(function (c) {
      var spec = ((c.properties || []).filter(function (p) { return p.name === "originalVersionSpecifier"; })[0] || {}).value;
      var type = c.version ? "exact" : (spec ? (/^\s*$/.test(spec) ? "unpinned" : "range") : "unpinned");
      return '<div class="comp"><div class="mono" style="font-weight:600">' + esc(c.name) + '</div><div class="mono">' + esc(c.version || spec || "—") + "</div>" +
        '<div><span class="tag ' + type + '">' + type + '</span></div><div class="purl mono" title="' + esc(c.purl || "") + '">' + esc(c.purl || "no purl (version not exact)") + "</div>" +
        (c.purl ? '<button class="btn sm" data-copy="' + esc(c.purl) + '">Copy PURL</button>' : "<span></span>") + "</div>";
    }).join("");
    $("sbomJson").innerHTML = highlight(JSON.stringify(state.sbom, null, 2));
  }
  function highlight(json) {
    return esc(json).replace(/(&quot;(?:\\.|[^\\&])*?&quot;)(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+\-]?\d+)?/g, function (m, str, colon, bool) {
      if (str) return colon ? '<span class="j-key">' + str + "</span>" + colon : '<span class="j-str">' + str + "</span>";
      if (bool) return '<span class="j-bool">' + m + "</span>";
      return '<span class="j-num">' + m + "</span>";
    });
  }
  $("sbomListBtn").onclick = function () { $("sbomListBtn").classList.add("on"); $("sbomJsonBtn").classList.remove("on"); $("sbomList").classList.remove("hidden"); $("sbomJson").classList.add("hidden"); };
  $("sbomJsonBtn").onclick = function () { $("sbomJsonBtn").classList.add("on"); $("sbomListBtn").classList.remove("on"); $("sbomJson").classList.remove("hidden"); $("sbomList").classList.add("hidden"); };
  $("sbomDownload").onclick = function () {
    if (!state.sbom) return toast("SBOM not loaded yet", "error");
    var a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(state.sbom, null, 2)], { type: "application/json" }));
    a.download = "sbom-" + state.scanId + ".cdx.json"; a.click(); URL.revokeObjectURL(a.href);
    toast("CycloneDX SBOM downloaded", "ok");
  };

  /* ------------------------------------------------------------------ *
   * Copy, export toasts, delete
   * ------------------------------------------------------------------ */
  document.addEventListener("click", function (e) {
    var b = e.target.closest("[data-copy]"); if (!b) return;
    var text = b.dataset.copy;
    (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(function () { toast("Copied to clipboard", "ok"); })
      .catch(function () { toast("Copy failed. Select the text manually.", "error"); });
  });
  $("exportPdf").addEventListener("click", function () { toast("Preparing PDF report…"); });
  $("exportCsv").addEventListener("click", function () { toast("Preparing CSV report…"); });

  var dlg = $("confirmDlg");
  $("deleteBtn").onclick = function () { dlg.showModal(); };
  $("dlgCancel").onclick = function () { dlg.close(); };
  $("dlgOk").onclick = function () {
    dlg.close();
    api("/api/scan/" + encodeURIComponent(state.scanId), { method: "DELETE" }).then(function () {
      toast("Scan deleted", "ok"); state.scanId = null; location.hash = "analyzer"; show("viewUpload"); loadHistory();
    }).catch(function (e) { toast(e.message, "error"); });
  };

  /* ------------------------------------------------------------------ *
   * Boot
   * ------------------------------------------------------------------ */
  show("viewUpload");
  loadHistory().then(function () {
    var m = /scan=(\d+)/.exec(location.hash);
    if (m) openScan(m[1]);
  });
})();
