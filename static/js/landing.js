/* Landing screen: routing between the landing page and the analyzer, nav state, health status.
   Loaded after dashboard.js. Does not touch any backend API except the existing GET /health. */
(function () {
  "use strict";

  var body = document.body;
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var $ = function (id) { return document.getElementById(id); };
  var nav = $("lNav"), menuBtn = $("lMenuBtn");

  /* ---------------- Routing (hash based, no backend changes) ----------------
     #home / #features / #about -> landing        #history -> analyzer + history
     #analyzer / #scan=ID       -> analyzer       (empty) -> landing            */
  function parse() {
    var h = ""; try { h = decodeURIComponent((location.hash || "").replace(/^#\/?/, "")); } catch (e) { h = ""; }
    return h;
  }
  function isAppRoute(h) { return h === "analyzer" || h === "history" || /^scan=\d+/.test(h); }

  function scrollToId(id) {
    var el = $(id); if (!el) return;
    el.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
  }

  function revealHistory() {
    var sb = $("sidebar"), hist = $("history");
    if (sb) sb.classList.remove("collapsed");
    if (hist) {
      hist.classList.remove("flash-ring"); void hist.offsetWidth; hist.classList.add("flash-ring");
      var first = hist.querySelector(".hist-item"); if (first) first.focus({ preventScroll: true });
    }
  }

  var lastMode = null;
  function route() {
    var h = parse(), app = isAppRoute(h), changed = lastMode !== app;
    lastMode = app;
    body.classList.toggle("mode-app", app);
    body.classList.toggle("mode-landing", !app);
    document.title = app ? "SBOM Analyzer — Dashboard" : "SBOM & Dependency Risk Analyzer";
    closeMenu();

    if (app) {
      if (changed) window.scrollTo(0, 0);
      if (h === "history") revealHistory();
      return;
    }
    if (h === "features" || h === "about") { scrollToId(h); }
    else if (changed || h === "home" || h === "") { window.scrollTo({ top: 0, behavior: reduce || changed ? "auto" : "smooth" }); }
    setActive(h === "features" || h === "about" ? h : "home");
  }
  window.addEventListener("hashchange", route);

  /* ---------------- Nav: active link + scroll spy ---------------- */
  function setActive(key) {
    var links = nav ? nav.querySelectorAll("a[data-spy]") : [];
    Array.prototype.forEach.call(links, function (a) {
      var on = a.getAttribute("data-spy") === key;
      a.classList.toggle("active", on);
      if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    });
  }
  if ("IntersectionObserver" in window) {
    var spy = new IntersectionObserver(function (entries) {
      if (body.classList.contains("mode-app")) return;
      entries.forEach(function (e) { if (e.isIntersecting) setActive(e.target.getAttribute("data-key")); });
    }, { rootMargin: "-40% 0px -55% 0px" });
    [["lTitle", "home"], ["features", "features"], ["about", "about"]].forEach(function (p) {
      var el = $(p[0]); if (!el) return;
      var host = p[0] === "lTitle" ? el.closest("section") : el;
      host.setAttribute("data-key", p[1]); spy.observe(host);
    });
  }

  /* ---------------- Mobile menu ---------------- */
  function closeMenu() { if (nav) nav.classList.remove("open"); if (menuBtn) menuBtn.setAttribute("aria-expanded", "false"); }
  if (menuBtn) menuBtn.addEventListener("click", function () {
    var open = nav.classList.toggle("open"); menuBtn.setAttribute("aria-expanded", open ? "true" : "false");
  });
  if (nav) nav.addEventListener("click", function (e) { if (e.target.closest("a")) closeMenu(); });

  /* ---------------- Real backend status (existing GET /health) ---------------- */
  (function status() {
    var el = $("lStatus"); if (!el) return;
    var label = el.querySelector("span");
    function set(state, text) { el.setAttribute("data-state", state); label.textContent = text; }
    var ctrl = window.AbortController ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctrl) ctrl.abort(); }, 4000);
    fetch("/health", { cache: "no-store", signal: ctrl ? ctrl.signal : undefined })
      .then(function (r) { clearTimeout(timer); r.ok ? set("ok", "Secure • Ready") : set("offline", "Backend unavailable"); })
      .catch(function () { clearTimeout(timer); set("offline", "Backend offline"); });
  })();

  /* ---------------- Ambient particles (skipped for reduced motion) ---------------- */
  (function dots() {
    var host = $("lDots"); if (!host || reduce) return;
    var colors = ["#22e6f0", "#4f8cff", "#8b5cf6", "#ff4fd8"], n = window.innerWidth < 700 ? 14 : 30;
    for (var i = 0; i < n; i++) {
      var s = document.createElement("span"), size = 2 + Math.random() * 3;
      s.style.cssText = "left:" + (Math.random() * 100).toFixed(1) + "%;top:" + (Math.random() * 100).toFixed(1) + "%;--s:" + size.toFixed(1) +
        "px;--c:" + colors[i % colors.length] + ";--t:" + (5 + Math.random() * 6).toFixed(1) + "s;--d:-" + (Math.random() * 8).toFixed(1) + "s";
      host.appendChild(s);
    }
  })();

  route();
})();
