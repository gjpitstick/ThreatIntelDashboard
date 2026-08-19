// CTI Dashboard front-end. No build step, no framework -- vanilla fetch + DOM.
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const state = {
    vulnFilters: { search: "", severity: "", kevOnly: false },
    newsFilters: { search: "", category: "" },
    iocFilters: { search: "", type: "" },
  };

  const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
  const SEVERITY_COLOR_VAR = {
    CRITICAL: "--status-critical",
    HIGH: "--status-serious",
    MEDIUM: "--status-warning",
    LOW: "--status-good",
    UNKNOWN: "--status-unknown",
  };
  const CATEGORICAL_VARS = ["--series-1", "--series-2", "--series-3", "--series-4", "--series-5", "--series-6", "--series-7", "--series-8"];

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function fmtDate(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (isNaN(d)) return "—";
    return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  }

  function fmtDateTime(iso) {
    if (!iso) return "never";
    const d = new Date(iso);
    if (isNaN(d)) return "never";
    return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  function escapeHtml(str) {
    if (str == null) return "";
    return String(str).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  async function fetchJSON(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`${url} -> ${res.status}`);
    return res.json();
  }

  // ---------------- Theme ----------------
  function initTheme() {
    const saved = document.documentElement.getAttribute("data-theme") || "dark";
    document.documentElement.setAttribute("data-theme", saved);
    $("#theme-toggle").addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme");
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      // Re-render charts so they pick up the new CSS variable values.
      loadSummary();
    });
  }

  // ---------------- Tabs ----------------
  function initTabs() {
    $$(".tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        $$(".tab").forEach((t) => { t.classList.remove("active"); t.setAttribute("aria-selected", "false"); });
        tab.classList.add("active");
        tab.setAttribute("aria-selected", "true");
        const target = tab.dataset.tab;
        $$(".panel").forEach((p) => p.classList.add("hidden"));
        $(`#panel-${target}`).classList.remove("hidden");
      });
    });
  }

  // ---------------- Table-view toggles (chart accessibility twin) ----------------
  function initTableToggles() {
    $$(".table-toggle").forEach((btn) => {
      btn.addEventListener("click", () => {
        const target = $("#" + btn.dataset.target);
        const chartBody = btn.closest(".chart-card").querySelector(".chart-body");
        const showingTable = !target.classList.contains("hidden");
        target.classList.toggle("hidden");
        chartBody.classList.toggle("hidden", !showingTable);
        btn.textContent = showingTable ? "Table view" : "Chart view";
      });
    });
  }

  // ---------------- Stat tiles ----------------
  function renderStatTiles(summary) {
    const tiles = [
      { label: "Total vulnerabilities", value: summary.total_vulnerabilities },
      { label: "CISA KEV", value: summary.kev_count, cls: summary.kev_count > 0 ? "critical" : "" },
      { label: "Critical CVEs", value: summary.critical_count, cls: summary.critical_count > 0 ? "critical" : "" },
      { label: "New CVEs (7d)", value: summary.new_vulns_7d },
      { label: "Breach stories (7d)", value: summary.breach_count_7d, cls: summary.breach_count_7d > 0 ? "warning" : "" },
      { label: "Campaign stories (7d)", value: summary.campaign_count_7d },
      { label: "Total IOCs", value: summary.total_iocs },
      { label: "IOCs (24h)", value: summary.iocs_24h },
    ];
    $("#stat-grid").innerHTML = tiles.map((t) => `
      <div class="stat-tile">
        <div class="label">${escapeHtml(t.label)}</div>
        <div class="value ${t.cls || ""}">${t.value.toLocaleString()}</div>
      </div>`).join("");
  }

  // ---------------- Source status pills ----------------
  function renderSourceStatus(sources) {
    const labelMap = { nvd: "NVD", cisa_kev: "CISA KEV", news: "News", iocs: "IOCs" };
    $("#source-status").innerHTML = sources.map((s) => `
      <span class="source-pill" title="${escapeHtml(s.message || s.status)}">
        <span class="dot dot-${s.status}"></span>
        ${labelMap[s.source] || s.source}: ${fmtDateTime(s.finished_at)}
      </span>`).join("");
  }

  // ---------------- Severity bar chart (status palette) ----------------
  function renderSeverityChart(breakdown) {
    const max = Math.max(1, ...Object.values(breakdown));
    const rows = SEVERITY_ORDER.filter((k) => breakdown[k]).map((sev) => {
      const count = breakdown[sev] || 0;
      const pct = (count / max) * 100;
      const color = cssVar(SEVERITY_COLOR_VAR[sev]);
      return `<div class="bar-row">
        <div class="bar-label">${sev}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${color}"></div></div>
        <div class="bar-value">${count}</div>
      </div>`;
    });
    $("#severity-chart").innerHTML = rows.join("") || `<p class="empty-state">No vulnerability data yet.</p>`;

    const tbody = $("#severity-table tbody");
    tbody.innerHTML = SEVERITY_ORDER.filter((k) => breakdown[k]).map((sev) =>
      `<tr><td>${sev}</td><td>${breakdown[sev]}</td></tr>`).join("");
  }

  // ---------------- IOC type bar chart (categorical palette) ----------------
  function renderIocTypeChart(breakdown) {
    const entries = Object.entries(breakdown).sort((a, b) => b[1] - a[1]);
    const top = entries.slice(0, 8);
    const other = entries.slice(8).reduce((sum, [, v]) => sum + v, 0);
    if (other > 0) top.push(["other", other]);
    const max = Math.max(1, ...top.map(([, v]) => v));

    const rows = top.map(([type, count], i) => {
      const pct = (count / max) * 100;
      const color = i < CATEGORICAL_VARS.length ? cssVar(CATEGORICAL_VARS[i]) : cssVar("--text-muted");
      return `<div class="bar-row">
        <div class="bar-label">${escapeHtml(type)}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${color}"></div></div>
        <div class="bar-value">${count}</div>
      </div>`;
    });
    $("#ioc-type-chart").innerHTML = rows.join("") || `<p class="empty-state">No IOC data yet. Set ABUSECH_API_KEY to enable.</p>`;

    const tbody = $("#ioc-table-chart tbody");
    tbody.innerHTML = top.map(([type, count]) => `<tr><td>${escapeHtml(type)}</td><td>${count}</td></tr>`).join("");
  }

  // ---------------- Trend line chart (sequential blue, hover tooltip) ----------------
  function renderTrendChart(trend) {
    const container = $("#trend-chart");
    const tbody = $("#trend-table tbody");
    tbody.innerHTML = trend.map((d) => `<tr><td>${d.date}</td><td>${d.count}</td></tr>`).join("");

    if (!trend.length) {
      container.innerHTML = `<p class="empty-state">No trend data yet.</p>`;
      return;
    }

    const width = container.clientWidth || 320;
    const height = 140;
    const padding = { top: 10, right: 10, bottom: 20, left: 10 };
    const plotW = width - padding.left - padding.right;
    const plotH = height - padding.top - padding.bottom;

    const maxCount = Math.max(1, ...trend.map((d) => d.count));
    const stepX = trend.length > 1 ? plotW / (trend.length - 1) : 0;

    const points = trend.map((d, i) => {
      const x = padding.left + i * stepX;
      const y = padding.top + plotH - (d.count / maxCount) * plotH;
      return { x, y, ...d };
    });

    const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");
    const areaPath = `${linePath} L${points[points.length - 1].x.toFixed(1)},${padding.top + plotH} L${points[0].x.toFixed(1)},${padding.top + plotH} Z`;

    const gridY = padding.top + plotH;

    const svg = `
      <svg class="line-chart-svg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="New vulnerabilities per day, last 14 days">
        <line class="gridline" x1="${padding.left}" y1="${gridY}" x2="${width - padding.right}" y2="${gridY}" />
        <path class="line-area" d="${areaPath}"></path>
        <path class="line-path" d="${linePath}"></path>
        ${points.map((p) => `<circle class="line-dot" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="3" data-date="${p.date}" data-count="${p.count}"></circle>`).join("")}
      </svg>`;
    container.innerHTML = svg;

    const tooltip = $("#tooltip");
    $$("circle", container).forEach((circle) => {
      circle.addEventListener("mouseenter", (e) => {
        tooltip.textContent = `${circle.dataset.date}: ${circle.dataset.count} new CVE${circle.dataset.count === "1" ? "" : "s"}`;
        tooltip.classList.remove("hidden");
      });
      circle.addEventListener("mousemove", (e) => {
        tooltip.style.left = `${e.clientX + 12}px`;
        tooltip.style.top = `${e.clientY + 12}px`;
      });
      circle.addEventListener("mouseleave", () => tooltip.classList.add("hidden"));
    });
  }

  // ---------------- Summary ----------------
  async function loadSummary() {
    try {
      const summary = await fetchJSON("/api/summary");
      renderStatTiles(summary);
      renderSourceStatus(summary.sources);
      renderSeverityChart(summary.severity_breakdown);
      renderIocTypeChart(summary.ioc_type_breakdown);
      renderTrendChart(summary.daily_vuln_trend);
      populateIocTypeFilter(summary.ioc_type_breakdown);
    } catch (err) {
      console.error("Failed to load summary", err);
    }
  }

  function populateIocTypeFilter(breakdown) {
    const select = $("#ioc-type");
    const existing = new Set(Array.from(select.options).map((o) => o.value));
    Object.keys(breakdown).forEach((type) => {
      if (!existing.has(type)) {
        const opt = document.createElement("option");
        opt.value = type;
        opt.textContent = type;
        select.appendChild(opt);
      }
    });
  }

  // ---------------- Vulnerabilities table ----------------
  function severityBadge(sev) {
    const cls = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" }[sev] || "unknown";
    return `<span class="badge badge-${cls}">${sev}</span>`;
  }

  async function loadVulns() {
    const { search, severity, kevOnly } = state.vulnFilters;
    const params = new URLSearchParams({ limit: "200" });
    if (search) params.set("search", search);
    if (severity) params.set("severity", severity);
    if (kevOnly) params.set("kev_only", "true");

    try {
      const rows = await fetchJSON(`/api/vulnerabilities?${params.toString()}`);
      const tbody = $("#vuln-table tbody");
      $("#vuln-empty").classList.toggle("hidden", rows.length > 0);
      tbody.innerHTML = rows.map((v) => `
        <tr>
          <td class="cve-cell"><a href="${escapeHtml(v.source_url)}" target="_blank" rel="noopener">${escapeHtml(v.cve_id)}</a></td>
          <td>${severityBadge(v.cvss_severity)}</td>
          <td>${v.cvss_score != null ? v.cvss_score.toFixed(1) : "—"}</td>
          <td>${v.is_kev ? `<span class="badge badge-kev" title="${escapeHtml(v.kev_required_action)}">KEV</span>` : ""}</td>
          <td>${fmtDate(v.published_date)}</td>
          <td>${escapeHtml(v.vendor_products) || "—"}</td>
          <td class="desc-cell">${escapeHtml((v.description || "").slice(0, 220))}${(v.description || "").length > 220 ? "…" : ""}</td>
        </tr>`).join("");
    } catch (err) {
      console.error("Failed to load vulnerabilities", err);
    }
  }

  // ---------------- News list ----------------
  async function loadNews() {
    const { search, category } = state.newsFilters;
    const params = new URLSearchParams({ limit: "100" });
    if (search) params.set("search", search);
    if (category) params.set("category", category);

    try {
      const rows = await fetchJSON(`/api/news?${params.toString()}`);
      const list = $("#news-list");
      $("#news-empty").classList.toggle("hidden", rows.length > 0);
      list.innerHTML = rows.map((n) => `
        <article class="news-card">
          <div class="news-card-head">
            <span class="cat-badge cat-${n.category}">${n.category}</span>
            <span class="news-source">${escapeHtml(n.source)}</span>
            <span class="news-date">${fmtDate(n.published_date)}</span>
          </div>
          <h3 class="news-title"><a href="${escapeHtml(n.link)}" target="_blank" rel="noopener">${escapeHtml(n.title)}</a></h3>
          <p class="news-summary">${escapeHtml((n.summary || "").slice(0, 280))}${(n.summary || "").length > 280 ? "…" : ""}</p>
          ${n.cve_refs ? `<div class="news-cves">Mentions: ${n.cve_refs.split(", ").map((c) => `<code>${escapeHtml(c)}</code>`).join(" ")}</div>` : ""}
        </article>`).join("");
    } catch (err) {
      console.error("Failed to load news", err);
    }
  }

  // ---------------- IOC table ----------------
  async function loadIocs() {
    const { search, type } = state.iocFilters;
    const params = new URLSearchParams({ limit: "300" });
    if (search) params.set("search", search);
    if (type) params.set("ioc_type", type);

    try {
      const rows = await fetchJSON(`/api/iocs?${params.toString()}`);
      const tbody = $("#ioc-table tbody");
      $("#ioc-empty").classList.toggle("hidden", rows.length > 0);
      tbody.innerHTML = rows.map((i) => `
        <tr>
          <td>${escapeHtml(i.ioc_type)}</td>
          <td style="max-width:280px;word-break:break-all;">${escapeHtml(i.ioc_value)}</td>
          <td>${escapeHtml(i.malware) || "—"}</td>
          <td>${escapeHtml(i.threat_type) || "—"}</td>
          <td>${i.confidence_level != null ? i.confidence_level + "%" : "—"}</td>
          <td>${fmtDate(i.first_seen)}</td>
          <td>${escapeHtml(i.source)}</td>
        </tr>`).join("");
    } catch (err) {
      console.error("Failed to load IOCs", err);
    }
  }

  // ---------------- Filters wiring ----------------
  function debounce(fn, ms) {
    let t;
    return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
  }

  function initFilters() {
    const vulnSearch = debounce(() => { state.vulnFilters.search = $("#vuln-search").value; loadVulns(); }, 300);
    $("#vuln-search").addEventListener("input", vulnSearch);
    $("#vuln-severity").addEventListener("change", (e) => { state.vulnFilters.severity = e.target.value; loadVulns(); });
    $("#vuln-kev-only").addEventListener("change", (e) => { state.vulnFilters.kevOnly = e.target.checked; loadVulns(); });

    const newsSearch = debounce(() => { state.newsFilters.search = $("#news-search").value; loadNews(); }, 300);
    $("#news-search").addEventListener("input", newsSearch);
    $("#news-category").addEventListener("change", (e) => { state.newsFilters.category = e.target.value; loadNews(); });

    const iocSearch = debounce(() => { state.iocFilters.search = $("#ioc-search").value; loadIocs(); }, 300);
    $("#ioc-search").addEventListener("input", iocSearch);
    $("#ioc-type").addEventListener("change", (e) => { state.iocFilters.type = e.target.value; loadIocs(); });
  }

  // ---------------- Init ----------------
  function init() {
    initTheme();
    initTabs();
    initTableToggles();
    initFilters();
    loadSummary();
    loadVulns();
    loadNews();
    loadIocs();

    // Refresh view data periodically (cheap DB reads) so a page left open
    // stays current as the background scheduler ingests new data.
    setInterval(() => { loadSummary(); loadVulns(); loadNews(); loadIocs(); }, 5 * 60 * 1000);
    window.addEventListener("resize", debounce(() => loadSummary(), 400));
  }

  document.addEventListener("DOMContentLoaded", init);
})();
