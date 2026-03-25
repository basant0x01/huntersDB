// ── State ─────────────────────────────────────────────────────────────────────
let currentView = "dashboard";
let currentProjectId = null;
let currentSubPage = 1;
let selectedProjects = new Set();
let projSortField = "created_at";
let projSortOrder = "desc";
let currentProjPage = 1;
let logCursor = 0;
let miniLogCursor = 0;
let liveLogTimer = null;
let syncPollTimer = null;
let dashPollTimer = null;
let serverPollTimer = null;
let serverLogCursor = 0;
let serverLogAll = [];
let miniLogBuf = [];
let MINI_LOG_MAX = 50;
let maxConcurrentScans = 10;
let techSearchTimer = null;
let nucleiPollTimer = null;
let _lastVulnCount = -1;

// ── Platform live poll state ──────────────────────────────────────────────────
let h1LiveTimer = null; let _h1WasRunning = false; let _h1LastProgHash = "";
let ywhLiveTimer = null; let _ywhWasRunning = false;

// JS-04 FIX: Global handler for unhandled promise rejections
window.addEventListener('unhandledrejection', (event) => {
  console.warn('Unhandled fetch/promise rejection:', event.reason);
  // Note: NOT calling preventDefault() so errors still appear in devtools
});

// ── Router ────────────────────────────────────────────────────────────────────
function showView(view, id) {
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.querySelectorAll(".nav-link").forEach(l => {
    l.classList.toggle("active", l.dataset.view === view);
  });
  const titles = {
    dashboard:"Dashboard", projects:"Projects", chaos:"Chaos Sync",
    bbscope:"HackerOne Private", yeswehack:"YesWeHack Private",
    search:"Global Search", nuclei:"Nuclei Scanner", server:"Server Control",
    logs:"Live Logs", settings:"Settings", projectDetail:"Project Detail",
    monitor:"24/7 Monitor", alerts:"Alerts", review:"Bug Review Queue"
  };
  document.getElementById("pageTitle").textContent = titles[view] || view;
  currentView = view;

  if (view === "projectDetail" && id) {
    currentProjectId = id;
    document.getElementById("projectDetailView").classList.add("active");
    loadProjectDetail(id);
  } else {
    const el = document.getElementById(view + "View");
    if (el) el.classList.add("active");
  }

  // Stop ALL polls FIRST before starting the new view's polls (prevents timer leaks)
  stopSyncPoll();
  stopLiveMode();
  stopDashPoll();
  stopH1LivePoll();
  stopYWHLivePoll();
  stopProjectsLivePoll();
  stopServerPoll();
  stopNucleiPoll();
  if (typeof stopMonitorPoll==="function") stopMonitorPoll();

  if (view === "dashboard")   { loadDashboard(); startDashPoll(); }
  if (view === "projects")    { loadPlatformFilter(); loadProjects(); startProjectsLivePoll(); }
  if (view === "chaos")       { loadChaosPlatforms(); loadSyncStatus(); loadSyncHistory(); startSyncPoll(); }
  if (view === "bbscope")     { loadBBScopeView(); loadBBScopeHistory(); loadBBScopeProjects(); startH1LivePoll(); }
  if (view === "yeswehack")   { loadYWHView(); loadYWHHistory(); loadYWHProjects(); startYWHLivePoll(); }
  if (view === "nuclei")      { loadNucleiProjects(); loadVulns(); _loadVulnBreakdown(); startNucleiPoll(); }
  if (view === "server")      { loadServerStatus(); startServerPoll(); }
  if (view === "logs")        { loadLogs(); startLiveMode(); }
  if (view === "settings")    loadSettings();
  // Beast Mode views
  if (view === "monitor")     { if (typeof loadMonitorStatus==="function") { loadMonitorStatus(); startMonitorPoll(); } }
  if (view === "alerts")      { if (typeof loadAlerts==="function") loadAlerts(); }
  if (view === "review")      { if (typeof loadReviewQueue==="function") loadReviewQueue(); }
}

document.querySelectorAll(".nav-link[data-view]").forEach(l => {
  l.addEventListener("click", () => showView(l.dataset.view));
});

// ── Fetch wrapper with auth redirect, timeout, and retry ──
const _fetchRetryCount = new Map();
async function apiFetch(url, options={}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeout || 30000);
  try {
    const r = await fetch(url, {...options, signal: controller.signal});
    if (r.status === 401) {
      const d = await r.json().catch(()=>({}));
      if (d.login_required) { window.location.href = "/login"; return null; }
    }
    _fetchRetryCount.delete(url);
    return r;
  } catch(e) {
    if (e.name === "AbortError") {
      console.warn(`Request timeout: ${url}`);
      return null;
    }
    throw e;
  } finally {
    clearTimeout(timeout);
  }
}

// ── Utils ─────────────────────────────────────────────────────────────────────

// ── Project detail tab switching ─────────────────────────────────────────────
function switchDetailTab(tab, btn) {
  document.querySelectorAll("#projectDetailView .tab-content").forEach(el => {
    el.style.display = "none"; el.classList.remove("active");
  });
  document.querySelectorAll("#projectDetailView .tab-bar .tab").forEach(el => el.classList.remove("active"));
  const target = document.getElementById("tab-" + tab);
  if (target) { target.style.display = "block"; target.classList.add("active"); }
  if (btn) btn.classList.add("active");
  if (tab === "subdomains" && currentProjectId) loadSubs();
  if (tab === "vulns"      && currentProjectId) loadProjectVulns();
  if (tab === "leaks"      && currentProjectId) loadLeakTab();
  if (tab === "garbage"    && currentProjectId) loadGarbageTab();
  if (tab === "recon"      && currentProjectId) loadReconTab();
}

async function loadProjectVulns() {
  if (!currentProjectId) return;
  const data = await fetch(`/api/projects/${currentProjectId}/vulnerabilities`).then(r=>r.json());
  const tbody = document.getElementById("detailVulnBody");
  if (!tbody) return;
  tbody.innerHTML = (data||[]).length
    ? data.map(v=>`<tr>
        <td>${sevBadge(v.severity)}</td>
        <td style="font-weight:500">${esc(v.name)||"—"}</td>
        <td class="mono text-xs">${esc(v.template_id)||"—"}</td>
        <td><span class="badge badge-default">${esc(v.type)||"—"}</span></td>
        <td><a href="${esc(v.matched_at||v.url)}" target="_blank" class="cell-link">${esc((v.matched_at||v.url||"—").slice(0,80))}</a></td>
        <td class="text-xs text-dim">${fmtTs(v.created_at)}</td>
      </tr>`).join("")
    : `<tr><td colspan="6" class="empty">No vulnerabilities found for this project</td></tr>`;
}

// ════════════════════════════════════════════════════════════════════════════════
// LEAK INTELLIGENCE TAB
// ════════════════════════════════════════════════════════════════════════════════

let _leakRows = [];

async function loadLeakTab() {
  if (!currentProjectId) return;
  const tbody = document.getElementById("leakTbody");
  if (tbody) tbody.innerHTML = `<tr><td colspan="9" class="empty"><span class="spin">⟳</span> Loading leak data…</td></tr>`;
  try {
    const [lr, sr] = await Promise.all([
      fetch(`/api/projects/${currentProjectId}/leak-intel?per_page=500`).then(r => r.ok ? r.json() : {results:[]}),
      fetch(`/api/projects/${currentProjectId}/subdomains?alive_only=true&per_page=1000`).then(r => r.ok ? r.json() : {subdomains:[]}),
    ]);
    const leakMap = {};
    for (const l of (lr.results || [])) leakMap[l.subdomain] = l;
    _leakRows = (sr.subdomains || []).map(s => ({ subdomain: s.subdomain, leak: leakMap[s.subdomain] || null }));
    for (const [sub, lk] of Object.entries(leakMap)) {
      if (!_leakRows.find(r => r.subdomain === sub)) _leakRows.push({ subdomain: sub, leak: lk });
    }
    const comp    = _leakRows.filter(r => r.leak?.compromised).length;
    const records = _leakRows.reduce((a, r) => a + (r.leak?.total_records || 0), 0);
    const checked = _leakRows.filter(r => r.leak?.checked_at).length;
    const el_ = id => document.getElementById(id);
    if (el_("lk-total"))   el_("lk-total").textContent   = checked;
    if (el_("lk-comp"))    el_("lk-comp").textContent    = comp;
    if (el_("lk-records")) el_("lk-records").textContent = records > 0 ? fmt(records) : "—";
    const badge = el_("dtab-leaks-cnt");
    if (badge) { badge.textContent = comp; badge.style.display = comp > 0 ? "inline" : "none"; }
    filterLeakTable();
  } catch(e) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="9" class="empty">Error: ${esc(e.message)}</td></tr>`;
  }
}

function filterLeakTable() {
  const q    = (document.getElementById("leakSearch")?.value || "").toLowerCase();
  const comp = document.getElementById("leakCompOnly")?.checked;
  const tbody = document.getElementById("leakTbody");
  if (!tbody) return;
  let rows = _leakRows;
  if (q)    rows = rows.filter(r => r.subdomain.toLowerCase().includes(q));
  if (comp) rows = rows.filter(r => r.leak?.compromised);
  const cnt = document.getElementById("leakRowCount");
  if (cnt) cnt.textContent = rows.length + " subdomains";
  if (!rows.length) { tbody.innerHTML = `<tr><td colspan="9" class="empty">No results</td></tr>`; return; }
  tbody.innerHTML = rows.map(r => {
    const lk = r.leak || {};
    const sources = Array.isArray(lk.sources) ? lk.sources : [];
    const records = lk.total_records || 0;
    return `<tr onclick="openLeakDetail('${esc(r.subdomain)}')" style="cursor:pointer" class="${lk.compromised ? 'row-danger' : ''}">
      <td style="font-family:var(--mono);font-size:11px">${esc(r.subdomain)}</td>
      <td>${lk.compromised
        ? '<span class="badge badge-danger">🔴 COMPROMISED</span>'
        : lk.checked_at ? '<span class="badge badge-success">✓ CLEAN</span>'
        : '<span style="color:var(--text-muted);font-size:10px">—</span>'}</td>
      <td style="font-size:10px">${sources.map(s => `<span class="badge badge-default" style="margin-right:2px">${esc(s)}</span>`).join("")}</td>
      <td>${lk.emails?.length > 0 ? `<span style="color:var(--orange,#f97316)">${lk.emails.length}</span>` : "—"}</td>
      <td>${lk.passwords?.length > 0 ? `<span style="color:var(--red,#ef4444);font-weight:700">${lk.passwords.length}</span>` : "—"}</td>
      <td>${records > 0 ? fmt(records) : "—"}</td>
      <td style="font-size:10px;color:var(--text-muted)">${lk.first_seen || "—"}</td>
      <td style="font-size:10px;color:var(--text-muted)">${lk.last_seen  || "—"}</td>
      <td><button class="btn btn-xs btn-ghost" onclick="event.stopPropagation();runSingleLeakCheck('${esc(r.subdomain)}')" title="Re-check">↻</button></td>
    </tr>`;
  }).join("");
}

async function openLeakDetail(sub) {
  const card = document.getElementById("leakDetailCard");
  if (!card) return;
  card.style.display = "block";
  const subEl = document.getElementById("leakDetailSub");
  if (subEl) subEl.textContent = sub;
  const ids = ["leakDetailEmails","leakDetailPasswords","leakDetailSources","leakDetailTimeline","leakDetailGithub"];
  ids.forEach(id => { const el = document.getElementById(id); if(el) el.innerHTML = '<span style="color:var(--text-muted)">Loading…</span>'; });
  try {
    const d = await fetch(`/api/projects/${currentProjectId}/leak-intel/${encodeURIComponent(sub)}`).then(r => r.ok ? r.json() : null);
    if (!d) { document.getElementById("leakDetailEmails").innerHTML = '<span style="color:var(--text-muted)">No data found</span>'; return; }
    const el_ = id => document.getElementById(id);
    const emails = d.emails || [];
    if (el_("leakDetailEmails")) el_("leakDetailEmails").innerHTML = emails.length
      ? emails.map(e => `<div style="padding:2px 0;border-bottom:1px solid var(--border);font-size:11px">${esc(e)}</div>`).join("")
      : '<span style="color:var(--text-muted)">None found</span>';
    const pwds = d.passwords || [];
    if (el_("leakDetailPasswords")) el_("leakDetailPasswords").innerHTML = pwds.length
      ? pwds.map(p => `<div style="padding:3px 0;border-bottom:1px solid var(--border);display:flex;gap:8px;font-size:11px">
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis">${esc(p.value||"")}</span>
          <span style="font-size:9px;color:var(--text-muted)">${esc(p.source||"")}</span>
          ${p.hashed ? '<span style="font-size:9px;color:var(--orange,#f97316)">HASH</span>' : ''}
        </div>`).join("")
      : '<span style="color:var(--text-muted)">None found</span>';
    const sources = d.sources || [];
    if (el_("leakDetailSources")) el_("leakDetailSources").innerHTML = sources.length
      ? sources.map(s => `<span class="badge badge-default" style="margin-right:4px;margin-bottom:4px">${esc(s)}</span>`).join("")
      : '<span style="color:var(--text-muted)">No sources</span>';
    const tl = d.breach_timeline || [];
    if (el_("leakDetailTimeline")) el_("leakDetailTimeline").innerHTML = tl.length
      ? tl.map(t => `<div style="padding:4px 0;border-bottom:1px solid var(--border);font-size:11px">
          <span style="font-weight:600">${esc(t.event||t.name||"")}</span>
          <span style="color:var(--text-muted);margin-left:8px">${esc(t.date||"")}</span>
          ${t.records ? `<span style="color:var(--orange,#f97316);margin-left:8px">${fmt(t.records)} records</span>` : ""}
        </div>`).join("")
      : '<span style="color:var(--text-muted)">No breach timeline</span>';
    const gh = d.github_leaks || [];
    if (el_("leakDetailGithub")) el_("leakDetailGithub").innerHTML = gh.length
      ? gh.map(g => `<div style="padding:3px 0;font-size:11px"><a href="${esc(g.url||"#")}" target="_blank" class="cell-link">${esc(g.file||"")} in ${esc(g.repo||"")}</a></div>`).join("")
      : '<span style="color:var(--text-muted)">None found</span>';
    card.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch(e) {
    const el = document.getElementById("leakDetailEmails");
    if (el) el.innerHTML = `<span style="color:var(--red,#ef4444)">Error: ${esc(e.message)}</span>`;
  }
}

async function runLeakScan() {
  if (!currentProjectId) return;
  const btn = document.getElementById("leakScanBtn");
  if (btn) { btn.disabled = true; btn.textContent = "⏳ Queuing…"; }
  try {
    const d = await fetch(`/api/projects/${currentProjectId}/recon/run`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: "leak_only" }),
    }).then(r => r.json());
    showToast(d.ok ? "Leak scan queued — results appear as they complete" : (d.error || "Failed"), d.ok ? "success" : "error");
  } catch(e) { showToast("Error: " + e.message, "error"); }
  finally {
    if (btn) { btn.disabled = false; btn.textContent = "▶ Run Leak Scan"; }
    setTimeout(loadLeakTab, 4000);
  }
}

async function runSingleLeakCheck(sub) {
  showToast(`Checking leaks for ${sub}…`, "info");
  try {
    await fetch(`/api/projects/${currentProjectId}/recon/${encodeURIComponent(sub)}/leak-check`, { method: "POST" });
    setTimeout(loadLeakTab, 4000);
  } catch(e) { showToast("Error: " + e.message, "error"); }
}

// ════════════════════════════════════════════════════════════════════════════════
// RECON INTEL TAB (inline summary — full dashboard opens in new tab)
// ════════════════════════════════════════════════════════════════════════════════

async function loadReconTab() {
  if (!currentProjectId) return;
  const tbody = document.getElementById("reconTopTbody");
  if (tbody) tbody.innerHTML = `<tr><td colspan="8" class="empty"><span class="spin">⟳</span> Loading…</td></tr>`;
  try {
    const sum = await fetch(`/api/projects/${currentProjectId}/recon/summary`).then(r => r.ok ? r.json() : {});
    const r = sum.recon || {}, l = sum.leaks || {};
    const set_ = (id, v) => { const el = document.getElementById(id); if(el) el.textContent = v; };
    set_("rc-scanned",  r.total_scanned   || "0");
    set_("rc-crit",     r.critical_count  || "0");
    set_("rc-high",     r.high_count      || "0");
    set_("rc-secrets",  sum.secrets_found  || "0");
    set_("rc-takeover", sum.takeovers_found || "0");
    set_("rc-avg",      Math.round(r.avg_risk_score || 0) + "/100");
    const top = sum.top_risky || [];
    if (!top.length) {
      if (tbody) tbody.innerHTML = `<tr><td colspan="8" class="empty">No recon data yet — run a scan or open the full Recon Intel dashboard</td></tr>`;
      return;
    }
    const sevColor = { critical:"var(--red,#ef4444)", high:"var(--orange,#f97316)", medium:"var(--yellow,#f0b429)", low:"var(--green,#22c55e)" };
    const sevCls   = { critical:"bc", high:"bh", medium:"bm", low:"bl" };
    if (tbody) tbody.innerHTML = top.map(row => {
      const ports = (row.ports || []).slice(0, 4);
      return `<tr>
        <td style="font-family:var(--mono);font-size:11px">${esc(row.subdomain)}</td>
        <td><div style="display:flex;align-items:center;gap:6px">
          <div style="flex:1;height:6px;background:var(--border);border-radius:3px;overflow:hidden;max-width:60px">
            <div style="height:100%;width:${row.risk_score}%;background:${sevColor[row.risk_severity]||"var(--accent)"}"></div>
          </div>
          <span style="font-weight:700;color:${sevColor[row.risk_severity]||""}">${row.risk_score}</span>
        </div></td>
        <td><span class="badge ${sevCls[row.risk_severity]||"bx"}">${esc(row.risk_severity||"low")}</span></td>
        <td style="font-size:10px">${ports.map(p=>`<span class="badge badge-default" style="margin-right:2px">${p}</span>`).join("")}</td>
        <td>${row.js_secrets?.length > 0 ? `<span class="badge bc">${row.js_secrets.length}</span>` : "—"}</td>
        <td>${row.takeover?.vulnerable ? '<span class="badge bh">⚠ YES</span>' : "—"}</td>
        <td>${row.compromised ? '<span class="badge badge-danger">🔴 YES</span>' : "—"}</td>
        <td><button class="btn btn-xs btn-ghost" onclick="if(currentProjectId)window.open('/projects/'+currentProjectId+'/recon-intel','_blank')">↗ Full</button></td>
      </tr>`;
    }).join("");
  } catch(e) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="8" class="empty">Error: ${esc(e.message)}</td></tr>`;
  }
}

async function runReconScan() {
  if (!currentProjectId) return;
  try {
    const d = await fetch(`/api/projects/${currentProjectId}/recon/run`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: "full" }),
    }).then(r => r.json());
    showToast(d.ok ? "Recon scan queued" : (d.error || "Failed"), d.ok ? "success" : "error");
    if (d.ok) setTimeout(loadReconTab, 5000);
  } catch(e) { showToast("Error: " + e.message, "error"); }
}

// ── Tab badge counts: called on every project open ────────────────────────────
async function _updateDetailBadges(pid) {
  try {
    const [lk, vk] = await Promise.all([
      fetch(`/api/projects/${pid}/leak-intel/status`).then(r => r.ok ? r.json() : {}),
      fetch(`/api/projects/${pid}/vulnerabilities?per_page=500`).then(r => r.ok ? r.json() : []),
    ]);
    const comp  = lk.compromised || 0;
    const vulns = Array.isArray(vk) ? vk.length : 0;
    const lb = document.getElementById("dtab-leaks-cnt");
    const vb = document.getElementById("dtab-vulns-cnt");
    if (lb) { lb.textContent = comp;  lb.style.display = comp  > 0 ? "inline" : "none"; }
    if (vb) { vb.textContent = vulns; vb.style.display = vulns > 0 ? "inline" : "none"; }
    if (lk.unchecked > 0 && lk.total_checked === 0) {
      const t = document.getElementById("dtab-leaks");
      if (t) t.title = `${lk.unchecked} subdomains not yet leak-checked`;
    }
  } catch(_) {}
}

// ── Dropdown toggle ────────────────────────────────────────────────────────
function toggleDropdown(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const isOpen = el.style.display === "block";
  // Close all dropdowns first
  document.querySelectorAll(".dropdown-menu").forEach(d => d.style.display = "none");
  el.style.display = isOpen ? "none" : "block";
  // Close when clicking outside
  if (!isOpen) {
    setTimeout(() => {
      const handler = (e) => {
        if (!el.contains(e.target)) { el.style.display = "none"; document.removeEventListener("click", handler); }
      };
      document.addEventListener("click", handler);
    }, 0);
  }
}

function fmt(n) { return n == null ? "—" : Number(n).toLocaleString(); }
function fmtTs(ts) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString("en-GB",{dateStyle:"short",timeStyle:"short"}); }
  catch { return ts.slice(0,16); }
}
function fmtDuration(sec) {
  if (!sec) return "—";
  sec = parseInt(sec);
  if (sec < 60) return sec + "s";
  if (sec < 3600) return `${Math.floor(sec/60)}m ${sec%60}s`;
  return `${Math.floor(sec/3600)}h ${Math.floor((sec%3600)/60)}m`;
}
function fmtSize(b) {
  if (!b) return "—";
  if (b>=1048576) return (b/1048576).toFixed(1)+"MB";
  if (b>=1024)    return (b/1024).toFixed(1)+"KB";
  return b+"B";
}
function esc(s) {
  if (!s) return "";
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
function debounce(fn, ms=350, immediate=false) {
  let t;
  return (...args) => {
    const callNow = immediate && !t;
    clearTimeout(t);
    t = setTimeout(() => { t = null; if (!immediate) fn(...args); }, ms);
    if (callNow) fn(...args);
  };
}
// ── Toast with dedup and queue limit ──
let _toastQueue = 0;
const TOAST_MAX = 5;
function showToast(msg, type="info", dur=3500) {
  if (_toastQueue >= TOAST_MAX) return; // Prevent toast spam
  const t = document.getElementById("toast");
  if (!t) return;
  _toastQueue++;
  const d = document.createElement("div");
  d.className = `toast-item ${type}`;
  d.textContent = ({success:"✓",error:"✗",warning:"⚠",info:"ℹ"}[type]||"") + " " + msg;
  t.prepend(d);
  setTimeout(()=>{ d.remove(); _toastQueue--; }, dur);
}
function platClass(p) {
  const m = {hackerone:"hackerone",bugcrowd:"bugcrowd",yeswehack:"yeswehack",hackenproof:"hackenproof",manual:"manual",bbscope:"bbscope"};
  return "plat-pill plat-" + (m[(p||"").toLowerCase()]||"other");
}
function scClass(code) {
  if (!code) return "sc-0";
  if (code>=500) return "sc-5xx";
  if (code>=400) return "sc-4xx";
  if (code>=300) return "sc-3xx";
  if (code>=200) return "sc-2xx";
  return "sc-0";
}
function scBadge(code) {
  if (!code) return `<span class="sc-badge sc-0">—</span>`;
  const rangeClass = scClass(code);
  return `<span class="sc-badge ${rangeClass} sc-${code}">${code}</span>`;
}
function scanPill(status) {
  const map = {pending:["⏳","badge badge-yellow","Pending"],scanning:["🔄","badge badge-accent","Scanning"],nuclei_scanning:["🛡","badge badge-red","Nuclei"],done:["✅","badge badge-green","Done"],phase_a:["🔄","badge badge-accent","Phase A"],phase_a_done:["🔄","badge badge-accent","Phase A ✓"],phase_b_done:["🔄","badge badge-accent","Phase B ✓"],phase_c_done:["🔄","badge badge-accent","Phase C ✓"],phase_d:["🛡","badge badge-red","Nuclei"],recon_done:["🔄","badge badge-accent","Recon ✓"]};
  const [ic,cls,lbl] = map[status]||["?","badge badge-default",status||"?"];
  return `<span class="${cls}">${ic} ${lbl}</span>`;
}
function sevBadge(s) {
  const m = {critical:"badge-red",high:"badge-orange",medium:"badge-yellow",low:"badge-green",info:"badge-default"};
  return `<span class="badge ${m[(s||"").toLowerCase()]||"badge-default"}">${esc(s)||"info"}</span>`;
}
function techTags(tech) {
  if (!tech) return "";
  const all = tech.split(",").filter(Boolean);
  const shown = all.slice(0,5).map(t=>`<span class="tech-tag">${esc(t.trim())}</span>`).join("");
  // JS-09 FIX: show +N more badge if truncated
  const extra = all.length > 5 ? `<span class="tech-tag tech-more" title="${esc(all.slice(5).map(t=>t.trim()).join(', '))}">+${all.length-5}</span>` : "";
  return shown + extra;
}
function portTags(ports_json) {
  if (!ports_json) return "";
  try {
    const ports = JSON.parse(ports_json);
    return ports.slice(0,6).map(p=>`<span class="port-tag">${p}</span>`).join("");
  } catch { return ""; }
}

const debouncedLoadProjects = debounce(()=>{ currentProjPage = 1; loadProjects(); });
const debouncedLoadSubs     = debounce(()=>{ currentSubPage = 1; loadSubs(); });

// ── Modal ─────────────────────────────────────────────────────────────────────
function openModal(title,body,footer="") {
  document.getElementById("modalTitle").textContent = title;
  document.getElementById("modalBody").innerHTML = body;
  document.getElementById("modalFtr").innerHTML = footer;
  document.getElementById("modalBg").classList.add("open");
  // Pause all heavy polling while modal is open to prevent lag
  _modalPollsPaused = true;
}
let _modalPollsPaused = false;
function closeModal() {
  document.getElementById("modalBg").classList.remove("open");
  _modalPollsPaused = false;
}
document.addEventListener("keydown", e=>{
  if(e.key==="Escape") closeModal();
  // Ctrl/Cmd+K = focus search
  if((e.ctrlKey||e.metaKey) && e.key==="k") { e.preventDefault(); showView("search"); }
  // Ctrl/Cmd+D = dashboard
  if((e.ctrlKey||e.metaKey) && e.key==="d") { e.preventDefault(); showView("dashboard"); }
});
function toggleSidebar() { document.getElementById("sidebar").classList.toggle("open"); }

// ── Stats / TopBar ────────────────────────────────────────────────────────────
async function refreshStats() {
  if (!_tabVisible) return;
  try {
    const d = await fetch("/api/stats").then(r=>r.json());
    document.getElementById("tk-proj").textContent  = fmt(d.projects?.total ?? d.programs ?? 0);
    document.getElementById("tk-alive").textContent = fmt(d.subdomains?.alive ?? d.alive ?? 0);
    document.getElementById("tk-vulns").textContent = fmt(d.vulnerabilities ?? 0);
    const tkAlerts = document.getElementById("tk-alerts");
    const alertCount = d.unread_alerts ?? d.alerts ?? 0;
    if (tkAlerts) tkAlerts.textContent = alertCount > 0 ? alertCount : "—";

    // Alert badge in nav
    const alertBadge = document.getElementById("alertBadgeNav");
    if (alertBadge) {
      alertBadge.textContent = alertCount;
      alertBadge.style.display = alertCount > 0 ? "" : "none";
    }

    maxConcurrentScans = d.bulk_scan?.concurrent || 10;

    // Sync job indicator
    const job = d.job || {};
    const wrap = document.getElementById("syncIndicatorWrap");
    if (wrap) {
      if (job.running) {
        const pct = job.total>0 ? Math.round(job.current/job.total*100):0;
        const phase = (job.phase||"sync").toUpperCase().replace("_"," ");
        wrap.innerHTML = `<div style="display:flex;align-items:center;gap:6px;padding:4px 10px;background:var(--accent-lt);border-radius:20px;font-size:11px;font-weight:600;color:var(--accent)"><span class="spin">⟳</span>${phase} ${pct}%${job.eta?" · "+job.eta:""}</div>`;
      } else {
        wrap.innerHTML = "";
      }
    }

    // Bulk scan ETA pill
    const bs = d.bulk_scan || {};
    const etaWrap = document.getElementById("scanEtaWrap");
    if (etaWrap) {
      if (bs.running) {
        const pct = bs.total>0 ? Math.round(bs.completed/bs.total*100):0;
        etaWrap.innerHTML = `<div style="display:flex;align-items:center;gap:5px;padding:4px 10px;background:#f0fdf4;border:1px solid #86efac;border-radius:20px;font-size:11px;font-weight:600;color:#16a34a"><span class="spin">⟳</span>SCAN ${bs.completed}/${bs.total} · ${pct}%${bs.eta?" · "+bs.eta:""}</div>`;
      } else if (selectedProjects.size > 0 && currentView==="projects") {
        const cnt = selectedProjects.size;
        const batches = Math.ceil(cnt / maxConcurrentScans);
        const etaSecs = batches * 120;
        const etaStr = etaSecs>=60 ? `~${Math.floor(etaSecs/60)}m ${etaSecs%60}s` : `~${etaSecs}s`;
        etaWrap.innerHTML = `<div style="display:flex;align-items:center;gap:5px;padding:4px 10px;background:#f0fdf4;border:1px solid #86efac;border-radius:20px;font-size:11px;font-weight:600;color:#16a34a">⚡ ${cnt} selected · ${batches} batch${batches>1?"es":""} · ETA ${etaStr}</div>`;
      } else {
        etaWrap.innerHTML = "";
      }
    }
    return d;
  } catch(e) { console.warn("refreshStats error:", e); }
}

// JS-08 FIX: lightweight topbar counter update using /api/stats/live
async function refreshTopbar() {
  try {
    const d = await fetch("/api/stats/live").then(r=>r.json());
    if (!d) return;
    const tkProj  = document.getElementById("tk-proj");
    const tkAlive = document.getElementById("tk-alive");
    const tkVulns = document.getElementById("tk-vulns");
    const tkAlerts= document.getElementById("tk-alerts");
    if (tkProj)  tkProj.textContent  = fmt(d.projects?.total ?? 0);
    if (tkAlive) tkAlive.textContent = fmt(d.alive ?? 0);
    if (tkVulns) tkVulns.textContent = fmt(d.vulnerabilities ?? 0);
    const alertCount = d.unread_alerts ?? 0;
    if (tkAlerts) tkAlerts.textContent = alertCount > 0 ? alertCount : "—";
    const alertBadge = document.getElementById("alertBadgeNav");
    if (alertBadge) { alertBadge.textContent = alertCount; alertBadge.style.display = alertCount > 0 ? "" : "none"; }
  } catch(e) { /* silent */ }
}

// ── Dashboard Live State ──────────────────────────────────────────────────────
let dashLiveTimer      = null;
let dashSlowTimer      = null;
let _lastAliveCount    = -1;   // track changes to avoid unnecessary DOM writes
let _lastRecentHash    = "";   // hash of recent-alive table to avoid re-render flicker
let _lastScanningSet   = "";   // JSON of scanning project IDs for change detection
let _dashAnimFrame     = null; // rAF handle for number animations

// Simple counter update — no rAF loop, just set value directly.
// Avoids frame-racing when multiple counters update at once.
// ── Efficient counter update with optional animation ──
const _counterCache = new WeakMap();
function animateCounter(el, newVal) {
  if (!el) return;
  const cached = _counterCache.get(el);
  if (cached === newVal) return; // Skip if unchanged
  _counterCache.set(el, newVal);
  // Use requestAnimationFrame to batch DOM writes
  requestAnimationFrame(() => {
    el.setAttribute("data-raw", newVal);
    el.textContent = newVal.toLocaleString();
  });
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function loadDashboard() {
  const d = await refreshStats();
  if (!d) return; // guard: only bail if fetch completely failed

  // KPI cards — live-only subdomains
  const kpis = [
    {label:"Programs",    value:d.projects?.total||0,   sub:`${d.projects?.chaos||0} chaos · ${(d.projects?.hackerone||0)+(d.projects?.yeswehack||0)} private`, color:"var(--accent)",  icon:"📁"},
    {label:"Live Hosts",  value:d.subdomains?.alive??0,  sub:`${d.subdomains?.new||0} new this sync`, color:"var(--green)",  icon:"✅"},
    {label:"Pending Scan",value:d.projects?.pending??0,  sub:"awaiting HTTPX",     color:"var(--orange)", icon:"⏳"},
    {label:"Scanning Now",value:d.projects?.scanning??0, sub:"active scans",       color:"var(--accent)", icon:"🔄"},
    {label:"Vulns Found", value:d.vulnerabilities??0,    sub:"all projects",       color:"var(--red)",    icon:"🛡"},
  ];
  document.getElementById("kpiGrid").innerHTML = kpis.map((k,i)=>
    `<div class="kpi" style="--kpi-color:${k.color}" id="kpi-card-${i}">
       <div class="kpi-label">${k.label}</div>
       <div class="kpi-value" id="kpi-val-${i}" data-raw="${k.value}">${fmt(k.value)}</div>
       <div class="kpi-sub" id="kpi-sub-${i}">${k.sub}</div>
       <div class="kpi-icon">${k.icon}</div>
     </div>`).join("");

  // Platforms
  const plats = d.platforms||[];
  const maxP = plats[0]?.c||1;
  document.getElementById("platformBreakdown").innerHTML = plats.length
    ? plats.map(p=>`<div class="plat-item">
        <div class="plat-name" title="${esc(p.p)}">${esc(p.p)}</div>
        <div class="plat-bar-wrap"><div class="plat-bar" style="width:${Math.round(p.c/maxP*100)}%"></div></div>
        <div class="plat-cnt">${p.c}</div>
      </div>`).join("")
    : `<div class="empty"><div class="empty-icon">🏷</div>No programs yet</div>`;

  // Top Technologies — normalized, clickable, no duplicates
  const techs = d.tech_top||[];
  const maxT = techs[0]?.c||1;
  document.getElementById("techBreakdown").innerHTML = techs.length
    ? techs.map(t=>`<div class="plat-item tech-item" onclick="filterByTech('${esc(t.tech)}')" title="${esc(t.tech)} → click to filter">
        <div class="plat-name">${esc(t.tech)}</div>
        <div class="plat-bar-wrap"><div class="plat-bar" style="width:${Math.round(t.c/maxT*100)}%"></div></div>
        <div class="plat-cnt">${t.c}</div>
      </div>`).join("")
    : `<div class="empty"><div class="empty-icon">🔧</div>Scan projects to see technologies</div>`;

  // Top Ports
  const ports = d.top_ports||[];
  document.getElementById("topPortsList").innerHTML = ports.length
    ? ports.map(p=>`<div class="port-item">
        <span class="port-num">${p.port}</span>
        <span class="port-service">${esc(p.service||"")}</span>
        <span class="port-bar-wrap"><span class="port-bar" style="width:${Math.round(p.count/(ports[0].count||1)*100)}%"></span></span>
        <span class="port-count">${fmt(p.count)}</span>
      </div>`).join("")
    : `<div class="empty"><div class="empty-icon">🔌</div>No port data available</div>`;

  // Recent alive
  renderRecentAlive(d.recent_alive||[]);

  // Vulnerability summary — initial load
  fetch("/api/vulnerabilities/breakdown").then(r=>r.json()).then(bd => {
    const total = (bd.by_severity||[]).reduce((s,v)=>s+v.count,0);
    _lastVulnCount = total;  // Initialize so live poll always detects changes
    _renderVulnSummaryLive({vulnerabilities:total, vuln_by_severity:bd.by_severity||[], review_pending:0, recent_vulns:bd.recent||[]});
    _renderVulnBreakdownChart(bd);
  }).catch(()=>{});

  // Kick off live polling
  startDashLive();
}

function renderRecentAlive(recent) {
  const hash = recent.map(r=>r.subdomain+":"+r.status_code+":"+r.last_seen).join("|");
  if (hash === _lastRecentHash) return;
  _lastRecentHash = hash;
  const dot = document.getElementById("recentAliveDot");
  if (dot) { dot.style.opacity="1"; setTimeout(()=>dot.style.opacity="0.4",800); }
  const tsEl = document.getElementById("recentAliveTs");
  if (tsEl) tsEl.textContent = "Updated " + new Date().toLocaleTimeString("en-GB",{hour:"2-digit",minute:"2-digit",second:"2-digit"});

  function scDisplay(code) {
    if (!code || code === 0) return `<span class="sc-0">—</span>`;
    if (code === 1) return `<span class="badge badge-yellow" style="font-size:10px">✓ Alive</span>`;
    return `<span class="${scClass(code)}">${code}</span>`;
  }

  document.getElementById("recentAlive").innerHTML = recent.length
    ? recent.map(r=>`<tr class="dash-live-row">
        <td class="mono">${esc(r.subdomain)}</td>
        <td>${r.url ? `<a href="${esc(r.url)}" target="_blank" class="cell-link">${esc(r.url)}</a>` : `<span class="text-dim" style="font-size:11px">awaiting deep scan…</span>`}</td>
        <td>${scDisplay(r.status_code)}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.title)||"—"}</td>
        <td><div class="tech-tags">${techTags(r.tech)}</div></td>
        <td class="text-sm">${esc(r.project_name)}</td>
      </tr>`).join("")
    : `<tr><td colspan="6" class="empty">No live hosts yet — run a sync!</td></tr>`;
}

// ── Live polling — fast (2s) when scanning, slow (10s) when idle ──────────────
function startDashLive() {
  stopDashPoll();
  _pollDashLive();
}

async function _pollDashLive() {
  if (currentView !== "dashboard") return;
  if (_modalPollsPaused || document.hidden) { dashLiveTimer = setTimeout(_pollDashLive, 5000); return; }
  try {
    const d = await fetch("/api/stats/live").then(r=>r.json());
    _applyLiveData(d);
    // Adaptive poll rate: fast during scan, slow when idle
    const interval = (d.scanning_count > 0 || d.job?.running) ? 1800 : 9000;
    dashLiveTimer = setTimeout(_pollDashLive, interval);
  } catch {
    dashLiveTimer = setTimeout(_pollDashLive, 5000);
  }
}

function _applyLiveData(d) {
  // ── 1. Topbar live subs counter ───────────────────────────────────────────
  const tkAlive = document.getElementById("tk-alive");
  if (tkAlive && d.alive !== _lastAliveCount) {
    animateCounter(tkAlive, d.alive);
    _lastAliveCount = d.alive;
  }

  // ── 2. KPI cards — patch only what changed ────────────────────────────────
  const aliveEl = document.getElementById("kpi-val-1");
  if (aliveEl) animateCounter(aliveEl, d.alive);

  const subEl = document.getElementById("kpi-sub-1");
  if (subEl) subEl.textContent = `${d.new_subs||0} new this sync`;

  const scanEl = document.getElementById("kpi-val-3");
  if (scanEl) animateCounter(scanEl, d.scanning_count||0);

  // Update Programs KPI card (kpi-val-0) and its subtitle from live project counts
  if (d.projects) {
    const progEl = document.getElementById("kpi-val-0");
    if (progEl) animateCounter(progEl, d.projects?.total||0);
    const progSub = document.getElementById("kpi-sub-0");
    if (progSub) progSub.textContent = `${d.projects.chaos||0} chaos · ${(d.projects.hackerone||0)+(d.projects.yeswehack||0)} private`;
  }

  // ── 3. Sync job indicator (topbar) ────────────────────────────────────────
  const job = d.job || {};
  const wrap = document.getElementById("syncIndicatorWrap");
  if (wrap) {
    if (job.running) {
      const pct = job.total>0 ? Math.round(job.current/job.total*100) : 0;
      const phase = (job.phase||"sync").toUpperCase().replace("_"," ");
      wrap.innerHTML = `<div style="display:flex;align-items:center;gap:6px;padding:4px 10px;background:var(--accent-lt);border-radius:20px;font-size:11px;font-weight:600;color:var(--accent)"><span class="spin">⟳</span>${phase} ${pct}%${job.eta?" · "+job.eta:""}</div>`;
    } else {
      wrap.innerHTML = "";
    }
  }

  // ── 4. Per-project live scan progress panel ───────────────────────────────
  const progress = d.project_progress || [];
  const scanKey  = JSON.stringify(progress.map(p=>p.id+":"+p.alive+":"+p.phase+":"+p.batch+":"+(p.nuclei_found||0)+":"+(p.nuclei_pct||0)));
  if (scanKey !== _lastScanningSet) {
    _lastScanningSet = scanKey;
    renderScanProgress(progress, d.job);
  }

  // ── 5. Recent live hosts ticker (only when new hosts appear) ──────────────
  if (d.recent_live && d.recent_live.length) {
    renderRecentAlive(d.recent_live);
  }

  // ── 6. Vulnerabilities — live dashboard cards + summary ──────────────────
  const vulnEl = document.getElementById("kpi-val-4");
  if (vulnEl && d.vulnerabilities !== undefined) animateCounter(vulnEl, d.vulnerabilities);
  const vulnSub = document.getElementById("kpi-sub-4");
  if (vulnSub && d.review_pending !== undefined) vulnSub.textContent = `${d.review_pending} pending review`;
  const tkVulns = document.getElementById("tk-vulns");
  if (tkVulns && d.vulnerabilities !== undefined) animateCounter(tkVulns, d.vulnerabilities);
  const scanKpiEl = document.getElementById("kpi-val-3");
  if (scanKpiEl && d.projects) animateCounter(scanKpiEl, (d.projects.scanning||0));
  const pendKpiEl = document.getElementById("kpi-val-2");
  if (pendKpiEl && d.projects) animateCounter(pendKpiEl, (d.projects.pending||0));
  // Always re-render vuln summary when count changes (keeps dashboard in sync)
  if (d.vulnerabilities !== undefined && d.vulnerabilities !== _lastVulnCount) {
    _lastVulnCount = d.vulnerabilities;
    _renderVulnSummaryLive(d);
  } else {
    _renderVulnSummaryLive(d);
  }
}

function renderScanProgress(projects, job) {
  const panel = document.getElementById("liveScanPanel");
  const body  = document.getElementById("liveScanBody");
  if (!panel || !body) return;

  const isActive = projects.length > 0 || job?.running;
  panel.style.display = isActive ? "block" : "none";
  if (!isActive) { body.innerHTML = ""; return; }

  // Global alive badge in card header
  const globalEl = document.getElementById("lspGlobalAlive");
  if (globalEl && _lastAliveCount >= 0) {
    globalEl.textContent = fmt(_lastAliveCount) + " alive";
  }

  // Job-level phase bar (overall sync progress)
  const phase = (job?.phase || "").toLowerCase();
  const phaseLabels = {
    import: { label: "📥 Importing",      cls: "lsp-phase-import" },
    scan:   { label: "⚡ Phase A · Alive", cls: "lsp-phase-a"     },
    alive:  { label: "⚡ Phase A · Alive", cls: "lsp-phase-a"     },
    b:      { label: "🗑 Phase B · Prune", cls: "lsp-phase-b"     },
    c:      { label: "🔬 Phase C · Deep",  cls: "lsp-phase-c"     },
    d:      { label: "🛡 Phase D · Nuclei", cls: "lsp-phase-d"    },
    done:   { label: "✅ Complete",         cls: "lsp-phase-done"  },
  };
  const phInfo = phaseLabels[phase] || { label: job?.running ? "⟳ Scanning" : "", cls: "" };
  const jobPct = job?.total > 0 ? Math.round(job.current / job.total * 100) : 0;

  let html = "";
  if (job?.running && phInfo.label) {
    html += `
    <div class="lsp-job-row">
      <span class="lsp-phase-badge ${phInfo.cls}">${phInfo.label}</span>
      <span class="lsp-job-meta">${job.current || 0} / ${job.total || 0} programs${job.eta ? " · ETA " + job.eta : ""}</span>
    </div>
    <div class="lsp-bar-track" style="margin-bottom:12px">
      <div class="lsp-bar-fill" style="width:${jobPct}%"></div>
    </div>`;
  }

  if (projects.length) {
    html += `<div class="lsp-projects">`;
    for (const p of projects) {
      const phaseA = p.phase === "A";
      const phaseB = p.phase === "B";
      const phaseC = p.phase === "C";
      const phaseD = p.phase === "D";
      const phaseTag = phaseA
        ? `<span class="lsp-phase-tag lsp-tag-a">Phase A · Alive</span>`
        : phaseB
        ? `<span class="lsp-phase-tag lsp-tag-b">Phase B · Prune</span>`
        : phaseD
        ? `<span class="lsp-phase-tag lsp-tag-d">Phase D · Nuclei</span>`
        : `<span class="lsp-phase-tag lsp-tag-c">Phase C · Deep</span>`;
      const batchInfo = phaseD
        ? (p.nuclei_found > 0 ? `<span class="lsp-batch-info">🎯 ${p.nuclei_found} vulns${p.nuclei_pct > 0 ? " · "+Math.round(p.nuclei_pct)+"%" : ""}</span>` : (p.nuclei_pct > 0 ? `<span class="lsp-batch-info">${Math.round(p.nuclei_pct)}%</span>` : `<span class="lsp-batch-info">scanning…</span>`))
        : p.batches > 1
        ? `<span class="lsp-batch-info">batch ${p.batch}/${p.batches}</span>`
        : "";
      const barColor = phaseA ? "var(--yellow)" : phaseD ? "var(--red)" : phaseC ? "var(--green)" : "var(--orange)";
      const pct = phaseD ? Math.min(100, p.nuclei_pct || 0) : Math.min(100, p.pct);

      html += `<div class="lsp-proj">
        <div class="lsp-proj-top">
          <div class="lsp-proj-name" title="${esc(p.name)}">${esc(p.name)}</div>
          <div class="lsp-proj-right">
            ${phaseTag}${batchInfo}
          </div>
        </div>
        <div class="lsp-proj-counts">
          <span class="lsp-alive-num">${fmt(p.alive)}</span>
          <span class="lsp-sep"> alive </span>
          <span class="lsp-total-num">/ ${fmt(p.total)}</span>
          <span class="lsp-pct-badge">${phaseD ? Math.round(p.nuclei_pct || 0) : p.pct}%</span>
        </div>
        <div class="lsp-proj-bar-wrap">
          <div class="lsp-proj-bar" style="width:${pct}%;background:${barColor}"></div>
        </div>
      </div>`;
    }
    html += `</div>`;
  } else if (job?.running) {
    html += `<div style="padding:8px 0;font-size:12px;color:var(--text3);text-align:center">Waiting for projects to start scanning…</div>`;
  }

  body.innerHTML = html;
}

// ── Vulnerability Summary for Dashboard (live-updated) ──────────────────────
function _renderVulnSummaryLive(d) {
  const el = document.getElementById("vulnSummary");
  if (!el) return;
  const total = d.vulnerabilities || 0;
  const bySev = d.vuln_by_severity || [];
  const pending = d.review_pending || 0;
  const recent = d.recent_vulns || [];
  if (total === 0) {
    el.innerHTML = `<div class="empty" style="padding:16px;text-align:center"><div class="empty-icon">🛡</div>No vulnerabilities found yet</div>`;
    return;
  }
  const sevColors = {critical:'#ef4444',high:'#f97316',medium:'#f59e0b',low:'#22c55e',info:'#6b7280'};
  const sevEmoji = {critical:'🔴',high:'🟠',medium:'🟡',low:'🟢'};
  const sevHtml = bySev.map(s => {
    const c = sevColors[(s.severity||'').toLowerCase()] || '#6b7280';
    const em = sevEmoji[(s.severity||'').toLowerCase()] || '';
    return `<span style="display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:600;background:${c}15;color:${c};border:1px solid ${c}30">${em} ${(s.severity||'?').toUpperCase()} <b>${s.count}</b></span>`;
  }).join(' ');
  const recentHtml = recent.slice(0,5).map(v => {
    const c = sevColors[(v.severity||'').toLowerCase()] || '#6b7280';
    return `<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--border);font-size:12px">
      <span style="color:${c};font-weight:700;min-width:56px;text-transform:uppercase">${v.severity||'?'}</span>
      <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(v.name||'')}">${esc(v.name||'Unknown')}</span>
      <span style="color:var(--text3);font-size:11px">${esc(v.project_name||'')}</span>
    </div>`;
  }).join('');
  el.innerHTML = `
    <div style="margin-bottom:10px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span style="font-size:20px;font-weight:700">${total}</span>
        <span style="font-size:12px;color:var(--text3)">total vulnerabilities</span>
        ${pending > 0 ? `<span style="margin-left:auto;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;background:#ef444420;color:#ef4444;cursor:pointer" onclick="showView('review')">${pending} pending review →</span>` : ''}
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:6px">${sevHtml}</div>
    </div>
    ${recentHtml ? `<div style="margin-top:8px">${recentHtml}</div>` : ''}`;
}

function _renderVulnBreakdownChart(bd) {
  const el = document.getElementById("vulnBreakdownChart");
  if (!el) return;
  const bySev = bd.by_severity || [];
  const total = bySev.reduce((s,v)=>s+v.count, 0);
  if (total === 0) { el.innerHTML = `<div class="empty" style="padding:20px;text-align:center"><div class="empty-icon">🛡</div>No vulnerabilities</div>`; return; }
  const sevColors = {critical:'#ef4444',high:'#f97316',medium:'#f59e0b',low:'#22c55e',info:'#6b7280'};
  el.innerHTML = `<div style="margin-bottom:12px;font-size:13px;font-weight:600;color:var(--text2)">Severity Breakdown · ${total} total</div>` +
    bySev.map(s => {
      const c = sevColors[(s.severity||'').toLowerCase()] || '#6b7280';
      const pct = Math.round(s.count/total*100);
      return `<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:12px">
        <span style="min-width:60px;font-weight:600;color:${c};text-transform:uppercase">${s.severity||'?'}</span>
        <div style="flex:1;height:8px;background:var(--border);border-radius:4px;overflow:hidden"><div style="width:${pct}%;height:100%;background:${c};border-radius:4px;transition:width 0.3s"></div></div>
        <span style="min-width:36px;text-align:right;font-weight:600">${s.count}</span>
        <span style="min-width:30px;text-align:right;color:var(--text3)">${pct}%</span>
      </div>`;
    }).join('');
}

async function _loadVulnBreakdown() {
  try {
    const bd = await fetch("/api/vulnerabilities/breakdown").then(r=>r.json());
    _renderVulnBreakdownChart(bd);
  } catch(e) {}
}

// ── Nuclei view live polling — auto-refreshes vulns while scan is running ────
function startNucleiPoll() {
  stopNucleiPoll();
  _pollNucleiLive();
}
function stopNucleiPoll() {
  if (nucleiPollTimer) { clearTimeout(nucleiPollTimer); nucleiPollTimer = null; }
}
async function _pollNucleiLive() {
  if (currentView !== "nuclei") return;
  try {
    // Check if any nuclei scan is currently active
    const live = await fetch("/api/stats/live").then(r=>r.json());
    const vulnCount = live.vulnerabilities || 0;
    const isScanning = (live.scanning_count > 0) ||
                       (live.project_progress||[]).some(p => p.phase === "D");

    // Always update vuln counts in topbar + nuclei view when count changes
    if (vulnCount !== _lastVulnCount) {
      _lastVulnCount = vulnCount;
      // Refresh the full vuln table and chart
      await loadVulns();
      await _loadVulnBreakdown();
      // Update count badge
      const countEl = document.getElementById("vulnCount");
      if (countEl) countEl.textContent = vulnCount;
    }

    // Update live scan progress in nuclei view if scanning
    if (isScanning) {
      _updateNucleiScanProgress(live);
    } else {
      // Scan just finished — do one final full refresh to catch all findings
      const card = document.getElementById("nucleiScanProgressCard");
      if (card && card.style.display !== "none") {
        card.style.display = "none";
        // Final refresh of vulns after scan completes
        _lastVulnCount = -1;  // force refresh
        await loadVulns();
        await _loadVulnBreakdown();
        showToast("Nuclei scan complete — vulnerability table updated", "success");
      }
    }

    // Fast poll when scanning, slow when idle
    const interval = isScanning ? 2000 : 8000;
    nucleiPollTimer = setTimeout(_pollNucleiLive, interval);
  } catch {
    nucleiPollTimer = setTimeout(_pollNucleiLive, 5000);
  }
}

function _updateNucleiScanProgress(d) {
  const el = document.getElementById("nucleiScanProgress");
  const card = document.getElementById("nucleiScanProgressCard");
  if (!el) return;
  const progress = (d.project_progress || []).filter(p => p.phase === "D");
  if (!progress.length) {
    if (card) card.style.display = "none";
    el.style.display = "none";
    return;
  }
  if (card) card.style.display = "block";
  el.style.display = "block";
  el.innerHTML = progress.map(p => {
    const pct = Math.round(p.nuclei_pct || 0);
    const found = p.nuclei_found || 0;
    return `<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)">
      <span style="font-size:18px">🛡</span>
      <div style="flex:1">
        <div style="display:flex;justify-content:space-between;margin-bottom:4px">
          <span style="font-weight:600;font-size:13px">${esc(p.name)}</span>
          <span style="font-size:12px;color:var(--text3)">${pct}% · ${fmt(p.total)} URLs</span>
        </div>
        <div style="background:var(--border);border-radius:4px;height:6px;overflow:hidden">
          <div style="width:${pct}%;height:100%;background:var(--red);border-radius:4px;transition:width 0.5s"></div>
        </div>
        ${found > 0 ? `<div style="margin-top:4px;font-size:11px;color:var(--red);font-weight:600">🎯 ${found} finding${found>1?'s':''} so far</div>` : ''}
      </div>
    </div>`;
  }).join('');
}

function startDashPoll() { startDashLive(); }

function stopDashPoll() {
  if (dashLiveTimer) { clearTimeout(dashLiveTimer); dashLiveTimer=null; }
}

// Pause/resume all active polls when tab visibility changes
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && currentView === 'dashboard' && !dashLiveTimer) {
    _pollDashLive();
  }
});

// ── Projects page auto-refresh during active scans ────────────────────────────
let projectsLivePollTimer = null;
let _projLastAlive = -1;  // track alive count to only reload when it changes
async function _pollProjectsLive() {
  if (currentView !== "projects") return;
  if (_modalPollsPaused || document.hidden) { projectsLivePollTimer = setTimeout(_pollProjectsLive, 8000); return; }
  try {
    // Use the lightweight live stats endpoint (in-memory, no heavy JOIN)
    const s = await fetch("/api/stats/live").then(r => r.json());
    const curAlive = s.alive || 0;
    const isScanning = s.scanning_count > 0 || s.job?.running;

    // Only reload the full projects table if alive count changed OR a scan just finished
    if (isScanning && curAlive !== _projLastAlive) {
      _projLastAlive = curAlive;
      // Update topbar immediately (cheap)
      const tkAlive = document.getElementById("tk-alive");
      if (tkAlive) tkAlive.textContent = curAlive.toLocaleString();
      // Reload projects table (throttled - only when data changed)
      await loadProjects();
    } else if (!isScanning && _projLastAlive !== -1 && curAlive !== _projLastAlive) {
      // Scan finished - do one final reload
      _projLastAlive = curAlive;
      await loadProjects();
    }
  } catch {}
  if (currentView === "projects") {
    // Poll faster while scanning, slower when idle
    const interval = 5000;
    projectsLivePollTimer = setTimeout(_pollProjectsLive, interval);
  }
}
function startProjectsLivePoll() {
  stopProjectsLivePoll();
  _projLastAlive = -1;
  projectsLivePollTimer = setTimeout(_pollProjectsLive, 5000);
}
function stopProjectsLivePoll() {
  if (projectsLivePollTimer) { clearTimeout(projectsLivePollTimer); projectsLivePollTimer = null; }
}


// ── Technology Search ─────────────────────────────────────────────────────────
function filterByTech(tech) {
  const inp = document.getElementById("techSearchInput");
  if (inp) { inp.value = tech; searchTechnology(tech); }
}

function searchTechnology(query) {
  clearTimeout(techSearchTimer);
  const tech = (query||"").trim();
  const resultsEl = document.getElementById("techSearchResults");
  if (!resultsEl) return;

  if (!tech || tech.length < 2) {
    resultsEl.style.display = "none"; resultsEl.innerHTML = "";
    return;
  }

  techSearchTimer = setTimeout(async ()=>{
    resultsEl.style.display = "";
    resultsEl.innerHTML = `<div style="padding:8px;font-size:11px;color:var(--text3)"><span class="spin">⟳</span> Searching…</div>`;
    try {
      const d = await fetch(`/api/tech/search?tech=${encodeURIComponent(tech)}`).then(r=>r.json());
      const results = d.subdomains || d.results || [];
      const total   = d.total ?? d.count ?? results.length;
      if (total === 0) {
        resultsEl.innerHTML = `<div class="empty" style="padding:10px">No subdomains found with "${esc(tech)}"</div>`;
        return;
      }
      resultsEl.innerHTML = `
        <div class="tech-search-header">
          <span style="font-size:12px;font-weight:600;color:var(--text1)">${fmt(total)} subdomains with <span style="color:var(--accent)">${esc(tech)}</span></span>
          <div style="display:flex;gap:6px">
            <button class="btn btn-xs btn-secondary" onclick="copyTechSubdomains('${esc(tech)}','subdomains')">📋 Copy Subdomains</button>
            <button class="btn btn-xs btn-accent" onclick="exportTechSubdomains('${esc(tech)}','urls')">⬇ Export URLs</button>
          </div>
        </div>
        <div class="tech-results">
          ${results.slice(0,15).map(r=>`<div class="tech-result-item">
            <div>
              <a href="${esc(r.url||'#')}" target="_blank" class="cell-link mono" style="font-size:11px">${esc(r.subdomain)}</a>
              <span class="text-dim" style="font-size:10px;margin-left:6px">${esc(r.project_name)}</span>
            </div>
            <span class="${scClass(r.status_code)}" style="flex-shrink:0">${r.status_code||"?"}</span>
          </div>`).join("")}
          ${total>15?`<div style="padding:6px 8px;font-size:11px;color:var(--text3);text-align:center">+ ${total-15} more</div>`:""}
        </div>`;
    } catch(e) {
      resultsEl.innerHTML = `<div style="padding:8px;color:var(--red);font-size:12px">Error: ${e.message}</div>`;
    }
  }, 300);
}

async function copyTechSubdomains(tech, type="subdomains") {
  try {
    const d = await fetch(`/api/tech/search?tech=${encodeURIComponent(tech)}&limit=5000`).then(r=>r.json());
    const _subs = d.subdomains || d.results || [];
    const items = type==="urls" ? _subs.map(r=>r.url).filter(Boolean) : _subs.map(r=>r.subdomain);
    await navigator.clipboard.writeText(items.join("\n"));
    showToast(`Copied ${items.length} ${type} to clipboard!`, "success");
  } catch(e) { showToast("Copy failed: "+e.message, "error"); }
}

function exportTechSubdomains(tech, fmt_type="urls") {
  showToast('Tech export: use Global Search → filter by tech → Export CSV', 'info', 5000);
}

// ── Mini Log ──────────────────────────────────────────────────────────────────
function pushMiniLog(entry) {
  miniLogBuf.push(entry);
  if (miniLogBuf.length > MINI_LOG_MAX) miniLogBuf.shift();
  const el = document.getElementById("miniLog");
  if (!el) return;
  const d = document.createElement("div");
  d.className = `mini-log-row ${entry.level||"info"}`;
  // Fixed: use textContent for message to avoid overflow glitch
  const ts = document.createElement("span");
  ts.className = "mini-log-ts";
  ts.textContent = fmtTs(entry.timestamp);
  const msg = document.createElement("span");
  msg.className = "mini-log-msg";
  msg.textContent = entry.message || "";
  d.appendChild(ts); d.appendChild(msg);
  el.insertBefore(d, el.firstChild);
  // Keep trimmed
  while (el.children.length > MINI_LOG_MAX) el.removeChild(el.lastChild);
}
function clearMiniLog() {
  const el = document.getElementById("miniLog");
  if (el) el.innerHTML = "";
  miniLogBuf = [];
}

// ── Selection & Bulk Actions ──────────────────────────────────────────────────
function toggleSelect(id, checked) {
  if (checked) selectedProjects.add(id);
  else selectedProjects.delete(id);
  updateBulkBar();
  refreshStats();
}
function toggleAll(chk) {
  document.querySelectorAll(".proj-chk").forEach(c=>{
    c.checked = chk.checked;
    if (chk.checked) selectedProjects.add(c.value);
    else selectedProjects.delete(c.value);
  });
  updateBulkBar();
  refreshStats();
}
function updateBulkBar() {
  const n = selectedProjects.size;
  const dBtn = document.getElementById("bulkDelBtn");
  const sBtn = document.getElementById("bulkScanBtn");
  if (dBtn) { dBtn.style.display = n>0?"":"none"; document.getElementById("selCount").textContent=n; }
  if (sBtn) { sBtn.style.display = n>0?"":"none"; document.getElementById("selScanCount").textContent=n; }
}

async function bulkScan() {
  const ids = [...selectedProjects];
  if (!ids.length) return;
  if (!confirm(`Start HTTPX scan on ${ids.length} project${ids.length>1?"s":""}?`)) return;
  const r = await fetch("/api/projects/bulk-scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ids})}).then(r=>r.json());
  if (r.ok) {
    showToast(`Bulk scan started: ${ids.length} projects`, "success");
    selectedProjects.clear(); updateBulkBar();
    document.getElementById("chkAll").checked=false;
    document.querySelectorAll(".proj-chk").forEach(c=>c.checked=false);
  } else showToast("Error: "+r.error, "error");
}

async function bulkDelete() {
  const ids = [...selectedProjects];
  if (!ids.length) return;
  if (!confirm(`Delete ${ids.length} project${ids.length>1?"s":""}? This cannot be undone.`)) return;
  const r = await fetch("/api/projects/bulk-delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ids})}).then(r=>r.json());
  if (r.ok) { showToast(`Deleted ${r.deleted} projects`,"success"); selectedProjects.clear(); updateBulkBar(); loadProjects(); }
  else showToast("Error: "+r.error,"error");
}

async function deleteAll() {
  // FIX: fetch backup state FIRST so the confirm dialog shows what will be recoverable
  let bkLine = "";
  try {
    const st = await fetch("/api/server/status").then(r=>r.json());
    const bk = st.backup || {};
    if (bk.exists && bk.projects > 0) {
      const ts = bk.updated ? new Date(bk.updated).toLocaleString("en-GB",{dateStyle:"short",timeStyle:"short"}) : "unknown";
      bkLine = `\n\n✅ A backup will be saved BEFORE deletion:\n   ${(bk.projects||0).toLocaleString()} programs · ${(bk.subs||0).toLocaleString()} subdomains\n   (recoverable via "Restore from Backup" in Server Control)`;
    } else {
      bkLine = `\n\n⚠️  No previous backup found — data will be permanently lost!`;
    }
  } catch(e) {}

  if (!confirm(`🗑 DELETE ALL DATA?\n\nThis will wipe all projects, subdomains, and vulnerabilities from the live database.${bkLine}\n\nContinue?`)) return;

  const r = await fetch("/api/projects/delete-all",{method:"POST"}).then(r=>r.json());
  if (r.ok) {
    // FIX: show how much is in the backup so the user knows recovery is possible
    const msg = r.backup_projects > 0
      ? `All data deleted. Backup preserved: ${(r.backup_projects).toLocaleString()} programs → restore via Server Control.`
      : "All deleted.";
    showToast(msg, "success", 6000);
    loadProjects();
    refreshStats();
    // Refresh server panel if visible so backup counts update immediately
    if (currentView === "server") loadServerStatus();
  } else {
    showToast("Error: " + (r.error||"unknown"), "error");
  }
}

async function deleteProject(pid) {
  if (!confirm("Delete this project and all its subdomains?")) return;
  const r = await fetch(`/api/projects/${pid}`,{method:"DELETE"}).then(r=>r.json());
  if (r.ok) { showToast("Deleted","success"); showView("projects"); }
  else showToast("Error: "+r.error,"error");
}
async function deleteCurrentProject() { if(currentProjectId) await deleteProject(currentProjectId); }

// ── Projects ──────────────────────────────────────────────────────────────────
async function loadPlatformFilter() {
  const r = await fetch("/api/chaos/platforms").then(r=>r.json());
  const sel = document.getElementById("fPlatform");
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = `<option value="">All Platforms</option>` +
    (r.platforms||[]).map(p=>`<option value="${esc(p)}" ${p===cur?"selected":""}>${esc(p)}</option>`).join("");
}

function sortBy(field) {
  if (projSortField===field) projSortOrder = projSortOrder==="asc"?"desc":"asc";
  else { projSortField=field; projSortOrder="desc"; }
  loadProjects();
}

async function loadProjects() {
  const q       = document.getElementById("fSearch")?.value||"";
  const platform= document.getElementById("fPlatform")?.value||"";
  const bounty  = document.getElementById("fBounty")?.value||"";
  const source  = document.getElementById("fSource")?.value||"";
  const scope   = document.getElementById("fScope")?.value||"";
  const status  = document.getElementById("fScanStatus")?.value||"";
  const isNew   = document.getElementById("fNew")?.checked?"1":"";
  const sort    = document.getElementById("fSort")?.value||"created_at";
  const limit   = parseInt(document.getElementById("fLimit")?.value||25);
  const params  = new URLSearchParams({q,platform,bounty,source,scope_type:scope,scan_status:status,is_new:isNew,sort,order:projSortOrder,page:currentProjPage||1,limit});

  // Show loading state immediately
  const tbody = document.getElementById("projTbody");
  tbody.innerHTML = `<tr><td colspan="13" style="text-align:center;padding:24px;color:var(--text-muted)"><span style="opacity:.6">⏳ Loading…</span></td></tr>`;

  let data;
  try {
    const resp = await fetch(`/api/projects?${params}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    data = await resp.json();
    if (data.error) throw new Error(data.error);
  } catch(e) {
    // Retry once after 1.5s (server may be busy with active scan)
    tbody.innerHTML = `<tr><td colspan="13" style="text-align:center;padding:24px;color:var(--text-muted)"><span style="opacity:.6">⏳ Retrying…</span></td></tr>`;
    await new Promise(r=>setTimeout(r,1500));
    try {
      const resp2 = await fetch(`/api/projects?${params}`);
      data = await resp2.json();
    } catch(e2) {
      tbody.innerHTML = `<tr><td colspan="13" class="empty"><div class="empty-icon">⚠</div>Failed to load projects. Server may be busy with active scans.<br><small style="color:var(--text-muted)">This is normal during heavy scanning — will auto-retry.</small></td></tr>`;
      // Schedule auto-retry in 3s
      setTimeout(()=>{ if(currentView==="projects") loadProjects(); }, 3000);
      return;
    }
  }

  const rows    = data.projects||[];
  document.getElementById("projCountBadge").textContent = fmt(data.total);

  tbody.innerHTML = rows.length ? rows.map(p=>{
    const alive = p.sub_alive||0;
    const total = p.sub_total||0;
    const srcBadge = p.source==="bbscope" ? `<span class="badge badge-purple" style="font-size:9px">🔐 Private</span>` :
                     p.source==="chaos"   ? `<span class="badge badge-teal" style="font-size:9px">⚡ Chaos</span>` :
                     `<span class="badge badge-default" style="font-size:9px">Manual</span>`;
    return `<tr id="proj-row-${p.id}" onclick="rowClick('${p.id}',event)">
      <td onclick="event.stopPropagation()">
        <input type="checkbox" class="proj-chk" value="${p.id}" onchange="toggleSelect('${p.id}',this.checked)">
      </td>
      <td>
        <div style="font-weight:600;font-size:13px;cursor:pointer;color:var(--accent)" onclick="event.stopPropagation();showView('projectDetail','${p.id}')">${esc(p.name)}</div>
        ${p.is_new?'<span class="badge badge-green" style="margin-top:2px">NEW</span>':""}
      </td>
      <td><span class="${platClass(p.platform)}">${esc(p.platform||"—")}</span></td>
      <td>${srcBadge}</td>
      <td><span class="badge ${p.scope_type==="public"?"badge-teal":"badge-purple"}">${esc(p.scope_type||"?")}</span></td>
      <td>${p.bounty?'<span class="badge badge-yellow">💰</span>':""}</td>
      <td class="mono text-sm">${fmt(total)}</td>
      <td class="mono text-sm" style="color:var(--green)">${fmt(alive)}</td>
      <td>${p.sub_new?`<span class="badge badge-green">${p.sub_new}</span>`:""}</td>
      <td>${p.vuln_count?`<span class="badge badge-red">${p.vuln_count}</span>`:""}</td>
      <td class="mono text-xs ${p.change>0?"text-green":p.change<0?"text-red":""}">${p.change>0?"+":""}${p.change||0}</td>
      <td>${scanPill(p.scan_status)}</td>
      <td onclick="event.stopPropagation()" style="white-space:nowrap">
        <button class="btn btn-xs btn-secondary" onclick="quickScan('${p.id}')">⚡</button>
        <button class="btn btn-xs btn-danger-ghost" onclick="deleteProject('${p.id}')">✕</button>
      </td>
    </tr>`;
  }).join("") : `<tr><td colspan="13" class="empty"><div class="empty-icon">📁</div>No projects match filters</td></tr>`;

  renderPager("projPager", data, loadProjects);
}

function rowClick(id, e) {
  if (e.target.type==="checkbox" || e.target.tagName==="BUTTON") return;
  showView("projectDetail", id);
}

async function quickScan(pid) {
  const r = await fetch(`/api/projects/${pid}/scan`,{method:"POST"}).then(r=>r.json());
  if (r.ok) showToast("Scan queued","success");
}

async function exportAllProjects() { window.location.href="/api/projects?format=csv&limit=10000"; }

// ── Add Manual Project ────────────────────────────────────────────────────────
function showAddModal() {
  openModal("＋ Add Manual Project",`
    <div class="form-row" style="border:none;padding:0 0 12px">
      <label class="form-lbl">Project Name</label>
      <input type="text" class="input-full" id="mpName" placeholder="My Bug Bounty Program">
    </div>
    <div class="form-row" style="border:none;padding:0 0 12px">
      <label class="form-lbl">Wildcard Domains (one per line)</label>
      <textarea class="input-full" id="mpWilds" rows="4" placeholder="*.example.com&#10;*.api.example.com"></textarea>
    </div>
    <div class="form-row" style="border:none;padding:0 0 12px">
      <label class="form-lbl">Extra Domains (one per line)</label>
      <textarea class="input-full" id="mpExtras" rows="3" placeholder="admin.example.com&#10;api.example.com"></textarea>
    </div>
    <div class="form-row" style="border:none;padding:0">
      <label class="form-lbl">Tags</label>
      <input type="text" class="input-full" id="mpTags" placeholder="h1,vip,active">
    </div>`,
    `<button class="btn btn-ghost" onclick="closeModal()">Cancel</button>
     <button class="btn btn-primary" onclick="createManualProject()">Create & Enumerate</button>`);
}

async function createManualProject() {
  const name  = document.getElementById("mpName")?.value.trim();
  const wilds = (document.getElementById("mpWilds")?.value||"").split("\n").filter(Boolean);
  const extras= (document.getElementById("mpExtras")?.value||"").split("\n").filter(Boolean);
  const tags  = document.getElementById("mpTags")?.value||"";
  if (!name) { showToast("Name is required","error"); return; }
  const r = await fetch("/api/projects",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({source:"manual",name,wildcards:wilds,extras,tags})}).then(r=>r.json());
  if (r.ok) { closeModal(); showToast("Project created — enumerating…","success"); loadProjects(); }
  else showToast("Error: "+r.error,"error");
}

// ── Project Detail ────────────────────────────────────────────────────────────
async function loadProjectDetail(pid) {
  currentSubPage = 1;  // reset subdomain pager on every project load
  // JS-10 FIX: show loading state immediately
  const nameEl = document.getElementById("detailProjectName");
  if (nameEl) nameEl.textContent = "Loading…";
  const p = await fetch(`/api/projects/${pid}`).then(r=>r.json());
  if (p.error) { showToast("Project not found","error"); showView("projects"); return; }

  document.getElementById("detailTitle").textContent = p.name;
  document.getElementById("detailPlatTag").innerHTML = `<span class="${platClass(p.platform)}">${esc(p.platform||"?")}</span>`;
  document.getElementById("detailScanPill").innerHTML = scanPill(p.scan_status);
  document.getElementById("pageTitle").textContent = p.name;

  // For BBScope projects, show in-scope domains from metadata
  let scopeInfo = "";
  if (p.source === "bbscope" && p.metadata) {
    try {
      const meta_obj = JSON.parse(p.metadata);
      const domains = meta_obj.domains || [];
      if (domains.length) scopeInfo = domains.join(", ");
    } catch {}
  }
  const metaBar = document.getElementById("detailMetaBar");
  if (metaBar) {
    const stats = [
      {lbl:"Total Subs", val:fmt(p.sub_total ?? p.count), icon:"📊"},
      {lbl:"Live", val:fmt(p.sub_alive ?? p.live_count), icon:"●", color:"var(--green)"},
      {lbl:"New", val:fmt(p.sub_new), icon:"🆕"},
      {lbl:"Vulns", val:fmt(p.vuln_count), icon:"🛡", color:p.vuln_count?"var(--red)":""},
      {lbl:"Change", val:(p.change>0?"+":"")+String(p.change||0), icon:"Δ", color:p.change>0?"var(--green)":p.change<0?"var(--red)":""},
    ];
    metaBar.innerHTML = stats.map(s=>
      `<div class="detail-stat-card">
        <div class="detail-stat-val" ${s.color?`style="color:${s.color}"`:""}}>${s.val}</div>
        <div class="detail-stat-lbl">${s.lbl}</div>
      </div>`
    ).join("");
  }

  const meta = [
    {lbl:"Platform",    val:p.platform||"—"},
    {lbl:"Source",      val:p.source==="bbscope"?"🔐 H1 Private":p.source==="chaos"?"⚡ Chaos":p.source||"—"},
    {lbl:"Scope",       val:p.scope_type||"—"},
    {lbl:"Bounty",      val:p.bounty?"💰 Yes":"No"},
    {lbl:"Status",      val:p.scan_status||"—"},
    {lbl:"Total Subs",  val:fmt(p.sub_total ?? p.count)},
    {lbl:"Live Subs",   val:fmt(p.sub_alive ?? p.live_count)},
    {lbl:"New Subs",    val:fmt(p.sub_new)},
    {lbl:"Vulns",       val:fmt(p.vuln_count)},
    {lbl:"Change",      val:p.change>0?"+"+p.change:String(p.change||0)},
    {lbl:"Last Updated",val:fmtTs(p.last_updated)},
    {lbl:"Created",     val:fmtTs(p.created_at)},
    {lbl:"Last Scan",   val:fmtTs(p.last_synced)},
    ...(scopeInfo ? [{lbl:"In-Scope Domains", val:scopeInfo}] : []),
  ];
  document.getElementById("detailMeta").innerHTML = meta.map(m=>
    `<div class="meta-item"><div class="meta-lbl">${m.lbl}</div><div class="meta-val">${esc(String(m.val))}</div></div>`
  ).join("");
  loadSubs();
  if (currentProjectId) _updateDetailBadges(currentProjectId);
}

async function loadSubs(resetPage) {
  if (!currentProjectId) return;
  // JS-06 FIX: reset page when called with resetPage=true (from filter changes)
  if (resetPage) currentSubPage = 1;
  const q      = document.getElementById("sfSearch")?.value||"";
  const status = document.getElementById("sfStatus")?.value||"";
  const tech   = document.getElementById("sfTech")?.value||"";
  const port   = document.getElementById("sfPort")?.value||"";
  // Backend expects alive as Optional[int]: 1=alive, 0=dead, empty=all
  const alive  = document.getElementById("sfAlive")?.checked?"1":"";
  // Backend expects is_new as Optional[int]
  const is_new = document.getElementById("sfNew")?.checked?"1":"";
  // CDN filter — send as a search string (backend does ILIKE on cdn_name)
  const cdn    = document.getElementById("sfCDN")?.checked?"true":"";
  // TLS filter — send as a search string (backend does ILIKE on tls_cn)
  const tls    = document.getElementById("sfTLS")?.checked?"true":"";
  const sort   = document.getElementById("sfSort")?.value||"last_seen";
  const limit  = document.getElementById("sfLimit")?.value||200;
  // Backend subdomains endpoint param names:
  // q, status (=status_code int), tech, port, alive (int), is_new (int), cdn (str), tls (str), sort, limit, page
  const params = new URLSearchParams();
  if (q)      params.set("q", q);
  if (status) params.set("status", status);
  if (tech)   params.set("tech", tech);
  if (port)   params.set("port", port);
  if (alive)  params.set("alive", alive);
  if (is_new) params.set("is_new", is_new);
  if (cdn)    params.set("cdn", cdn);
  if (tls)    params.set("tls", tls);
  params.set("sort", sort);
  params.set("limit", limit);
  params.set("page", currentSubPage||1);

  const tbody = document.getElementById("subTbody");
  if (tbody) tbody.innerHTML = `<tr><td colspan="18" style="text-align:center;padding:20px;color:var(--text3)"><span class="spin">⟳</span> Loading…</td></tr>`;

  let data;
  try {
    const resp = await fetch(`/api/projects/${currentProjectId}/subdomains?${params}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    data = await resp.json();
  } catch(e) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="18" class="empty">Failed to load subdomains: ${esc(e.message)}</td></tr>`;
    return;
  }

  const subs = data.subdomains || [];
  const totalLabel = document.getElementById("subTotalLabel");
  if (totalLabel) totalLabel.textContent = `${fmt(data.total||0)} total`;

  if (tbody) {
    tbody.innerHTML = subs.length
      ? subs.map(s=>`<tr>
          <td class="mono sub-cell" title="${esc(s.subdomain)}">${esc(s.subdomain)}</td>
          <td class="sub-url-cell">${s.url?`<a href="${esc(s.url)}" target="_blank" class="cell-link" title="${esc(s.url)}">${esc((s.url||'').replace(/^https?:\/\//,'').slice(0,45))}</a>`:'<span class="text-dim">—</span>'}</td>
          <td>${scBadge(s.status_code && s.status_code > 0 ? s.status_code : (s.is_alive ? null : 0))}</td>
          <td class="sub-title-cell" title="${esc(s.title)}">${esc(s.title)||"—"}</td>
          <td class="sub-tech-cell"><div class="tech-tags">${techTags(s.tech)}</div></td>
          <td class="mono text-xs">${esc(s.ip)||"—"}</td>
          <td class="mono text-xs">${s.port||"—"}</td>
          <td class="text-sm sub-server-cell" title="${esc(s.webserver)}">${esc(s.webserver)||"—"}</td>
          <td>${s.cdn_name?`<span class="badge badge-cyan">${esc(s.cdn_name)}</span>`:'<span class="text-dim">—</span>'}</td>
          <td class="mono text-xs">${fmtSize(s.content_length)}</td>
          <td class="mono text-xs">${esc(s.response_time)||"—"}</td>
          <td class="mono text-xs sub-cname-cell" title="${esc(s.cname)}">${esc(s.cname)||"—"}</td>
          <td class="mono text-xs sub-tls-cell" title="${esc(s.tls_cn)}">${esc(s.tls_cn)||"—"}</td>
          <td class="text-xs text-dim sub-issuer-cell" title="${esc(s.tls_issuer)}">${esc(s.tls_issuer)||"—"}</td>
          <td class="text-xs text-dim sub-path-cell" title="${esc(s.path)}">${esc(s.path)||"—"}</td>
          <td class="text-xs text-dim" style="white-space:nowrap">${fmtTs(s.first_seen)}</td>
          <td class="text-xs text-dim" style="white-space:nowrap">${fmtTs(s.last_seen)||"—"}</td>
          <td>${s.is_new?'<span class="badge badge-green">NEW</span>':""}</td>
        </tr>`).join("")
      : `<tr><td colspan="18" class="empty"><div class="empty-icon">🌐</div>No subdomains match filters</td></tr>`;
  }

  renderPager("subPager", data, loadSubs);
}

function exportSubs(f) { if(currentProjectId) window.location.href=`/api/projects/${currentProjectId}/export?format=${f}`; }
function exportUrls()   { if(currentProjectId) window.location.href=`/api/projects/${currentProjectId}/export-urls`; }

async function reRunHttpx() {
  const r = await fetch(`/api/projects/${currentProjectId}/scan`,{method:"POST"}).then(r=>r.json());
  if (r.ok) showToast("Full re-scan started: subfinder → alive check → deep scan","success");
  else showToast("Error: "+r.error,"error");
}
function openNucleiForProject() {
  if (!currentProjectId) return;
  showView("nuclei");
  // Wait for loadNucleiProjects() to populate the dropdown, then select current project
  // Use a retry loop instead of fixed timeout to handle slow API responses
  let attempts = 0;
  const _selectProject = () => {
    const s = document.getElementById("nucleiProject");
    if (!s) return;
    if (s.querySelector(`option[value="${currentProjectId}"]`)) {
      s.value = currentProjectId;
    } else if (attempts++ < 20) {
      // Retry up to 2s (20 × 100ms)
      setTimeout(_selectProject, 100);
    }
  };
  setTimeout(_selectProject, 200);
}

// ── Pager ─────────────────────────────────────────────────────────────────────
function renderPager(id, data, fn) {
  const el = document.getElementById(id); if (!el) return;
  if (!data || !data.total) { el.innerHTML = ""; return; }
  const items = data.subdomains || data.projects || [];
  const total = data.total || 0;
  const pages = data.pages || 1;
  const p = data.page || 1;
  if (pages <= 1) {
    el.innerHTML = `<div class="pager-info">Showing ${fmt(items.length)} of ${fmt(total)}</div>`;
    return;
  }
  let h = `<span class="pager-info">Page ${p}/${pages} · ${fmt(total)} total</span>`;
  if (p>1)     h+=`<button class="btn btn-ghost btn-sm" onclick="gotoPage('${id}',1)">« First</button>`;
  if (p>1)     h+=`<button class="btn btn-ghost btn-sm" onclick="gotoPage('${id}',${p-1})">‹ Prev</button>`;
  if (p<pages) h+=`<button class="btn btn-ghost btn-sm" onclick="gotoPage('${id}',${p+1})">Next ›</button>`;
  if (p<pages) h+=`<button class="btn btn-ghost btn-sm" onclick="gotoPage('${id}',${pages})">Last »</button>`;
  el.innerHTML = h;
}

function gotoPage(pagerId, page) {
  if (pagerId === "projPager") { currentProjPage = page; loadProjects(); }
  else if (pagerId === "subPager") { currentSubPage = page; loadSubs(); }
}

// ── Chaos Sync ────────────────────────────────────────────────────────────────
async function loadChaosPlatforms() {
  const r = await fetch("/api/chaos/platforms").then(r=>r.json()).catch(()=>({platforms:[]}));
  ["syncPlat","sAutoPlatform"].forEach(id=>{
    const sel = document.getElementById(id); if (!sel) return;
    const cur = sel.value;  // preserve current user selection
    sel.innerHTML = `<option value="">All Platforms</option>` +
      (r.platforms||[]).map(p=>`<option value="${esc(p)}" ${p===cur?"selected":""}>${esc(p)}</option>`).join("");
    // If saved value is no longer in list (e.g. stale), reset to All Platforms
    if (cur && !r.platforms.includes(cur)) sel.value = "";
  });
}

async function loadPreview() {
  document.getElementById("previewArea").innerHTML = `<div style="padding:20px;text-align:center"><span class="spin">⟳</span> Fetching fresh index…</div>`;
  const d = await fetch("/api/chaos/preview").then(r=>r.json()).catch(()=>null);
  if (!d||d.error) {
    document.getElementById("previewArea").innerHTML = `<div style="padding:16px;color:var(--red);font-size:12px">Error: ${d?.error||"Failed"}</div>`; return;
  }
  const plats = Object.entries(d.platforms||{}).slice(0,12);
  document.getElementById("previewArea").innerHTML = `
    <div class="preview-grid">
      <div class="preview-cell"><div class="preview-num">${fmt(d.total)}</div><div class="preview-lbl">Total</div></div>
      <div class="preview-cell"><div class="preview-num text-accent">${fmt(d.bounty)}</div><div class="preview-lbl">Bounty</div></div>
      <div class="preview-cell"><div class="preview-num text-green">${d.total_subdomains>=1e6?(d.total_subdomains/1e6).toFixed(1)+"M":fmt(d.total_subdomains)}</div><div class="preview-lbl">Total Subs</div></div>
    </div>
    <div class="plat-grid">
      ${plats.map(([p,c])=>`<div class="plat-grid-item"><span class="plat-grid-name">${esc(p)}</span><span class="plat-grid-cnt">${c}</span></div>`).join("")}
    </div>`;
}

async function startSync() {
  const platform = document.getElementById("syncPlat")?.value||null;
  const bounty   = document.getElementById("syncBounty")?.checked??true;
  const r = await fetch("/api/chaos/sync",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({platform,bounty_only:bounty})}).then(r=>r.json());
  if (r.ok) {
    showToast("Two-phase sync started! Phase 1→Import, Phase 2→HTTPX","success");
    document.getElementById("syncBtn").style.display="none";
    document.getElementById("syncStopBtn").style.display="";
    document.getElementById("syncProgressCard").style.display="";
    startSyncPoll();
  } else showToast("Error: "+r.error,"error");
}

// JS-05 FIX: use setTimeout + visibility check instead of setInterval
function startSyncPoll() {
  stopSyncPoll();
  async function _pollSync() {
    if (currentView !== 'chaos') return;
    if (!document.hidden) { try { await loadSyncStatus(); } catch(e){} }
    syncPollTimer = setTimeout(_pollSync, 3000);
  }
  _pollSync();
}
function stopSyncPoll()  { if(syncPollTimer){clearInterval(syncPollTimer);syncPollTimer=null;} }

async function loadSyncStatus() {
  const d = await fetch("/api/chaos/status").then(r=>r.json()).catch(()=>null);
  if (!d) return;
  const job = d.job||{};

  if (job.running) {
    document.getElementById("syncBtn").style.display="none";
    document.getElementById("syncStopBtn").style.display="";
    document.getElementById("syncProgressCard").style.display="";
  } else {
    document.getElementById("syncBtn").style.display="";
    document.getElementById("syncStopBtn").style.display="none";
    // Only hide progress card if there's no recent completed job to show
    if (job.phase !== "done") {
      document.getElementById("syncProgressCard").style.display="none";
    }
  }

  if (job.running || job.phase==="done") {
    const pct = job.total>0?Math.round(job.current/job.total*100):0;
    const phaseMap = {
      import:"phase-import",alive_check:"phase-alive",
      full_scan:"phase-scan",done:"phase-done",bbscope_fetch:"phase-import"
    };
    document.getElementById("syncPhaseBadge").innerHTML =
      `<span class="sync-phase-badge ${phaseMap[job.phase]||"phase-import"}">${(job.phase||"RUNNING").toUpperCase().replace("_"," ")}</span>`;
    document.getElementById("syncProgTitle").textContent = job.program_name||"Processing…";
    document.getElementById("syncProgBar").style.width = pct+"%";
    document.getElementById("syncCurrent").textContent = `${job.current}/${job.total} (${pct}%)${job.eta?" · ETA: "+job.eta:""}`;
    document.getElementById("syncTotal").textContent = "";
    document.getElementById("syncStats").innerHTML = `
      <div class="stat-cell"><div class="stat-val text-accent">${fmt(job.imported)}</div><div class="stat-lbl">Imported</div></div>
      <div class="stat-cell"><div class="stat-val text-red">${fmt(job.failed)}</div><div class="stat-lbl">Failed</div></div>
      <div class="stat-cell"><div class="stat-val text-dim">${fmt(job.skipped)}</div><div class="stat-lbl">Skipped</div></div>
      <div class="stat-cell"><div class="stat-val text-green">${fmt(job.scanned||0)}</div><div class="stat-lbl">Subs Scanned</div></div>
      <div class="stat-cell"><div class="stat-val text-purple">${fmt(job.scanned)}</div><div class="stat-lbl">Fully Scanned</div></div>`;
  }

  // Job stats card
  if (job.running) {
    document.getElementById("syncJobStats").innerHTML = `
      <div style="padding:8px;font-size:12px">
        <div style="margin-bottom:6px"><b>Program:</b> ${esc(job.program_name||"…")}</div>
        <div style="margin-bottom:4px"><b>Phase:</b> <span class="badge badge-accent">${(job.phase||"").replace("_"," ")}</span></div>
        <div style="margin-bottom:4px"><b>Progress:</b> ${job.current||0}/${job.total||0}</div>
        <div style="margin-bottom:4px"><b>ETA:</b> ${job.eta||"Calculating…"}</div>
        <div style="margin-bottom:4px"><b>Subs scanned:</b> <span style="color:var(--green)">${fmt(job.scanned||0)}</span></div>
      </div>`;
  }
}

async function loadSyncHistory() {
  const d = await fetch("/api/sync/history").then(r=>r.json()).catch(()=>[]);
  const el = document.getElementById("syncHistoryList");
  if (!el) return;
  if (!d.length) {
    el.innerHTML=`<div class="empty" style="padding:20px"><div class="empty-icon">📜</div>No sync history yet</div>`; return;
  }
  el.innerHTML = d.map(h=>`
    <div class="history-item" onclick="toggleHistoryDetail('${h.id}')">
      <div class="history-header">
        <div>
          <span class="badge ${h.sync_type==="chaos"||h.sync_type==="h1"?"badge-accent":"badge-purple"}">${h.sync_type==="chaos"?"⚡ Chaos":"🔐 H1 Private"}</span>
          <span style="font-weight:600;font-size:12px;margin-left:6px">${esc(h.platform||"All")}</span>
        </div>
        <div style="text-align:right">
          <span class="job-status ${h.status||"running"}">${h.status||"running"}</span>
          <div style="font-size:10px;color:var(--text3);margin-top:2px">${fmtTs(h.started_at)}</div>
        </div>
      </div>
      <div class="history-stats">
        <span>↓ ${fmt(h.programs_imported)} imported</span>
        <span style="color:var(--green)">✅ ${fmt(h.subdomains_alive)} live</span>
        <span style="color:var(--text3)">✗ ${fmt(h.failed||0)} failed</span>
        <span style="color:var(--text3)">⏱ ${fmtDuration(h.time_elapsed)}</span>
      </div>
      <div id="hist-detail-${h.id}" class="history-detail" style="display:none">
        <div style="font-size:11px;color:var(--text3)">
          <div>Started: ${fmtTs(h.started_at)}</div>
          <div>Ended: ${fmtTs(h.ended_at)||"—"}</div>
          <div>Subs scanned: ${fmt(h.subdomains_alive||0)}</div>
        </div>
        <button class="btn btn-xs btn-ghost" style="margin-top:6px" onclick="event.stopPropagation();viewHistoryLogs('${h.id}')">View Logs</button>
      </div>
    </div>`).join("");
}

function toggleHistoryDetail(id) {
  const el = document.getElementById(`hist-detail-${id}`);
  if (el) el.style.display = el.style.display==="none"?"block":"none";
}

async function viewHistoryLogs(jid) {
  const d = await fetch(`/api/sync/history/${jid}/logs`).then(r=>r.json()).catch(()=>[]);
  openModal(`📜 Sync Job Logs`,
    `<div style="max-height:500px;overflow-y:auto;background:var(--bg3);border-radius:6px;padding:8px;font-family:var(--mono);font-size:11px">
      ${d.map(e=>`<div class="log-row ${e.level}" style="padding:2px 4px;border-bottom:1px solid var(--border)">
        <span class="log-ts" style="color:var(--text3)">${fmtTs(e.timestamp)}</span>
        <span class="log-msg" style="margin-left:8px">${esc(e.message)}</span>
      </div>`).join("")||"<div style='padding:12px;color:var(--text3)'>No logs found</div>"}
    </div>`);
}

// ── BBScope ───────────────────────────────────────────────────────────────────
async function loadBBScopeView() {
  const el = document.getElementById("bbscopePlatformsList");
  if (!el) return;

  let d;
  try { d = await fetch("/api/h1/platforms").then(r=>r.json()); }
  catch { d = {configured: false}; }

  if (!d.configured && !d.h1 && !(d.platforms && d.platforms.includes("hackerone"))) {
    el.innerHTML = `<div class="empty" style="padding:20px">
      <div class="empty-icon">🔐</div>
      <b>HackerOne credentials not configured.</b><br><br>
      Go to <a onclick="showView('settings')" style="cursor:pointer;color:var(--accent)">Settings → HackerOne API</a>
      and enter your:<br>
      <ul style="text-align:left;margin:8px auto;display:inline-block">
        <li><b>API Token Identifier</b> — the name you gave the token</li>
        <li><b>API Token Value</b> — the secret token string</li>
      </ul>
      <br>Generate at:
      <a href="https://hackerone.com/settings/api_token/edit" target="_blank" style="color:var(--accent)">
        hackerone.com/settings/api_token/edit
      </a>
    </div>`;
    loadBBScopeProjects();
    return;
  }

  el.innerHTML = `
    <div class="plat-item" style="padding:12px 16px;justify-content:space-between;align-items:center">
      <div>
        <div style="font-weight:700;font-size:14px;color:var(--text1)">🟡 HackerOne — Private Programs</div>
        <div style="font-size:11px;color:var(--green);margin-top:3px" id="h1-cred-status">✓ Credentials configured</div>
      </div>
      <div style="display:flex;gap:8px">
        <button class="btn btn-sm btn-ghost" onclick="testH1Creds()">🔍 Test</button>
        <button class="btn btn-sm btn-primary" onclick="startBBScopeSync('hackerone')">⟳ Sync Now</button>
      </div>
    </div>`;

  loadBBScopeProjects();
}

async function testH1Creds() {
  // Update status in both the HackerOne view and the Settings page
  const statusEls = [
    document.getElementById("h1-cred-status"),
    document.getElementById("settings-h1-test-result")
  ].filter(Boolean);
  statusEls.forEach(el => el.innerHTML = `<span class="spin">⟳</span> Testing…`);
  try {
    const r = await fetch("/api/h1/test", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({platform:"hackerone"})
    }).then(r=>r.json());
    statusEls.forEach(el => {
      el.innerHTML = r.ok
        ? `<span style="color:var(--green)">✓ ${esc(r.message)}</span>`
        : `<span style="color:var(--red)">✗ ${esc(r.error)}</span>`;
    });
    showToast(r.ok ? r.message : r.error, r.ok ? "success" : "error");
  } catch(e) {
    statusEls.forEach(el => el.innerHTML = `<span style="color:var(--red)">✗ Network error</span>`);
    showToast("Test failed: " + e.message, "error");
  }
}

// testBBScopeCreds removed — use testH1Creds()

function _buildPrivateProjectsTable(rows) {
  if (!rows.length) return `<div class="empty" style="padding:20px"><div class="empty-icon">📭</div>No programs synced yet.</div>`;
  return `<table class="tbl" style="width:100%">
    <thead><tr>
      <th>Program</th><th>Platform</th><th>Scope</th>
      <th>Total Subs</th><th>Live Subs</th><th>New</th><th>Vulns</th>
      <th>Status</th><th>Last Scan</th><th></th>
    </tr></thead>
    <tbody>
      ${rows.map(p => {
        const alive = p.sub_alive || 0, total = p.sub_total || 0;
        const pct = total > 0 ? Math.round(alive/total*100) : 0;
        return `<tr onclick="showView('projectDetail','${p.id}')" style="cursor:pointer">
          <td>
            <div style="font-weight:600;font-size:13px;color:var(--accent)">${esc(p.name)}</div>
            ${p.is_new?'<span class="badge badge-green" style="font-size:9px">NEW</span>':""}
            ${p.bounty?'<span class="badge badge-yellow" style="font-size:9px;margin-left:2px">💰</span>':""}
          </td>
          <td><span class="${platClass(p.platform)}">${esc(p.platform||"—")}</span></td>
          <td><span class="badge badge-purple" style="font-size:10px">🔐 Private</span></td>
          <td class="mono text-sm">${fmt(total)}</td>
          <td class="mono text-sm" style="color:var(--green)">${fmt(alive)}${total>0?`<span style="font-size:10px;color:var(--text3);margin-left:3px">(${pct}%)</span>`:""}</td>
          <td>${p.sub_new?`<span class="badge badge-green">${p.sub_new}</span>`:""}</td>
          <td>${p.vuln_count?`<span class="badge badge-red">${p.vuln_count}</span>`:""}</td>
          <td>${scanPill(p.scan_status)}</td>
          <td class="text-xs text-dim">${fmtTs(p.last_synced)||"—"}</td>
          <td onclick="event.stopPropagation()" style="white-space:nowrap">
            <button class="btn btn-xs btn-secondary" onclick="quickScan('${p.id}')">⚡ Scan</button>
            <button class="btn btn-xs btn-danger-ghost" onclick="deleteProject('${p.id}')">✕</button>
          </td>
        </tr>`;
      }).join("")}
    </tbody>
  </table>`;
}

async function loadBBScopeProjects() {
  const el = document.getElementById("bbscopeProjectsList");
  if (!el) return;
  let data;
  try {
    // HackerOne projects have platform='hackerone' — query by platform filter
    data = await fetch("/api/projects?platform=hackerone&limit=500&sort=created_at&order=desc").then(r=>r.json());
  } catch { data = {projects:[]}; }
  const rows = (data.projects || []);
  el.innerHTML = _buildPrivateProjectsTable(rows);
}

async function loadBBScopeHistory() {
  const el = document.getElementById("bbscopeHistoryList");
  if (!el) return;

  let all;
  try { all = await fetch("/api/sync/history").then(r=>r.json()); }
  catch { all = []; }

  const bb = (all||[]).filter(h => ["h1","bbscope","hackerone"].includes(h.sync_type));

  if (!bb.length) {
    el.innerHTML = `<div class="empty" style="padding:20px"><div class="empty-icon">📜</div>No BBScope sync history yet</div>`;
    return;
  }

  el.innerHTML = bb.map(h => `
    <div class="history-item" onclick="toggleHistoryDetail('bb-${h.id}')">
      <div class="history-header">
        <div>
          <span class="badge badge-default" style="font-size:11px;text-transform:capitalize">🔐 ${esc(h.platform||"?")}</span>
        </div>
        <div style="text-align:right">
          <span class="job-status ${h.status||"running"}">${h.status||"running"}</span>
          <div style="font-size:10px;color:var(--text3);margin-top:2px">${fmtTs(h.started_at)}</div>
        </div>
      </div>
      <div class="history-stats">
        <span>↓ ${fmt(h.programs_imported||0)} programs</span>
        <span style="color:var(--green)">✅ ${fmt(h.subdomains_alive||0)} live</span>
        <span>⏱ ${fmtDuration(h.time_elapsed)}</span>
      </div>
      <div id="hist-detail-bb-${h.id}" class="history-detail" style="display:none">
        <button class="btn btn-xs btn-ghost" onclick="event.stopPropagation();viewHistoryLogs('${h.id}')">View Logs</button>
      </div>
    </div>`).join("");
}

async function startBBScopeSync(platform) {
  platform = platform || "hackerone";
  if (!confirm("Start HackerOne private program sync?\n\nThis will:\n• Fetch your private programs via HackerOne API\n• Enumerate subdomains with subfinder\n• Run 3-phase HTTPX scan")) return;
  try {
    const r = await fetch("/api/sync/hackerone", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({platform})
    }).then(r=>r.json());
    if (r.job_id || r.ok) {
      showToast("HackerOne private sync started!", "success");
      loadBBScopeHistory();
      startH1LivePoll();
    } else {
      showToast(r.error || "Failed to start sync", "error");
    }
  } catch(e) { showToast("Error: " + e.message, "error"); }
}

function startH1LivePoll() {
  stopH1LivePoll(); _h1WasRunning = false; _pollH1Live();
}
function stopH1LivePoll() { if(h1LiveTimer){clearTimeout(h1LiveTimer);h1LiveTimer=null;} }

async function _pollH1Live() {
  if (currentView !== "bbscope") return;
  try {
    const d = await fetch("/api/h1/live").then(r=>r.json());
    _applyPlatformLiveData(d, "h1");
    const interval = d.running ? 1000 : 8000;
    if (_h1WasRunning && !d.running) {
      loadBBScopeProjects(); loadBBScopeHistory();
      showToast("HackerOne sync complete!", "success");
    }
    _h1WasRunning = !!d.running;
    h1LiveTimer = setTimeout(_pollH1Live, interval);
  } catch { h1LiveTimer = setTimeout(_pollH1Live, 5000); }
}


async function loadNucleiProjects() {
  // Single fetch — get all projects with alive subs (superset of done projects)
  const d = await fetch("/api/projects?limit=500").then(r=>r.json());
  const allProjs = d.projects||[];
  const sel = document.getElementById("nucleiProject");
  if (!sel) return;
  sel.innerHTML = `<option value="">— Select project —</option>` +
    allProjs.filter(p=>p.sub_alive>0).map(p=>
      `<option value="${p.id}">${esc(p.name)} (${fmt(p.sub_alive)} alive)</option>`
    ).join("");
  const vsel = document.getElementById("vulnProjFil");
  if (vsel) vsel.innerHTML = `<option value="">All Projects</option>` +
    allProjs.map(p=>`<option value="${p.id}">${esc(p.name)}</option>`).join("");
}

async function runNuclei() {
  const pid = document.getElementById("nucleiProject")?.value;
  if (!pid) { showToast("Select a project first","error"); return; }
  const templates = document.getElementById("nucleiTemplate")?.value||"";
  const severity  = document.getElementById("nucleiSeverity")?.value||"";
  const btn = document.getElementById("nucleiRunBtn");
  if (btn) { btn.disabled=true; btn.textContent="Starting…"; }
  const r = await fetch(`/api/projects/${pid}/nuclei`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({templates:templates||null,severity:severity||null})}).then(r=>r.json());
  if (btn) { btn.disabled=false; btn.textContent="🛡 Start Nuclei Scan"; }
  if (r.ok) {
    showToast("Nuclei scan started — results will appear below automatically","success");
    // Reset vuln count cache so the live poll picks up new findings immediately
    _lastVulnCount = -1;
    // Show scanning progress card immediately
    const card = document.getElementById("nucleiScanProgressCard");
    if (card) card.style.display = "block";
    const progEl = document.getElementById("nucleiScanProgress");
    if (progEl) {
      progEl.style.display = "block";
      progEl.innerHTML = `<div style="padding:12px;text-align:center;color:var(--text3);font-size:13px"><span class="spin">⟳</span> Nuclei starting up — checking for vulnerabilities…</div>`;
    }
    // Kick off fast poll immediately
    stopNucleiPoll();
    nucleiPollTimer = setTimeout(_pollNucleiLive, 2000);
  }
  else showToast("Error: "+r.error,"error");
}

async function loadVulns() {
  const sev = document.getElementById("vulnSevFil")?.value||"";
  const pid = document.getElementById("vulnProjFil")?.value||"";
  const params = new URLSearchParams({severity:sev,project_id:pid});
  const data = await fetch(`/api/vulnerabilities?${params}`).then(r=>r.json());
  document.getElementById("vulnCount").textContent = Array.isArray(data)?data.length:0;
  const tbody = document.getElementById("vulnTbody");
  tbody.innerHTML = (data||[]).length
    ? data.map(v=>`<tr>
        <td>${sevBadge(v.severity)}</td>
        <td style="font-weight:500">${esc(v.name)||"—"}</td>
        <td class="mono text-xs">${esc(v.template_id)||"—"}</td>
        <td><span class="badge badge-default">${esc(v.type)||"—"}</span></td>
        <td><a href="${esc(v.matched_at)}" target="_blank" class="cell-link">${esc(v.matched_at)}</a></td>
        <td class="text-sm">${esc(v.project_name||"—")}</td>
        <td class="text-xs text-dim">${fmtTs(v.created_at)}</td>
      </tr>`).join("")
    : `<tr><td colspan="7" class="empty">No vulnerabilities found</td></tr>`;
}

// ── Logs ──────────────────────────────────────────────────────────────────────
async function loadLogs() {
  const level = document.getElementById("lLevel")?.value||"";
  const cat   = document.getElementById("lCat")?.value||"";
  const limit = document.getElementById("lLimit")?.value||1000;
  const q     = document.getElementById("lSearch")?.value||"";
  const params = new URLSearchParams({level,category:cat,limit,q});
  const data = await fetch(`/api/logs?${params}`).then(r=>r.json());
  renderLogs(data.reverse());
}

function renderLogs(entries) {
  const el = document.getElementById("logScroll"); if (!el) return;
  if (!entries.length) {
    el.innerHTML=`<div style="padding:24px;text-align:center;color:var(--text3)">No logs</div>`; return;
  }
  // Build using DOM to avoid XSS and rendering glitches
  const frag = document.createDocumentFragment();
  entries.forEach(e=>{
    const row = document.createElement("div");
    row.className = `log-row ${e.level||"info"}`;
    const ts = document.createElement("span"); ts.className="log-ts"; ts.textContent=fmtTs(e.timestamp);
    const cat = document.createElement("span"); cat.className=`log-cat ${e.category||"system"}`; cat.textContent=(e.category||"sys").slice(0,6);
    const msg = document.createElement("span"); msg.className="log-msg"; msg.textContent=e.message||"";
    row.appendChild(ts); row.appendChild(cat); row.appendChild(msg);
    frag.appendChild(row);
  });
  el.innerHTML="";
  el.appendChild(frag);
  if (document.getElementById("lAutoScroll")?.checked) el.scrollTop=el.scrollHeight;
}

function appendLogRow(e) {
  const el = document.getElementById("logScroll"); if (!el) return;
  const row = document.createElement("div");
  row.className = `log-row ${e.level||"info"}`;
  const ts = document.createElement("span"); ts.className="log-ts"; ts.textContent=fmtTs(e.timestamp);
  const cat= document.createElement("span"); cat.className=`log-cat ${e.category||"system"}`; cat.textContent=(e.category||"sys").slice(0,6);
  const msg= document.createElement("span"); msg.className="log-msg"; msg.textContent=e.message||"";
  row.appendChild(ts); row.appendChild(cat); row.appendChild(msg);
  el.appendChild(row);
  // Trim old entries
  while(el.children.length>2000) el.removeChild(el.firstChild);
  if(document.getElementById("lAutoScroll")?.checked) el.scrollTop=el.scrollHeight;
}

function startLiveMode() {
  stopLiveMode();
  if (!document.getElementById("lLiveMode")?.checked) return;
  function poll() {
    fetch(`/api/logs/live?since=${logCursor}`)
      .then(r=>r.json())
      .then(d=>{
        if (d.logs?.length) {
          logCursor=d.cursor;
          d.logs.forEach(e=>{ appendLogRow(e); pushMiniLog(e); });
          refreshStats();
        }
      }).catch(()=>{});
    liveLogTimer = setTimeout(poll, _modalPollsPaused ? 3000 : 1500);
  }
  poll();
}
function stopLiveMode()  { if(liveLogTimer){clearTimeout(liveLogTimer);liveLogTimer=null;} }
function toggleLiveMode(){ if(document.getElementById("lLiveMode")?.checked) startLiveMode(); else stopLiveMode(); }
async function clearLogs() {
  if (!confirm("Clear all logs?")) return;
  await fetch("/api/logs/clear",{method:"POST"});
  showToast("Logs cleared","success"); loadLogs();
}

// ── Settings ──────────────────────────────────────────────────────────────────
// ── Settings tab switcher ─────────────────────────────────────────────────────
function switchSettingsTab(tab) {
  // Update nav items
  document.querySelectorAll('.settings-nav-item').forEach(el => el.classList.remove('active'));
  const nav = document.getElementById('sTab-' + tab);
  if (nav) nav.classList.add('active');
  // Update panels
  document.querySelectorAll('.settings-panel').forEach(el => el.classList.remove('active'));
  const panel = document.getElementById('sPanel-' + tab);
  if (panel) panel.classList.add('active');
}

async function loadSettings() {
  try {
    const s = await fetch("/api/settings").then(r=>r.json());
    const set = (id,v)=>{ const e=document.getElementById(id); if(e && v!=null) e.value=v; };
    const chk = (id,v)=>{ const e=document.getElementById(id); if(e) e.checked=!!v; };

    set("sConcurrent",     s.max_concurrent_scans||5);
    set("sThreads",        s.httpx_threads||500);
    set("sTimeout",        s.httpx_timeout||10);
    set("sRateLimit",      s.httpx_rate_limit||500);
    set("sBatchSize",      s.httpx_batch_size||5000);
    set("sPorts",          s.httpx_ports||"80,443,8080,8443,8000,8888");
    chk("sScreenshot",     s.httpx_screenshot);
    chk("sRemoveDead",     s.remove_dead_subdomains??true);
    chk("sAutoSync",       s.auto_sync_enabled);
    set("sInterval",       s.sync_interval_hours||24);
    chk("sAutoBounty",     s.auto_sync_bounty_only??true);
    set("sImportLimit",    s.import_limit||0);
    chk("sSkipExisting",   s.skip_existing??true);
    set("sNucThreads",     s.nuclei_threads||25);
    set("sSfThreads",      s.subfinder_threads||10);
    set("sH1Username",     s.bbscope_hackerone_username||"");
    set("sH1Token",        s.bbscope_hackerone_token||"");
    set("sBCEmail",        s.bbscope_bugcrowd_email||"");
    set("sBCPassword",     s.bbscope_bugcrowd_password||"");
    set("sYwhToken",       s.bbscope_yeswehack_token||"");
    // Beast Mode / v7 fields
    set("s_monitor_enabled",   s.monitor_enabled);
    set("s_monitor_interval",  s.monitor_interval_min);
    set("s_tmpl_interval",     s.template_update_interval_hours);
    set("s_auto_nuclei",       s.auto_nuclei_on_new_subs);
    set("s_nuclei_skip_info",  s.nuclei_skip_info);
    set("s_discord_webhook",   s.discord_webhook_url);
    set("s_slack_webhook",     s.slack_webhook_url);
    set("s_tg_token",          s.telegram_bot_token);
    set("s_tg_chat",           s.telegram_chat_id);

    const concVal = document.getElementById("sConcurrentVal");
    if (concVal) concVal.textContent = s.max_concurrent_scans||5;
    const thrVal = document.getElementById("sThreadsVal");
    if (thrVal) thrVal.textContent = s.httpx_threads||500;

    const h1Status = document.getElementById("h1CredStatus");
    if (h1Status) {
      const hasH1 = !!(s.bbscope_hackerone_username && s.bbscope_hackerone_token);
      h1Status.textContent = hasH1 ? "✓ Configured" : "Not configured";
      h1Status.className   = "cred-card-status " + (hasH1 ? "stored" : "empty");
    }
    const ywhStatus = document.getElementById("ywhCredStatus");
    if (ywhStatus) {
      const hasYwh = !!s.bbscope_yeswehack_token;
      ywhStatus.textContent = hasYwh ? "✓ Configured" : "Not configured";
      ywhStatus.className   = "cred-card-status " + (hasYwh ? "stored" : "empty");
    }

    await loadChaosPlatforms();
    if (s.auto_sync_platform) { const e = document.getElementById("sAutoPlatform"); if(e) e.value=s.auto_sync_platform||""; }
    // NOTE: Never override theme from server - always respect localStorage user preference
  } catch(e) { console.error("loadSettings error", e); }
}

// saveSettings defined at end of file (single unified version)

// ── Sync Backup ───────────────────────────────────────────────────────────────

// ── YesWeHack ─────────────────────────────────────────────────────────────────
function startYWHLivePoll() {
  stopYWHLivePoll(); _ywhWasRunning = false; _pollYWHLive();
}
function stopYWHLivePoll() { if(ywhLiveTimer){clearTimeout(ywhLiveTimer);ywhLiveTimer=null;} }

async function _pollYWHLive() {
  if (currentView !== "yeswehack") return;
  try {
    const d = await fetch("/api/ywh/live").then(r=>r.json());
    _applyPlatformLiveData(d, "ywh");
    const interval = d.running ? 1000 : 8000;
    if (_ywhWasRunning && !d.running) {
      loadYWHProjects(); loadYWHHistory();
      showToast("YesWeHack sync complete!", "success");
    }
    _ywhWasRunning = !!d.running;
    ywhLiveTimer = setTimeout(_pollYWHLive, interval);
  } catch { ywhLiveTimer = setTimeout(_pollYWHLive, 5000); }
}

async function loadYWHView() {
  const d = await fetch("/api/h1/platforms").then(r=>r.json()).catch(()=>({platforms:[]}));
  const el = document.getElementById("ywhStatusPanel");
  if (!el) return;
  const hasYwh = d.platforms.includes("yeswehack");
  el.innerHTML = hasYwh
    ? `<div style="padding:12px;display:flex;align-items:center;gap:10px">
        <div class="dot dot-green" style="width:10px;height:10px"></div>
        <span style="font-size:13px;font-weight:600;color:var(--green)">YesWeHack token configured</span>
       </div>`
    : `<div style="padding:16px;text-align:center">
        <div style="font-size:12px;color:var(--text3);margin-bottom:8px">No YesWeHack token found</div>
        <button class="btn btn-xs btn-ghost" onclick="showView('settings')">→ Add Token in Settings</button>
       </div>`;
}

async function loadYWHHistory() {
  const d = await fetch("/api/sync/history").then(r=>r.json()).catch(()=>[]);
  const el = document.getElementById("ywhHistoryList");
  if (!el) return;
  const items = d.filter(h => (h.platform||"").toLowerCase() === "yeswehack");
  if (!items.length) { el.innerHTML=`<div class="empty" style="padding:20px"><div class="empty-icon">📜</div>No sync history yet</div>`; return; }
  el.innerHTML = items.map(h=>`
    <div class="history-item">
      <div class="history-header">
        <div><span class="badge badge-purple">🟢 YesWeHack</span></div>
        <div style="text-align:right">
          <span class="job-status ${h.status||"running"}">${h.status||"running"}</span>
          <div style="font-size:10px;color:var(--text3);margin-top:2px">${fmtTs(h.started_at)}</div>
        </div>
      </div>
      <div class="history-stats">
        <span>↓ ${fmt(h.imported||0)} imported</span>
        <span style="color:var(--green)">✅ ${fmt(h.scanned||0)} live</span>
        <span style="color:var(--red)">✗ ${fmt(h.failed||0)} failed</span>
      </div>
    </div>`).join("");
}

async function loadYWHProjects() {
  const el = document.getElementById("ywhProjectsList");
  if (!el) return;
  const d = await fetch("/api/projects?source=yeswehack&limit=500&sort=name&order=asc").then(r=>r.json()).catch(()=>({projects:[]}));
  const items = d.projects?.filter(p => (p.platform||"").toLowerCase() === "yeswehack") || [];
  if (!items.length) { el.innerHTML=`<div class="empty"><div class="empty-icon">📭</div>No YesWeHack programs synced yet</div>`; return; }
  el.innerHTML = _buildPrivateProjectsTable(items);
}

async function startYWHSync() {
  if (!confirm("Start YesWeHack private program sync?\n\nThis will:\n• Fetch your private programs via YesWeHack API\n• Enumerate subdomains with subfinder\n• Run 3-phase HTTPX scan")) return;
  try {
    const r = await fetch("/api/sync/yeswehack", {method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({platform:"yeswehack"})}).then(r=>r.json());
    if (r.job_id || r.ok) { showToast("YesWeHack sync started!", "success"); loadYWHHistory(); startYWHLivePoll(); }
    else showToast(r.error || "Failed to start sync", "error");
  } catch(e) { showToast("Error: " + e.message, "error"); }
}

async function testYWHCreds() {
  const el = document.getElementById("settings-ywh-test-result");
  if (el) el.textContent = "Testing…";
  const r = await fetch("/api/h1/test", {method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({platform:"yeswehack"})}).then(r=>r.json()).catch(e=>({ok:false,error:e.message}));
  if (el) {
    el.textContent  = r.ok ? "✓ " + (r.message||"Connected") : "✗ " + (r.error||"Failed");
    el.className    = "cred-test-result " + (r.ok ? "ok" : "fail");
    el.style.color  = "";
  }
}


// Shared function to apply live data for any private platform (h1/ywh)
function _applyPlatformLiveData(d, prefix) {
  const panelId    = prefix === "ywh" ? "ywhLivePanel"    : "h1LivePanel";
  const phaseId    = prefix === "ywh" ? "ywhPhaseLabel"   : "h1PhaseLabel";
  const importId   = prefix === "ywh" ? "ywhImportRow"    : "h1ImportRow";
  const scanId     = prefix === "ywh" ? "ywhScanCounters" : "h1ScanCounters";
  const dbId       = prefix === "ywh" ? "ywhDbCounts"     : "h1DbCounts";
  const projProgId = prefix === "ywh" ? "ywhProjProgress" : "h1ProjProgress";

  const panel = document.getElementById(panelId);
  if (!panel) return;
  const isActive = d.running || (d.phase && d.phase !== "done" && d.phase !== "");
  panel.style.display = isActive ? "block" : "none";
  if (!isActive) return;

  const phase = (d.phase || "").toLowerCase();
  const isImport = phase === "import" || phase === "init";
  const isScan   = phase === "scan";

  const phaseBadgeEl = document.getElementById(phaseId);
  if (phaseBadgeEl) {
    if (isImport) phaseBadgeEl.innerHTML = `<span class="lsp-phase-badge lsp-phase-import">📥 Importing Programs</span>`;
    else if (isScan) phaseBadgeEl.innerHTML = `<span class="lsp-phase-badge lsp-phase-a">⚡ Scanning</span>`;
    else phaseBadgeEl.innerHTML = `<span class="lsp-phase-badge lsp-phase-done">✅ Complete</span>`;
  }

  const importEl = document.getElementById(importId);
  if (importEl) {
    if (isImport) {
      const imp=d.imported||0, tot=d.total_programs||0, pct=tot>0?Math.round(imp/tot*100):0;
      importEl.innerHTML=`<div class="h1-stat-row"><span class="h1-stat-label">📥 Programs Imported</span><span class="h1-stat-val">${fmt(imp)} / ${fmt(tot)}</span>${d.current_program?`<span class="h1-current-prog">↳ ${esc(d.current_program)}</span>`:""}</div><div class="lsp-bar-track" style="margin:4px 0 8px"><div class="lsp-bar-fill" style="width:${pct}%"></div></div>`;
      importEl.style.display = "";
    } else importEl.style.display = "none";
  }

  const scanCountEl = document.getElementById(scanId);
  if (scanCountEl && isScan) {
    const comp=d.completed_scan||0,tot=d.total_scan||0,alive=d.scanned_subs||d.total_alive_db||0,
          deep=d.deep_scanned_subs||0,active=d.active_scans||0,maxC=d.max_concurrent||10,
          scanPct=tot>0?Math.round(comp/tot*100):0;
    scanCountEl.innerHTML=`<div class="h1-counters-grid"><div class="h1-counter-card"><div class="h1-counter-num" style="color:var(--accent)">${fmt(active)}<span style="font-size:11px;color:var(--text3)">/${maxC}</span></div><div class="h1-counter-lbl">Active Scans</div></div><div class="h1-counter-card"><div class="h1-counter-num" style="color:var(--green)">${fmt(alive)}</div><div class="h1-counter-lbl">Live Subs Found</div></div><div class="h1-counter-card"><div class="h1-counter-num" style="color:var(--purple)">${fmt(deep)}</div><div class="h1-counter-lbl">Deep Scanned</div></div><div class="h1-counter-card"><div class="h1-counter-num" style="color:var(--text1)">${fmt(comp)}/${fmt(tot)}</div><div class="h1-counter-lbl">Projects Done${d.scan_eta?" · "+d.scan_eta:""}</div></div></div><div class="lsp-bar-track" style="margin:6px 0 4px"><div class="lsp-bar-fill" style="width:${scanPct}%;background:var(--green)"></div></div>`;
    scanCountEl.style.display = "";
  } else if (scanCountEl) scanCountEl.style.display = "none";

  const dbEl = document.getElementById(dbId);
  if (dbEl && d.db_projects) {
    const dp=d.db_projects;
    dbEl.innerHTML=`<span style="color:var(--accent);font-weight:600">${fmt(dp.total)}</span> total · <span style="color:var(--green)">${fmt(dp.done)}</span> done · <span style="color:var(--yellow)">${fmt(dp.scanning)}</span> scanning · <span style="color:var(--text3)">${fmt(dp.pending)}</span> pending`;
    dbEl.style.display = "";
  }

  // Per-project progress bars
  const projProgEl = document.getElementById(projProgId);
  if (projProgEl && d.project_progress?.length) {
    const ph = {"A":"⚡ Alive","B":"✂ Prune","C":"🔍 Deep"};
    projProgEl.innerHTML = d.project_progress.slice(0,15).map(p=>`
      <div class="lsp-proj-row">
        <div class="lsp-proj-name" title="${esc(p.name)}">${esc(p.name)}</div>
        <div class="lsp-proj-stats">
          <span class="lsp-phase-badge lsp-phase-${p.phase?.toLowerCase()||"a"}">${ph[p.phase]||p.phase}</span>
          <span style="color:var(--green);font-size:11px">${fmt(p.alive)} live</span>
          <span style="font-size:10px;color:var(--text3)">${p.pct}%</span>
        </div>
        <div class="lsp-bar-track"><div class="lsp-bar-fill lsp-bar-alive" style="width:${p.pct}%"></div></div>
      </div>`).join("");
  } else if (projProgEl) projProgEl.innerHTML = "";
}


// ── Theme Toggle ──────────────────────────────────────────────────────────────
function toggleTheme() {
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  const next = isDark ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('submind-theme', next);
  const btn = document.getElementById('themeToggleBtn');
  if (btn) btn.textContent = next === 'dark' ? '☀ Light Mode' : '🌙 Dark Mode';
}
(function applyTheme() {
  const saved = localStorage.getItem('submind-theme') || 'light';
  document.documentElement.setAttribute('data-theme', saved);
  // Button text is set after DOM ready
  window.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('themeToggleBtn');
    if (btn) btn.textContent = saved === 'dark' ? '☀ Light Mode' : '🌙 Dark Mode'; // light=default
  });
})();

// ── Global Search ─────────────────────────────────────────────────────────────
let _searchDebTimer;
let _lastSearchResults = [];

function debGlobalSearch(val) {
  clearTimeout(_searchDebTimer);
  if (val.length >= 2) _searchDebTimer = setTimeout(runGlobalSearch, 300);
}

function quickSearch(term) {
  const inp = document.getElementById('globalSearchInput');
  if (inp) { inp.value = term; runGlobalSearch(); }
}

async function runGlobalSearch() {
  const q    = document.getElementById('globalSearchInput')?.value?.trim();
  const type = document.getElementById('searchType')?.value || 'all';
  const lim  = document.getElementById('searchLimit')?.value || 200;
  const wrap = document.getElementById('searchResultsWrap');
  const cntEl = document.getElementById('searchResultCount');
  if (!q || !wrap) return;

  wrap.innerHTML = `<div class="empty"><span class="spin">⟳</span> Searching…</div>`;
  if (cntEl) cntEl.textContent = '';

  const data = await fetch(`/api/search?q=${encodeURIComponent(q)}&type=${type}&limit=${lim}`)
    .then(r => r.json()).catch(() => ({ results: [] }));
  _lastSearchResults = data.results || [];

  const titleEl = document.getElementById('searchTableTitle');
  if (titleEl) titleEl.textContent = `${_lastSearchResults.length} result${_lastSearchResults.length !== 1 ? 's' : ''} for "${q}"`;
  if (cntEl)   cntEl.textContent = `${_lastSearchResults.length} found`;

  ['searchCopyBtn','searchExportBtn'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = _lastSearchResults.length ? '' : 'none';
  });

  if (!_lastSearchResults.length) {
    wrap.innerHTML = `<div class="empty"><div class="empty-icon">🔭</div>No results for <strong>${esc(q)}</strong></div>`;
    return;
  }

  const rows = _lastSearchResults.map(r => `
    <tr>
      <td><a href="${esc(r.url||'#')}" target="_blank" class="cell-link">${esc(r.subdomain||r.name||'—')}</a></td>
      <td><span class="sc-badge ${scClass(r.status_code)}">${r.status_code||'—'}</span></td>
      <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.title||'—')}</td>
      <td><div class="tech-tags">${techTags(r.tech||'')}</div></td>
      <td style="font-family:var(--mono);font-size:11px">${esc(r.ip||'—')}</td>
      <td style="font-size:12px">${esc(r.project_name||r.program_name||'')}</td>
      <td><button class="btn btn-xs btn-ghost" onclick="showView('projectDetail','${r.project_id||r.id}')">View</button></td>
    </tr>`).join('');

  wrap.innerHTML = `<div class="tbl-wrap"><table class="tbl" style="font-size:12px">
    <thead><tr><th>Subdomain</th><th>Status</th><th>Title</th><th>Tech</th><th>IP</th><th>Project</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

function copySearchResults(mode) {
  if (!_lastSearchResults.length) return;
  const txt = mode === 'urls'
    ? _lastSearchResults.filter(r => r.url).map(r => r.url).join('\n')
    : _lastSearchResults.map(r => r.subdomain).join('\n');
  navigator.clipboard.writeText(txt).then(() => showToast(`Copied ${_lastSearchResults.length} ${mode}`, 'success'));
}

// ── Tools Check ───────────────────────────────────────────────────────────────
async function loadTools() {
  const t = await fetch("/api/tools").then(r=>r.json());
  document.getElementById("toolsList").innerHTML = Object.entries(t).map(([n,ok])=>
    `<div class="tool-row"><div class="tool-dot ${ok?"ok":"bad"}"></div><span>${n}</span>${!ok?'<span class="text-xs text-red" style="margin-left:auto">missing</span>':''}</div>`
  ).join("");
}

// ── Init ──────────────────────────────────────────────────────────────────────
(async function init() {
  await loadTools();
  await refreshStats();
  // NOTE: No global stats interval — each view manages its own polling
  // to avoid hammering the server with redundant requests
  showView("dashboard");
  loadPlatformFilter();

  // Global mini-log poller — adaptive rate: fast when scanning, slow when idle
  let _miniPollActive = true;
  document.addEventListener('visibilitychange', () => { _miniPollActive = !document.hidden; });
  function pollMini() {
    if (document.hidden) { setTimeout(pollMini, 10000); return; }
    fetch(`/api/logs/live?since=${miniLogCursor}`)
      .then(r=>r.json())
      .then(d=>{
        if (d.logs?.length) { miniLogCursor=d.cursor; d.logs.forEach(pushMiniLog); }
        // Slow down to 8s when no new logs; stay at 3s when active
        setTimeout(pollMini, d.logs?.length ? 3000 : 8000);
      }).catch(()=>{ setTimeout(pollMini, 10000); });
  }
  pollMini();
})();

// ══════════════════════════════════════════════════════════════
// SERVER CONTROL TAB
// ══════════════════════════════════════════════════════════════

function startServerPoll() {
  stopServerPoll();
  // 10s is sufficient for server status — it doesn't change second-by-second
  serverPollTimer = setInterval(() => {
    if (!document.hidden) loadServerStatus();
  }, 10000);
}
function stopServerPoll() {
  if (serverPollTimer) { clearInterval(serverPollTimer); serverPollTimer = null; }
}

async function loadServerStatus() {
  let data;
  try { data = await fetch("/api/server/status").then(r=>r.json()); }
  catch(e) { return; }

  // Tool grid
  const grid = document.getElementById("toolGrid");
  if (grid && data.tools) {
    grid.innerHTML = Object.entries(data.tools).map(([n, t]) => `
      <div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px;display:flex;flex-direction:column;gap:4px">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
          <span style="font-size:16px">${t.ok?"✅":"❌"}</span>
          <span style="font-weight:700;font-size:13px">${n}</span>
          ${data.processes?.[n]?.running ? `<span class="badge badge-green" style="font-size:9px;margin-left:auto">RUNNING</span>` : ""}
        </div>
        <div style="font-size:10px;color:var(--text-muted)">${esc(t.desc)}</div>
        <div style="font-family:var(--mono);font-size:9px;color:${t.ok?"var(--green)":"var(--red)"};margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(t.version||"not installed")}</div>
        ${data.processes?.[n]?.running ? `<button class="btn btn-danger-ghost btn-xs" style="margin-top:6px;font-size:10px" onclick="stopTool('${n}')">⏹ Stop</button>` : ""}
      </div>`).join("");
  }

  // Scan state
  const ss = document.getElementById("serverScanState");
  if (ss) {
    const bs = data.bulk_scan || {};
    const as_ = data.active_scans || {};
    ss.innerHTML = `
      <span style="color:var(--text-muted)">Bulk Scan:</span> ${bs.running ? `<span style="color:var(--green)">● Running</span> — ${bs.completed||0}/${bs.total||0} projects | ETA: ${bs.eta||"—"}` : `<span style="color:var(--text-muted)">Idle</span>`}
      &nbsp;&nbsp;|&nbsp;&nbsp;
      <span style="color:var(--text-muted)">Active:</span> ${as_.count||0}/${as_.max||10}
    `;
  }

  // Update backup status from the server/status response (no extra fetch needed)
  if (data.backup) {
    const bk = data.backup;
    const el = document.getElementById("backupStatusText");
    const badge = document.getElementById("autoBackupBadge");
    if (el) {
      if (bk.exists) {
        const ts = bk.updated ? new Date(bk.updated).toLocaleString("en-GB",{dateStyle:"short",timeStyle:"short"}) : "—";
        // FIX: bk.projects / bk.subs come from submind-backup.db directly
        const projCount = (bk.projects||0).toLocaleString();
        const subCount  = (bk.subs||0).toLocaleString();
        el.innerHTML =
          `<span style="color:var(--green);font-weight:700">✓ Backup ready</span>` +
          ` &nbsp;·&nbsp; Saved: <b>${ts}</b>`;
        if (badge) badge.textContent = `💾 submind-backup.db · Last saved: ${new Date(bk.updated).toLocaleTimeString("en-GB",{timeStyle:"short"})}`;

        // Backup DB column — what is RECOVERABLE
        const bkDiv = document.getElementById("backupDbDetails");
        if (bkDiv) {
          bkDiv.innerHTML =
            `<div style="display:flex;justify-content:space-between;font-size:12px"><span style="color:var(--text-muted)">Programs</span><b style="color:var(--green)">${projCount}</b></div>` +
            `<div style="display:flex;justify-content:space-between;font-size:12px"><span style="color:var(--text-muted)">Subdomains</span><b style="color:var(--green)">${subCount}</b></div>` +
            `<div style="display:flex;justify-content:space-between;font-size:12px"><span style="color:var(--text-muted)">File size</span><b>${(bk.size_mb||0).toFixed(1)} MB</b></div>` +
            `<div style="display:flex;justify-content:space-between;font-size:12px"><span style="color:var(--text-muted)">Saved at</span><b>${ts}</b></div>`;
        }

        // Storage breakdown (bottom bar)
        const sb = document.getElementById("storageBreakdown");
        if (sb) {
          sb.style.display = "flex";
          const mainDbMB = (bk.main_db_size_mb||0);
          const backupMB = (bk.size_mb||0);
          const totalMB  = (bk.total_dir_size_mb||0);
          const otherMB  = Math.max(0, totalMB - mainDbMB - backupMB).toFixed(1);
          document.getElementById("storageMain")   && (document.getElementById("storageMain").innerHTML   = `submind.db: <b>${mainDbMB.toFixed(1)} MB</b>`);
          document.getElementById("storageBackup") && (document.getElementById("storageBackup").innerHTML = `submind-backup.db: <b>${backupMB.toFixed(1)} MB</b>`);
          document.getElementById("storageTotal")  && (document.getElementById("storageTotal").innerHTML  = `Other: <b>${otherMB} MB</b> &nbsp;·&nbsp; Total: <b style="color:var(--accent)">${totalMB.toFixed(1)} MB</b>`);
          const noteEl = document.getElementById("storageNote");
          if (noteEl) noteEl.textContent = `Data dir: ~/.submind-pro/`;
        }
      } else {
        el.innerHTML = `<span style="color:var(--text-muted)">No backup file yet — auto-saves every 30s</span>`;
        const bkDiv = document.getElementById("backupDbDetails");
        if (bkDiv) bkDiv.innerHTML = `<div style="font-size:12px;color:var(--text-muted)">No backup file found</div>`;
        const sb = document.getElementById("storageBreakdown");
        if (sb) sb.style.display = "none";
        if (badge) badge.textContent = "Auto-saves every 30s to submind-backup.db";
      }
    }

  // Live DB details — only refresh on initial load or explicit request, not every poll tick
  if (data.backup && !document.getElementById("liveDbDetails")?.dataset.loaded) {
    try {
      const st = await fetch("/api/stats").then(r=>r.json());
      const liveDiv = document.getElementById("liveDbDetails");
      if (liveDiv && st) {
        liveDiv.dataset.loaded = "1";
        const bk = data.backup;
        const lp = (st.projects?.total||0).toLocaleString();
        const ls = (st.subdomains?.total||0).toLocaleString();
        const la = (st.subdomains?.alive||0).toLocaleString();
        const mainMB = bk.main_db_size_mb||0;
        liveDiv.innerHTML =
          `<div style="display:flex;justify-content:space-between;font-size:12px"><span style="color:var(--text-muted)">Programs</span><b style="color:var(--accent)">${lp}</b></div>` +
          `<div style="display:flex;justify-content:space-between;font-size:12px"><span style="color:var(--text-muted)">Subdomains</span><b style="color:var(--accent)">${ls}</b></div>` +
          `<div style="display:flex;justify-content:space-between;font-size:12px"><span style="color:var(--text-muted)">Live hosts</span><b style="color:var(--green)">${la}</b></div>` +
          `<div style="display:flex;justify-content:space-between;font-size:12px"><span style="color:var(--text-muted)">File size</span><b>${mainMB.toFixed(1)} MB</b></div>`;
      }
    } catch(e) {}
  }
  }

  // Append only NEW server logs (ID-based cursor = no index-shift corruption)
  try {
    const ld = await fetch(`/api/server/logs?since=${serverLogCursor}`).then(r=>r.json());
    if (ld.logs?.length) {
      serverLogCursor = ld.cursor;
      serverLogAll = serverLogAll.concat(ld.logs).slice(-SERVER_LOG_MAX_UI);
      appendServerLogs(ld.logs);
    }
  } catch(e) {}
}

const SERVER_LOG_MAX_UI = 500;

function _logEntryHtml(l) {
  const col = {success:"#3fb950",error:"#f85149",warning:"#e3b341",info:"#79c0ff"}[l.level]||"#c9d1d9";
  const ts = l.ts ? l.ts.slice(11,19) : "";
  return `<div style="padding:1px 0;border-bottom:1px solid rgba(255,255,255,.04)">
    <span style="color:#484f58">[${ts}]</span>
    <span style="color:${col};font-weight:600;font-size:10px;margin:0 6px">[${(l.level||"").toUpperCase()}]</span>
    <span style="color:#888;margin-right:6px">[${esc(l.name||"")}]</span>
    <span>${esc(l.message||"")}</span>
  </div>`;
}

// Full rebuild - called on filter change or initial load
function renderServerLogs() {
  const box = document.getElementById("serverLogBox");
  if (!box) return;
  const filter = document.getElementById("serverLogFilter")?.value || "";
  const logs = filter ? serverLogAll.filter(l => l.level === filter) : serverLogAll;
  box.innerHTML = logs.slice().reverse().map(_logEntryHtml).join("");
  box.scrollTop = 0; // newest at top
}

// Incremental append - called on each poll to add only new entries
function appendServerLogs(newLogs) {
  const box = document.getElementById("serverLogBox");
  if (!box) return;
  const filter = document.getElementById("serverLogFilter")?.value || "";
  const toAdd = filter ? newLogs.filter(l => l.level === filter) : newLogs;
  if (!toAdd.length) return;
  // Prepend to top (newest first layout)
  const frag = document.createDocumentFragment();
  toAdd.slice().reverse().forEach(l => {
    const div = document.createElement("div");
    div.innerHTML = _logEntryHtml(l);
    frag.appendChild(div.firstChild);
  });
  box.insertBefore(frag, box.firstChild);
  // Prune excess DOM nodes
  while (box.childElementCount > SERVER_LOG_MAX_UI) box.removeChild(box.lastChild);
}

function filterServerLogs() { renderServerLogs(); }

function copyServerLogs() {
  const text = serverLogAll.map(l=>`[${l.ts?.slice(11,19)||""}] [${l.level?.toUpperCase()}] [${l.name}] ${l.message}`).join("\n");
  navigator.clipboard?.writeText(text).then(()=>showToast("Logs copied","success")).catch(()=>showToast("Copy failed","error"));
}

function downloadServerLogs() {
  const text = serverLogAll.map(l=>`[${l.ts||""}] [${l.level?.toUpperCase()}] [${l.name}] ${l.message}`).join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], {type:"text/plain"}));
  a.download = `submind-server-log-${new Date().toISOString().slice(0,10)}.txt`;
  a.click();
}

async function clearServerLogs() {
  if (!confirm("Clear server activity logs?")) return;
  await fetch("/api/server/logs/clear", {method:"POST"});
  serverLogAll = []; serverLogCursor = 0;
  const box = document.getElementById("serverLogBox");
  if (box) box.innerHTML = "";
  showToast("Server logs cleared","success");
}

async function stopTool(name) {
  if (!confirm(`Stop tool process: ${name}?`)) return;
  const r = await fetch(`/api/server/tool/${name}/stop`, {method:"POST"}).then(r=>r.json());
  if (r.ok) showToast(`Stopped ${name}`,"success");
  else showToast("Error: "+(r.error||"unknown"),"error");
  loadServerStatus();
}

async function stopAllScans() {
  if (!confirm("Stop all active scans and kill tracked processes?\n\nThis will terminate ALL running httpx, nuclei, subfinder processes and reset stuck projects to pending.")) return;
  showToast("🛑 Stopping all scans…","warning",3000);
  try {
    const r = await fetch("/api/server/scans/stop",{method:"POST"}).then(r=>r.json());
    if (r.ok) showToast(`🛑 All scans stopped (${r.stopped_procs} processes killed)`,"warning",5000);
    else showToast("Error stopping scans: "+(r.error||"unknown"),"error");
  } catch(e) { showToast("Network error stopping scans","error"); }
  setTimeout(loadServerStatus, 1000);
}

async function resumeScans() {
  if (!confirm("Resume all pending scans?\n\nThis will start concurrent recon + nuclei for all pending projects.")) return;
  showToast("▶ Triggering scan resume…","info",3000);
  try {
    const r = await fetch("/api/server/scans/resume",{method:"POST"}).then(r=>r.json());
    if (r.ok) showToast(`▶ Resumed ${r.queued} projects — check Live Logs for progress`,"success",5000);
    else showToast("Error: "+(r.error||"unknown"),"error");
  } catch(e) { showToast("Network error resuming scans","error"); }
  setTimeout(loadServerStatus, 2000);
}

async function restartServer() {
  if (!confirm("Restart the SUBMIND server? The page will reload automatically once it comes back online.")) return;
  showToast("🔄 Restarting server…","warning",8000);
  const box = document.getElementById("serverLogBox");
  if (box) box.insertAdjacentHTML("afterbegin", `<div style="color:#e3b341;padding:6px 2px;border-bottom:1px solid rgba(255,255,255,.06)">🔄 [${new Date().toLocaleTimeString()}] Server restart requested — waiting for restart…</div>`);
  try { await fetch("/api/server/restart",{method:"POST"}); } catch(e) {}
  // Poll until server is back — don't just blindly reload after a fixed delay
  _waitForServerAndReload();
}





async function restoreFromBackup() {
  // FIX: fetch backup counts from backup DB so confirm shows recoverable data
  let bkInfo = "";
  try {
    const status = await fetch("/api/server/status").then(r=>r.json());
    const bk = status.backup || {};
    if (bk.exists) {
      const ts = bk.updated ? new Date(bk.updated).toLocaleString("en-GB",{dateStyle:"medium",timeStyle:"short"}) : "unknown";
      // bk.projects / bk.subs now come from submind-backup.db directly
      bkInfo = `\n\n📦 Will restore from submind-backup.db:\n   ${(bk.projects||0).toLocaleString()} programs · ${(bk.subs||0).toLocaleString()} subdomains\n🕐 Backup saved: ${ts}`;
    } else {
      showToast("❌ No backup file found. Cannot restore.", "error", 6000);
      return;
    }
  } catch(e) {}

  if (!confirm(`⚠️  RESTORE FROM BACKUP\n\nThis will OVERWRITE the current live database with submind-backup.db.\nAny data added or changed after the last backup will be lost.${bkInfo}\n\nThe server will auto-restart after restore.\nThis page will reload automatically.\n\nAre you sure?`)) return;

  const btn = document.querySelector("[onclick='restoreFromBackup()']");
  if (btn) { btn.disabled = true; btn.textContent = "⏳ Restoring…"; }

  showToast("📤 Restoring from backup — please wait…","warning",10000);

  let result;
  try {
    result = await fetch("/api/backup/restore", {method:"POST"}).then(r=>r.json());
  } catch(e) {
    // Network error = server restarted (expected)
    result = {ok: true, _network_error: true};
  }

  if (result.ok || result._network_error) {
    const projs = result.projects_restored || "?";
    const subs  = result.subdomains_restored ? result.subdomains_restored.toLocaleString() : null;
    const rdesc = subs ? `${String(projs)} programs / ${subs} assets` : `${projs} programs`;
    showToast(`Restore complete: ${rdesc}. Server restarting…`, "success", 8000);
    const box = document.getElementById("serverLogBox");
    if (box) box.innerHTML = `<div style="color:#e3b341;padding:8px">🔄 Server restarting after restore… page will reload automatically.</div>`;
    _waitForServerAndReload();
  } else {
    showToast("❌ Restore failed: "+(result.error||"unknown error"),"error",8000);
    if (btn) { btn.disabled = false; btn.textContent = "📤 Restore from Backup"; }
  }
}

function _waitForServerAndReload(attempts=0) {
  if (attempts > 30) { location.reload(); return; }  // give up after 15s and reload
  setTimeout(async () => {
    try {
      const r = await fetch("/api/stats", {signal: AbortSignal.timeout(2000)});
      if (r.ok) { location.reload(); return; }
    } catch(e) {}
    _waitForServerAndReload(attempts + 1);
  }, 500);
}

// ══════════════════════════════════════════════════════════════════════════════
// SUBMIND PRO v7.0 — Beast Mode JavaScript
// ══════════════════════════════════════════════════════════════════════════════

// Router additions merged into main showView above
// ── Global alert badge polling ─────────────────────────────────────────────
let _alertBadgeTimer = null;
function startAlertBadgePoll() {
  if (_alertBadgeTimer) return;
  // 30s interval — alerts don't need real-time updates
  _alertBadgeTimer = setInterval(() => {
    if (!document.hidden) refreshAlertBadge();
  }, 30000);
  refreshAlertBadge();
}
async function refreshAlertBadge() {
  try {
    const d = await fetch('/api/alerts/count').then(r=>r.json());
    const c = d.unread || 0;
    const badge = document.getElementById('alertBadgeNav');
    const topEl  = document.getElementById('tk-alerts');
    if (badge) { badge.textContent = c; badge.style.display = c > 0 ? '' : 'none'; }
    if (topEl) topEl.textContent = c > 0 ? c : '—';
    // Monitor dot — use field from alert count if available, else skip extra fetch
    if (d.monitor_running !== undefined) {
      const dot = document.getElementById('monitorNavDot');
      if (dot) dot.style.display = d.monitor_running ? '' : 'none';
    }
    // Review badge — use field from alert count if available
    const rb = document.getElementById('reviewBadgeNav');
    if (rb && d.review_pending !== undefined) {
      rb.textContent = d.review_pending;
      rb.style.display = d.review_pending > 0 ? '' : 'none';
    } else if (rb) {
      // Only fetch separately if the alert endpoint doesn't include it
      const rv = await fetch('/api/review/queue').then(r=>r.json());
      const rc = rv.total || 0;
      rb.textContent = rc; rb.style.display = rc > 0 ? '' : 'none';
    }
  } catch(e) {}
}

// ── Monitor view ──────────────────────────────────────────────────────────────
let _monitorPollTimer = null;
function startMonitorPoll() { if (!_monitorPollTimer) _monitorPollTimer = setInterval(loadMonitorStatus, 8000); }
function stopMonitorPoll()  { clearInterval(_monitorPollTimer); _monitorPollTimer = null; }

async function loadMonitorStatus() {
  try {
    const [ms, ts] = await Promise.all([
      fetch('/api/monitor/status').then(r=>r.json()),
      fetch('/api/templates/status').then(r=>r.json()),
    ]);
    renderMonitorKpis(ms, ts);
    renderMonitorStatus(ms);
    renderTemplateStatus(ts);
    renderMonitorRuns(ms.recent_runs || []);
  } catch(e) { console.error('Monitor status error', e); }
}

function renderMonitorKpis(ms, ts) {
  const kpis = [
    { label:'Status',       value: ms.running ? '<span class="dot dot-green pulse"></span> RUNNING' : 'Idle', raw:true },
    { label:'Projects Checked', value: fmt(ms.projects_checked||0) },
    { label:'New Subs Found',   value: fmt(ms.new_subs_total||0), accent:true },
    { label:'Templates',        value: fmt(ts.count||0) },
    { label:'Last Tick',        value: ms.last_tick ? timeAgo(ms.last_tick) : '—' },
    { label:'Next Tick',        value: ms.next_tick ? timeAgo(ms.next_tick, true) : '—' },
    { label:'Sweep',        value: ms.sweep_running ? '<span class="dot dot-yellow pulse"></span> RUNNING' : 'Idle', raw:true },
    { label:'Template Delta',   value: ts.last_update ? (ts.last_update.delta >= 0 ? '+' : '') + ts.last_update.delta : '—' },
  ];
  document.getElementById('monitorKpis').innerHTML = kpis.map(k=>
    `<div class="kpi-card"><div class="kpi-val ${k.accent?'kpi-accent':''}">${k.raw?k.value:k.value}</div><div class="kpi-label">${k.label}</div></div>`
  ).join('');
}

function renderMonitorStatus(ms) {
  const el = document.getElementById('monitorStatusBody');
  if (!el) return;
  const rows = [
    ['Monitor Enabled',  ms.running !== undefined ? 'Yes' : 'Unknown'],
    ['Last Tick',        ms.last_tick ? new Date(ms.last_tick).toLocaleString() : 'Never'],
    ['Next Tick',        ms.next_tick ? new Date(ms.next_tick).toLocaleString() : '—'],
    ['Projects Checked', fmt(ms.projects_checked||0)],
    ['Total New Subs',   fmt(ms.new_subs_total||0)],
    ['Sweep Running',    ms.sweep_running ? '🟡 Yes' : '✅ No'],
  ];
  el.innerHTML = `<table class="tbl"><tbody>${rows.map(([k,v])=>
    `<tr><td class="text-dim" style="width:50%">${k}</td><td><b>${v}</b></td></tr>`
  ).join('')}</tbody></table>`;
}

function renderTemplateStatus(ts) {
  const el = document.getElementById('templateStatusBody');
  if (!el) return;
  const lu = ts.last_update;
  el.innerHTML = `
    <div style="font-size:28px;font-weight:700;margin-bottom:4px">${fmt(ts.count||0)}</div>
    <div class="text-dim text-sm" style="margin-bottom:12px">Nuclei templates installed</div>
    ${lu ? `
    <div class="text-sm"><b>Last update:</b> ${new Date(lu.updated_at).toLocaleString()}</div>
    <div class="text-sm"><b>Delta:</b> <span style="color:${lu.delta>0?'var(--green)':'var(--text-dim)'}">${lu.delta >= 0 ? '+' : ''}${lu.delta}</span></div>
    <div class="text-sm"><b>Sweep triggered:</b> ${lu.sweep_triggered ? '✅ Yes' : 'No'}</div>
    ` : '<div class="text-dim text-sm">No updates recorded yet</div>'}
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn btn-secondary btn-sm" onclick="updateTemplates()">📦 Update Now</button>
      <button class="btn btn-ghost btn-sm" onclick="triggerSweep()">🔄 Sweep (-nt)</button>
    </div>`;
}

function renderMonitorRuns(runs) {
  const tb = document.getElementById('monitorRunsTbl');
  if (!tb) return;
  if (!runs.length) { tb.innerHTML = '<tr><td colspan="5" class="text-dim" style="text-align:center;padding:12px">No runs yet</td></tr>'; return; }
  tb.innerHTML = runs.map(r => {
    const dur = r.completed_at && r.started_at
      ? Math.round((new Date(r.completed_at)-new Date(r.started_at))/1000) + 's'
      : r.status === 'running' ? '<span class="dot dot-green pulse"></span> running' : '—';
    return `<tr>
      <td class="text-sm">${new Date(r.started_at).toLocaleString()}</td>
      <td>${dur}</td>
      <td>${fmt(r.projects_checked||0)}</td>
      <td><b style="color:${(r.new_subs_found||0)>0?'var(--accent)':'inherit'}">${fmt(r.new_subs_found||0)}</b></td>
      <td><span class="badge ${r.status==='done'?'badge-green':r.status==='running'?'badge-accent':'badge-red'}">${r.status}</span></td>
    </tr>`;
  }).join('');
}

async function triggerMonitor() {
  const btn = document.getElementById('monitorStartBtn');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Triggering…'; }
  try {
    await fetch('/api/monitor/trigger', {method:'POST'});
    showToast('Monitor tick triggered!', 'success');
    setTimeout(loadMonitorStatus, 2000);
  } catch(e) { showToast('Error triggering monitor', 'error'); }
  finally { if (btn) { btn.disabled = false; btn.textContent = '⚡ Trigger Now'; } }
}

async function updateTemplates() {
  showToast('Updating nuclei templates…', 'info');
  await fetch('/api/templates/update', {method:'POST'});
  setTimeout(loadMonitorStatus, 3000);
}

async function triggerSweep() {
  showToast('Starting new-template sweep (-nt)…', 'info');
  await fetch('/api/templates/sweep', {method:'POST'});
  setTimeout(loadMonitorStatus, 2000);
}

// ── Alerts view ───────────────────────────────────────────────────────────────
async function loadAlerts() {
  try {
    const d = await fetch('/api/alerts?limit=100').then(r=>r.json());
    const badge = document.getElementById('alertsCountBadge');
    if (badge) badge.textContent = d.total || 0;
    renderAlerts(d.alerts || []);
  } catch(e) {}
}

function renderAlerts(alerts) {
  const el = document.getElementById('alertsWrap');
  if (!el) return;
  if (!alerts.length) {
    el.innerHTML = '<div class="empty"><div class="empty-icon">🔔</div>No alerts yet</div>';
    return;
  }
  const sevColor = {critical:'#ef4444',high:'#f97316',medium:'#f59e0b',low:'#22c55e',info:'#3b82f6'};
  el.innerHTML = alerts.map(a => {
    let detail = {};
    let detailText = '';
    if (a.detail) {
      if (typeof a.detail === 'object') { detail = a.detail; }
      else if (typeof a.detail === 'string') {
        try { detail = JSON.parse(a.detail); }
        catch(e) { detailText = a.detail; }
      }
    }
    const color = sevColor[a.severity] || '#6b7280';
    return `<div class="card" style="margin-bottom:8px;padding:12px 16px;border-left:3px solid ${color};opacity:${a.seen?0.6:1}">
      <div style="display:flex;justify-content:space-between;align-items:flex-start">
        <div style="min-width:0;flex:1">
          <div style="font-weight:600;margin-bottom:4px">${escHtml(a.title)}</div>
          <div class="text-dim text-sm">${escHtml(a.alert_type)} · ${timeAgo(a.created_at)}
          ${a.project_id ? ` · <a href="#" onclick="showView('projectDetail','${a.project_id}');return false" class="link-dim">View Project</a>` : ''}
          ${a.vuln_id ? ` · <a href="#" onclick="openReviewItem(${a.vuln_id});return false" class="link-dim">Review Finding</a>` : ''}
          </div>
          ${detail.subdomains ? `<div class="text-sm" style="margin-top:6px">${detail.subdomains.slice(0,5).map(s=>escHtml(s)).join(', ')}${detail.count>5?' <span class="text-dim">+more</span>':''}</div>` : ''}
          ${detailText ? `<div class="text-sm text-dim" style="margin-top:4px;word-break:break-all">${escHtml(detailText)}</div>` : ''}
        </div>
        <div style="display:flex;gap:6px;align-items:center;flex-shrink:0;margin-left:12px">
          <span class="badge" style="background:${color}20;color:${color}">${escHtml(a.severity||'info')}</span>
          ${!a.seen ? `<button class="btn btn-xs btn-ghost" onclick="markAlertSeen(${a.id},this)">✓ Mark read</button>` : ''}
        </div>
      </div>
    </div>`;
  }).join('');
}

async function markAlertSeen(id, btn) {
  await fetch(`/api/alerts/${id}/seen`, {method:'POST'});
  if (btn) btn.closest('.card').style.opacity = '0.5';
  refreshAlertBadge();
}

async function markAllAlertsSeen() {
  await fetch('/api/alerts/seen-all', {method:'POST'});
  loadAlerts(); refreshAlertBadge();
}

// ── Bug Review Queue ──────────────────────────────────────────────────────────
let _reviewItems = [];

async function loadReviewQueue() {
  try {
    const d = await fetch('/api/review/queue').then(r=>r.json());
    _reviewItems = d.queue || [];
    const badge = document.getElementById('reviewQueueBadge');
    if (badge) badge.textContent = d.total || 0;
    renderReviewQueue(_reviewItems);
  } catch(e) {}
}

function renderReviewQueue(items) {
  const el = document.getElementById('reviewQueueWrap');
  if (!el) return;
  if (!items.length) {
    el.innerHTML = '<div class="empty"><div class="empty-icon">✅</div>Queue empty — no pending findings</div>';
    return;
  }
  const sevColor = {critical:'#ef4444',high:'#f97316',medium:'#f59e0b',low:'#22c55e',info:'#6b7280'};
  el.innerHTML = items.map(v => {
    const color = sevColor[v.severity] || '#6b7280';
    const platform = (v.source||v.platform||'').toLowerCase();
    const platLabel = platform.includes('yeswehack') ? 'YWH' : platform.includes('hackerone') ? 'H1' : platform.toUpperCase();
    return `<div class="card" id="review_card_${v.id}" style="margin-bottom:10px;border-left:3px solid ${color}">
      <div style="padding:12px 16px">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
          <div style="flex:1;min-width:0">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">
              <span class="badge" style="background:${color}20;color:${color}">${v.severity||'?'}</span>
              <span class="badge badge-ghost">${escHtml(v.template_id||'')}</span>
              ${platLabel ? `<span class="badge badge-accent">${platLabel}</span>` : ''}
            </div>
            <div style="font-weight:600;font-size:15px;margin-bottom:4px">${escHtml(v.name||'')}</div>
            <div class="text-sm text-dim" style="margin-bottom:4px">
              <a href="${escHtml(v.matched_at||v.url||'')}" target="_blank" rel="noopener" class="link-dim">${escHtml(v.matched_at||v.url||'')}</a>
            </div>
            <div class="text-sm text-dim">${escHtml(v.project_name||'')} · ${timeAgo(v.created_at)}</div>
            ${v.description ? `<details style="margin-top:8px"><summary class="text-sm" style="cursor:pointer;color:var(--text-dim)">Description</summary><div class="text-sm" style="margin-top:6px;padding:8px;background:var(--bg-card-alt,#1a1a2e);border-radius:4px">${escHtml(v.description)}</div></details>` : ''}
            ${v.curl_cmd ? `<details style="margin-top:4px"><summary class="text-sm" style="cursor:pointer;color:var(--text-dim)">PoC / curl</summary><pre class="code-pre" style="margin-top:6px;font-size:11px;overflow-x:auto">${escHtml(v.curl_cmd)}</pre></details>` : ''}
          </div>
          <div style="display:flex;flex-direction:column;gap:6px;flex-shrink:0;min-width:90px">
            <button class="btn btn-accent btn-sm" onclick="reportVuln(${v.id})">📤 Report</button>
            <button class="btn btn-danger-ghost btn-sm" onclick="declineVuln(${v.id})">✕ Decline</button>
          </div>
        </div>
        <div style="margin-top:8px">
          <input type="text" class="fi fi-sm" id="notes_${v.id}" placeholder="Researcher notes…"
            value="${escHtml(v.researcher_notes||'')}" style="width:100%;max-width:500px"
            onblur="saveNotes(${v.id},this.value)">
        </div>
      </div>
    </div>`;
  }).join('');
}

async function reportVuln(vid) {
  const notes = document.getElementById(`notes_${vid}`)?.value || '';
  const card = document.getElementById(`review_card_${vid}`);
  if (card) {
    card.style.opacity = '0.6';
    card.querySelector('.btn-accent').textContent = '⏳ Submitting…';
    card.querySelector('.btn-accent').disabled = true;
  }
  try {
    const r = await fetch(`/api/review/${vid}/report`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({notes})
    }).then(r=>r.json());
    if (r.ok) {
      showToast(`✅ Reported! ${r.report_url ? `<a href="${r.report_url}" target="_blank">View Report</a>` : ''}`, 'success', 6000);
      if (card) card.remove();
    } else {
      showToast(`❌ Submit failed: ${r.error}`, 'error', 8000);
      if (card) { card.style.opacity = '1'; card.querySelector('.btn-accent').textContent = '📤 Report'; card.querySelector('.btn-accent').disabled = false; }
    }
  } catch(e) {
    showToast(`Error: ${e.message}`, 'error');
    if (card) { card.style.opacity = '1'; }
  }
  refreshAlertBadge();
}

async function declineVuln(vid) {
  if (!confirm('Decline and remove this finding?')) return;
  await fetch(`/api/review/${vid}/decline`, {method:'POST'});
  const card = document.getElementById(`review_card_${vid}`);
  if (card) card.remove();
  showToast('Finding declined', 'info');
  refreshAlertBadge();
}

async function saveNotes(vid, notes) {
  await fetch(`/api/review/${vid}/notes`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({notes})
  });
}

async function openReviewItem(vid) {
  showView('review');
  setTimeout(() => {
    const card = document.getElementById(`review_card_${vid}`);
    if (card) card.scrollIntoView({behavior:'smooth',block:'center'});
  }, 500);
}

// ── Toast notifications (duplicate removed — showToast defined at line 197) ──

// ── Enhanced settings — new fields ───────────────────────────────────────────
function renderMonitorSettings(s) {
  return `
  <div class="card" style="margin-top:14px">
    <div class="card-hdr"><div class="card-hdr-title">🔄 Beast Mode — 24/7 Monitor</div></div>
    <div style="padding:14px 16px;display:grid;gap:12px">
      <div class="fi-group">
        <label class="fi-label">Monitor Enabled</label>
        <select class="fi" id="s_monitor_enabled">
          <option value="true" ${s.monitor_enabled?'selected':''}>Enabled</option>
          <option value="false" ${!s.monitor_enabled?'selected':''}>Disabled</option>
        </select>
      </div>
      <div class="fi-group">
        <label class="fi-label">Monitor Interval (minutes)</label>
        <input type="number" class="fi" id="s_monitor_interval" value="${s.monitor_interval_min||60}" min="5" max="1440">
      </div>
      <div class="fi-group">
        <label class="fi-label">Template Update Interval (hours)</label>
        <input type="number" class="fi" id="s_tmpl_interval" value="${s.template_update_interval_hours||6}" min="1" max="72">
      </div>
      <div class="fi-group">
        <label class="fi-label">Auto-nuclei on New Subs</label>
        <select class="fi" id="s_auto_nuclei">
          <option value="true" ${s.auto_nuclei_on_new_subs?'selected':''}>Yes (recommended)</option>
          <option value="false" ${!s.auto_nuclei_on_new_subs?'selected':''}>No</option>
        </select>
      </div>
      <div class="fi-group">
        <label class="fi-label">Skip Info Severity in Auto-Nuclei</label>
        <select class="fi" id="s_nuclei_skip_info">
          <option value="true" ${s.nuclei_skip_info?'selected':''}>Yes (faster, less noise)</option>
          <option value="false" ${!s.nuclei_skip_info?'selected':''}>No (all severities)</option>
        </select>
      </div>
    </div>
  </div>
  <div class="card" style="margin-top:14px">
    <div class="card-hdr"><div class="card-hdr-title">🔔 Notifications</div></div>
    <div style="padding:14px 16px;display:grid;gap:12px">
      <div class="fi-group">
        <label class="fi-label">Discord Webhook URL</label>
        <input type="url" class="fi" id="s_discord_webhook" value="${s.discord_webhook_url||''}" placeholder="https://discord.com/api/webhooks/…">
      </div>
      <div class="fi-group">
        <label class="fi-label">Slack Webhook URL</label>
        <input type="url" class="fi" id="s_slack_webhook" value="${s.slack_webhook_url||''}" placeholder="https://hooks.slack.com/…">
      </div>
      <div class="fi-group">
        <label class="fi-label">Telegram Bot Token</label>
        <input type="text" class="fi" id="s_tg_token" value="${s.telegram_bot_token||''}" placeholder="123456:ABC-DEF…">
      </div>
      <div class="fi-group">
        <label class="fi-label">Telegram Chat ID</label>
        <input type="text" class="fi" id="s_tg_chat" value="${s.telegram_chat_id||''}" placeholder="-100123456789">
      </div>
    </div>
  </div>`;
}

// Patch the existing saveSettings function to include new fields
const _origSaveSettings = typeof saveSettings !== 'undefined' ? saveSettings : null;
// saveSettings — single unified version (reads from actual UI element IDs)
async function saveSettings() {
  const g  = id=>document.getElementById(id)?.value||"";
  const gb = id=>!!document.getElementById(id)?.checked;
  const gi = id=>parseInt(document.getElementById(id)?.value)||0;
  const settings = {
    max_concurrent_scans: gi("sConcurrent"),
    httpx_threads:        gi("sThreads"),
    httpx_timeout:        gi("sTimeout"),
    httpx_rate_limit:     gi("sRateLimit"),
    httpx_batch_size:     gi("sBatchSize"),
    httpx_ports:          g("sPorts"),
    httpx_screenshot:     gb("sScreenshot"),
    remove_dead_subdomains:gb("sRemoveDead"),
    auto_sync_enabled:    gb("sAutoSync"),
    sync_interval_hours:  gi("sInterval"),
    auto_sync_platform:   g("sAutoPlatform")||null,
    auto_sync_bounty_only:gb("sAutoBounty"),
    import_limit:         gi("sImportLimit"),
    skip_existing:        gb("sSkipExisting"),
    nuclei_threads:       gi("sNucThreads"),
    subfinder_threads:    gi("sSfThreads"),
    bbscope_hackerone_username: g("sH1Username"),
    bbscope_hackerone_token:    g("sH1Token"),
    bbscope_bugcrowd_email:     g("sBCEmail"),
    bbscope_bugcrowd_password:  g("sBCPassword"),
    bbscope_yeswehack_token:    g("sYwhToken"),
    h1_username:           g("sH1Username"),
    h1_token:              g("sH1Token"),
    ywh_token:             g("sYwhToken"),
  };
  // Beast Mode v7 fields (only include if elements exist)
  const beastFields = {
    monitor_enabled:            "s_monitor_enabled",
    monitor_interval_min:       "s_monitor_interval",
    template_update_interval_hours: "s_tmpl_interval",
    auto_nuclei_on_new_subs:    "s_auto_nuclei",
    nuclei_skip_info:           "s_nuclei_skip_info",
    discord_webhook_url:        "s_discord_webhook",
    slack_webhook_url:          "s_slack_webhook",
    telegram_bot_token:         "s_tg_token",
    telegram_chat_id:           "s_tg_chat",
  };
  for (const [key, elId] of Object.entries(beastFields)) {
    const el = document.getElementById(elId);
    if (el) {
      const v = el.value;
      if (v === 'true') settings[key] = true;
      else if (v === 'false') settings[key] = false;
      else if (v && !isNaN(v)) settings[key] = parseInt(v);
      else if (v) settings[key] = v;
    }
  }

  try {
    const r = await fetch('/api/settings', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(settings)}).then(r=>r.json());
    if (r.ok) {
      showToast('Settings saved successfully', 'success');
      maxConcurrentScans = settings.max_concurrent_scans;
      // Refresh stats to reflect new settings
      setTimeout(refreshStats, 500);
    }
    else showToast('Save failed — check values', 'error');
  } catch(e) { showToast('Error saving settings', 'error'); }
}

// loadSettings is merged above (Beast Mode fields included)

// ── Patch loadDashboard to show alert count ───────────────────────────────────
const _origLoadDashboard = typeof loadDashboard !== 'undefined' ? loadDashboard : null;
// Hook into the live stats polling
const _origUpdateLiveStats = window.updateLiveStats;
window.updateLiveStats = async function() {
  if (typeof _origUpdateLiveStats === 'function') await _origUpdateLiveStats();
  try {
    const d = await fetch('/api/stats/live').then(r=>r.json());
    // Update alert badge in topbar
    const n = d.unread_alerts || 0;
    const el = document.getElementById('tk-alerts');
    if (el) el.textContent = n > 0 ? n : '—';
    el && (el.style.color = n > 0 ? 'var(--red,#ef4444)' : '');
    // Monitor dot
    const mon = d.monitor || {};
    const dot = document.getElementById('monitorNavDot');
    if (dot) dot.style.display = mon.running ? '' : 'none';
  } catch(e) {}
};

// ── Helper: format number ─────────────────────────────────────────────────────
// fmt() defined above


// ── Helper: time ago ──────────────────────────────────────────────────────────
function timeAgo(iso, future=false) {
  if (!iso) return '—';
  const diff = (new Date(iso) - new Date()) * (future ? 1 : -1);
  const abs = Math.abs(diff);
  if (abs < 60000)   return future ? 'soon' : 'just now';
  if (abs < 3600000) return `${Math.round(abs/60000)}m ${future?'from now':'ago'}`;
  if (abs < 86400000)return `${Math.round(abs/3600000)}h ${future?'from now':'ago'}`;
  return `${Math.round(abs/86400000)}d ${future?'from now':'ago'}`;
}

// ── Helper: escHtml ───────────────────────────────────────────────────────────
function escHtml(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ── Visibility API — pause all polling when tab is hidden ──
let _tabVisible = true;
document.addEventListener("visibilitychange", () => {
  _tabVisible = !document.hidden;
  if (_tabVisible && currentView === "dashboard") {
    loadDashboard(); // Refresh immediately when tab becomes visible
  }
});

// ── Startup ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startAlertBadgePoll();
});
// Also start if DOM already ready
if (document.readyState !== 'loading') startAlertBadgePoll();

// ── CSS for new elements (injected into <head>) ───────────────────────────────
(function() {
  const style = document.createElement('style');
  style.textContent = `
    @keyframes slideIn { from { transform:translateX(40px); opacity:0 } to { transform:translateX(0); opacity:1 } }
    @keyframes fadeOut { from { opacity:1 } to { opacity:0 } }
    .badge-red    { background:#ef444420; color:#ef4444; }
    .badge-green  { background:#22c55e20; color:#22c55e; }
    .badge-ghost  { background:var(--border,rgba(255,255,255,.1)); color:var(--text-dim); }
    .link-dim     { color:var(--text-dim); text-decoration:underline; }
    .link-dim:hover { color:var(--text); }
    .code-pre     { background:var(--bg-card-alt,#111827); border-radius:6px; padding:10px 12px;
                    font-family:monospace; white-space:pre-wrap; word-break:break-all; }
    .kpi-accent   { color:var(--accent,#6366f1)!important; }
    .dot-yellow   { background:#f59e0b; }
    #toastContainer a { color:#fff; text-decoration:underline; }
    .grid-2       { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
    @media(max-width:768px) { .grid-2 { grid-template-columns:1fr; } }
  `;
  document.head.appendChild(style);
})();

// ── Beast Mode Settings Helpers ───────────────────────────────────────────────
async function saveBeastModeSettings() {
  const g = id => document.getElementById(id)?.value || '';
  const payload = {
    monitor_enabled:                 document.getElementById('s_monitor_enabled')?.value === 'true',
    monitor_interval_min:            parseInt(g('s_monitor_interval')) || 60,
    template_update_interval_hours:  parseInt(g('s_tmpl_interval')) || 6,
    auto_nuclei_on_new_subs:         document.getElementById('s_auto_nuclei')?.value === 'true',
    nuclei_skip_info:                document.getElementById('s_nuclei_skip_info')?.value === 'true',
    // FE-12 FIX: webhook fields removed from Beast Mode save.
    // Notification webhooks are saved separately in saveNotificationSettings()
    // to prevent Beast Mode saves from blanking out webhook URLs when the user
    // hasn't visited the Notifications tab in the same session.
  };
  try {
    const r = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (r.ok) showToast('Beast Mode settings saved', 'success');
    else showToast('Error saving settings', 'error');
  } catch(e) { showToast('Error saving settings', 'error'); }
}

async function testNotifications() {
  // Send a test notification via the settings save + a dedicated test ping
  // Attempt the endpoint; if 404, fall back to informing the user to check webhooks
  try {
    const r = await fetch('/api/notifications/test', { method: 'POST' });
    if (r.status === 404) {
      showToast('Save your webhook URLs first, then notifications fire automatically on new findings.', 'info', 5000);
      return;
    }
    const d = await r.json().catch(() => ({}));
    if (r.ok) showToast(d.message || 'Test notification sent!', 'success');
    else showToast(d.error || 'Test failed — check your webhook URLs in Settings', 'warning');
  } catch(e) {
    showToast('Could not reach server', 'error');
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// SUBMIND PRO v7.2 — NEW FEATURES
// SSE Real-time Stats, API Key Management, Threat Intelligence, CLI Support
// ══════════════════════════════════════════════════════════════════════════════

// ── SSE Real-time Stats ──────────────────────────────────────────────────────
let _sseSource = null;
function connectSSE() {
  if (_sseSource) _sseSource.close();
  try {
    _sseSource = new EventSource("/api/stats/stream");
    _sseSource.onmessage = (e) => {
      try {
        const d = JSON.parse(e.data);
        if (d.error) return;
        // Update topbar live stats from SSE
        const tkP = document.getElementById("tk-proj");
        if (tkP) animateCounter(tkP, d.programs || 0);
        const tkA = document.getElementById("tk-alive");
        if (tkA) animateCounter(tkA, d.alive || 0);
        const tkV = document.getElementById("tk-vulns");
        if (tkV) animateCounter(tkV, d.vulnerabilities || 0);
        const tkAl = document.getElementById("tk-alerts");
        if (tkAl) { const n = d.alerts||0; tkAl.textContent = n>0?n:'—'; }
      } catch {}
    };
    _sseSource.onerror = () => {
      _sseSource.close(); _sseSource = null;
      setTimeout(connectSSE, 15000); // Reconnect after 15s
    };
  } catch { /* SSE not supported, polling fallback already active */ }
}
// Connect SSE on load (supplements existing polling, doesn't replace it)
setTimeout(connectSSE, 2000);

// ── API Key Management ──────────────────────────────────────────────────────
async function loadApiKeys() {
  const el = document.getElementById("apiKeysList");
  if (!el) return;
  try {
    const keys = await fetch("/api/keys").then(r => r.json());
    if (!keys.length) {
      el.innerHTML = `<div class="empty" style="padding:16px;text-align:center"><div class="empty-icon">🔑</div>No API keys yet. Click "Generate Key" to create one.</div>`;
      return;
    }
    el.innerHTML = keys.map(k => `
      <div class="card" style="margin-bottom:8px;padding:12px 16px;opacity:${k.active?1:0.5}">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div>
            <div style="font-weight:600;font-size:13px">${esc(k.name)}</div>
            <div style="font-family:monospace;font-size:11px;color:var(--text3);margin-top:4px">${esc(k.key.slice(0,8))}…${esc(k.key.slice(-6))}</div>
            <div style="font-size:10px;color:var(--text3);margin-top:2px">Created: ${fmtTs(k.created_at)} · Used: ${k.usage_count}x${k.last_used?" · Last: "+fmtTs(k.last_used):""}</div>
          </div>
          <div style="display:flex;gap:6px">
            ${k.active ? `
              <button class="btn btn-xs btn-ghost" onclick="navigator.clipboard.writeText('${esc(k.key)}').then(()=>showToast('Key copied!','success'))">📋 Copy</button>
              <button class="btn btn-xs btn-danger-ghost" onclick="revokeApiKey(${k.id})">Revoke</button>
            ` : '<span class="badge badge-default">Revoked</span>'}
          </div>
        </div>
      </div>`).join("");
  } catch {
    el.innerHTML = `<div class="empty">Failed to load API keys</div>`;
  }
}

async function generateApiKey() {
  const name = prompt("Key name (e.g. 'My CLI')", "CLI Key");
  if (!name) return;
  const r = await fetch("/api/keys", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({name})
  }).then(r => r.json());
  if (r.ok) {
    showToast("API key created! Copy it now.", "success", 8000);
    openModal("🔑 New API Key",
      `<div style="padding:16px">
        <div style="font-weight:600;margin-bottom:8px">Your new API key:</div>
        <div style="background:#0f172a;padding:14px;border-radius:8px;font-family:monospace;font-size:13px;word-break:break-all;user-select:all">${esc(r.key)}</div>
        <div style="margin-top:12px;font-size:12px;color:var(--text3)">Copy this key now. You won't see it in full again.</div>
      </div>`,
      `<button class="btn btn-accent" onclick="navigator.clipboard.writeText('${esc(r.key)}');showToast('Copied!','success');closeModal()">📋 Copy & Close</button>`
    );
    loadApiKeys();
  } else showToast("Error: " + r.error, "error");
}

async function revokeApiKey(id) {
  if (!confirm("Revoke this API key? It will stop working immediately.")) return;
  await fetch(`/api/keys/${id}/revoke`, {method: "POST"});
  showToast("Key revoked", "success");
  loadApiKeys();
}

// Hook into settings load to also load API keys
const _origLoadSettings = typeof loadSettings !== 'undefined' ? loadSettings : null;
if (_origLoadSettings) {
  const _wrappedLoadSettings = loadSettings;
  loadSettings = async function() {
    await _wrappedLoadSettings();
    loadApiKeys();
  };
}



// ════════════════════════════════════════════════════════════════════════════
// GARBAGE SUBDOMAINS TAB — FIX-UI-GARBAGE-01
// All garbage management: list, promote, delete, bulk ops
// ════════════════════════════════════════════════════════════════════════════

let _garbageRows = [];
let _garbageSortKey = 'score';
let _garbageSortDir = 'asc';
let _garbageSelected = new Set();

async function loadGarbageTab() {
  if (!currentProjectId) return;
  const tb = document.getElementById('garbageTbody');
  if (tb) tb.innerHTML = '<tr><td colspan="8" class="empty"><span class="spin">⟳</span> Loading garbage subdomains…</td></tr>';

  try {
    const search = document.getElementById('garbageSearch')?.value || '';
    const notPromoted = document.getElementById('garbageNotPromoted')?.checked;
    const params = new URLSearchParams({
      per_page: 500,
      sort: _garbageSortKey,
      order: _garbageSortDir,
    });
    if (search) params.set('search', search);
    if (notPromoted) params.set('promoted', '0');

    const data = await fetch(`/api/projects/${currentProjectId}/garbage?${params}`).then(r => r.ok ? r.json() : { garbage: [] });
    _garbageRows = data.garbage || [];
    _garbageSelected.clear();

    // Update count badge
    const countLabel = document.getElementById('garbageCountLabel');
    if (countLabel) countLabel.textContent = `(${data.total || _garbageRows.length} total)`;
    const badge = document.getElementById('dtab-garbage-cnt');
    if (badge) { badge.textContent = data.total || _garbageRows.length; badge.style.display = (data.total || _garbageRows.length) > 0 ? 'inline' : 'none'; }

    renderGarbageTable();
  } catch (e) {
    if (tb) tb.innerHTML = `<tr><td colspan="8" class="empty" style="color:var(--red)">Error: ${esc(String(e?.message || e))}</td></tr>`;
  }
}

function filterGarbageTable() {
  loadGarbageTab();
}

function garbageSortBy(key) {
  if (_garbageSortKey === key) {
    _garbageSortDir = _garbageSortDir === 'asc' ? 'desc' : 'asc';
  } else {
    _garbageSortKey = key;
    _garbageSortDir = key === 'score' ? 'asc' : 'asc';
  }
  loadGarbageTab();
}

function garbageToggleAll(checked) {
  if (checked) {
    _garbageRows.forEach(r => _garbageSelected.add(r.id));
  } else {
    _garbageSelected.clear();
  }
  renderGarbageTable();
  updateGarbageSelCount();
}

function garbageToggleRow(id, checked) {
  if (checked) _garbageSelected.add(id);
  else _garbageSelected.delete(id);
  updateGarbageSelCount();
}

function updateGarbageSelCount() {
  const el = document.getElementById('garbageSelCount');
  if (el) el.textContent = _garbageSelected.size > 0 ? `${_garbageSelected.size} selected` : '';
}

function renderGarbageTable() {
  const tb = document.getElementById('garbageTbody');
  if (!tb) return;
  if (!_garbageRows.length) {
    tb.innerHTML = '<tr><td colspan="8" style="padding:36px;text-align:center;color:var(--text3);font-size:12.5px">No garbage subdomains found — AI classifier found all subdomains to be real</td></tr>';
    return;
  }
  const scoreColor = s => s >= 0 ? 'var(--green)' : s >= -3 ? 'var(--yellow)' : 'var(--red)';
  tb.innerHTML = _garbageRows.map(r => `
    <tr class="${r.promoted ? 'row-faded' : ''}">
      <td style="text-align:center">
        <input type="checkbox" ${_garbageSelected.has(r.id) ? 'checked' : ''}
          onchange="garbageToggleRow(${r.id}, this.checked)">
      </td>
      <td class="mono" style="font-size:11px;font-weight:${r.promoted ? '400' : '600'}">${esc(r.subdomain)}</td>
      <td style="font-family:var(--mono);font-size:11px;color:${scoreColor(r.score)};text-align:center">${r.score ?? '—'}</td>
      <td class="text-xs text-dim" title="${esc(r.reason)}">${esc((r.reason || '—').slice(0, 40))}${(r.reason || '').length > 40 ? '…' : ''}</td>
      <td><span class="pill pill-gray" style="font-size:9px">${esc(r.source || '—')}</span></td>
      <td class="text-xs text-dim">${r.created_at ? r.created_at.slice(0, 10) : '—'}</td>
      <td>${r.promoted
        ? '<span class="pill pill-green" style="font-size:9px">✓ Promoted</span>'
        : '<span class="pill pill-gray" style="font-size:9px">Garbage</span>'}</td>
      <td style="white-space:nowrap">
        ${!r.promoted ? `<button class="btn btn-xs btn-ghost" onclick="garbagePromoteSingle(${r.id},'${esc(r.subdomain)}')" title="Promote to real subdomain">✓ Promote</button>` : ''}
        <button class="btn btn-xs btn-danger-ghost" onclick="garbageDeleteSingle(${r.id})" title="Delete" style="margin-left:2px">✗</button>
      </td>
    </tr>`).join('');
}

async function garbagePromoteSingle(id, subdomain) {
  try {
    const r = await fetch(`/api/projects/${currentProjectId}/garbage/${id}/promote`, { method: 'POST' }).then(r => r.json());
    if (r.ok) {
      showToast(`✓ Promoted: ${subdomain}`, 'success');
      loadGarbageTab();
    } else {
      showToast(r.detail || 'Failed to promote', 'error');
    }
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function garbageDeleteSingle(id) {
  try {
    const r = await fetch(`/api/projects/${currentProjectId}/garbage/${id}`, { method: 'DELETE' }).then(r => r.json());
    if (r.ok) {
      showToast('Deleted', 'success');
      loadGarbageTab();
    } else {
      showToast(r.detail || 'Failed', 'error');
    }
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function garbageBulkPromote() {
  const ids = [..._garbageSelected];
  if (!ids.length) { showToast('Select rows first', 'warning'); return; }
  if (!confirm(`Promote ${ids.length} garbage subdomain(s) to real?
They will be added to the scan queue.`)) return;
  try {
    const r = await fetch(`/api/projects/${currentProjectId}/garbage/bulk-promote`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids }),
    }).then(r => r.json());
    showToast(`✓ Promoted ${r.promoted || 0} subdomains`, 'success');
    loadGarbageTab();
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function garbageBulkDelete() {
  const ids = [..._garbageSelected];
  if (!ids.length) { showToast('Select rows first', 'warning'); return; }
  if (!confirm(`Permanently delete ${ids.length} garbage entries?`)) return;
  try {
    const r = await fetch(`/api/projects/${currentProjectId}/garbage/bulk-delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids }),
    }).then(r => r.json());
    showToast(`✓ Deleted ${r.deleted || 0} entries`, 'success');
    loadGarbageTab();
  } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

// ════════════════════════════════════════════════════════════════════════════
// PIPELINE PROGRESS WIDGET — FIX-UI-PIPELINE-01
// Shows real-time per-project scan phase + tool progress
// ════════════════════════════════════════════════════════════════════════════

function renderPipelineStatus(projectProgress) {
  const el = document.getElementById('pipelineStatus');
  if (!el) return;

  if (!projectProgress || !projectProgress.length) {
    el.innerHTML = '';
    return;
  }

  const phaseLabel = { A: '⚡ Alive Check', B: '✂ Lifecycle', C: '🔍 Deep Scan', D: '🛡 Nuclei' };
  const phaseClass = { A: 'phase-a', B: 'phase-b', C: 'phase-c', D: 'phase-d' };

  el.innerHTML = `
    <div style="margin-bottom:12px">
      <div style="font-size:11px;font-weight:700;color:var(--text3);letter-spacing:.5px;margin-bottom:8px">ACTIVE SCANS</div>
      ${projectProgress.slice(0, 6).map(p => {
        const pct = p.pct || 0;
        const phase = (p.phase || 'A').toUpperCase();
        return `<div style="margin-bottom:10px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:3px">
            <span style="font-size:11px;font-weight:600;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(p.name || '')}">${esc(p.name || 'Project')}</span>
            <span style="font-size:10px;color:var(--accent)">${pct}%</span>
          </div>
          <div style="height:3px;background:var(--border);border-radius:2px;overflow:hidden;margin-bottom:3px">
            <div style="height:100%;width:${pct}%;background:var(--accent);border-radius:2px;transition:width .3s ease"></div>
          </div>
          <div style="display:flex;align-items:center;gap:5px">
            <span style="font-size:9px;padding:1px 5px;border-radius:3px;background:var(--surface3);color:var(--accent)">${phaseLabel[phase] || 'Phase ' + phase}</span>
            ${p.alive != null ? `<span style="font-size:9px;color:var(--green)">${fmt(p.alive)} alive</span>` : ''}
            ${p.total ? `<span style="font-size:9px;color:var(--text4)">/ ${fmt(p.total)}</span>` : ''}
          </div>
          ${p.tools && Object.keys(p.tools).length ? renderMiniToolProgress(p.tools) : ''}
        </div>`;
      }).join('')}
    </div>`;
}

function renderMiniToolProgress(tools) {
  const active = Object.entries(tools).filter(([, t]) => t.status === 'running');
  if (!active.length) return '';
  return `<div style="display:flex;flex-wrap:wrap;gap:3px;margin-top:3px">
    ${active.map(([k, t]) => `<span style="font-size:8px;padding:1px 4px;border-radius:2px;background:rgba(88,166,255,.12);color:var(--accent)">${k}${t.count ? ' (' + t.count + ')' : ''}</span>`).join('')}
  </div>`;
}

// ── Patch dashboard polling to also update pipeline widget ─────────────────
const _origRefreshStats = window.refreshStats;

// ════════════════════════════════════════════════════════════════════════════
// FIX-UI-DETAIL-BADGE: Load garbage count in _loadDetailBadges
// ════════════════════════════════════════════════════════════════════════════

// Extend badge loading to include garbage count
const _origLoadDetailBadges = window._loadDetailBadges;

async function _loadDetailBadgesPatched(pid) {
  try {
    const [lk, vk, gk] = await Promise.all([
      fetch('/api/projects/' + pid + '/leak-intel/status').then(r => r.ok ? r.json() : {}),
      fetch('/api/projects/' + pid + '/vulnerabilities?per_page=500').then(r => r.ok ? r.json() : []),
      fetch('/api/projects/' + pid + '/garbage/stats').then(r => r.ok ? r.json() : { pending: 0 }),
    ]);
    const comp  = lk.compromised || 0;
    const vulns = Array.isArray(vk) ? vk.length : 0;
    const garbagePending = gk.pending || 0;
    const lb = document.getElementById('dtab-leaks-cnt');
    const vb = document.getElementById('dtab-vulns-cnt');
    const gb = document.getElementById('dtab-garbage-cnt');
    if (lb) { lb.textContent = comp;          lb.style.display = comp > 0 ? 'inline-block' : 'none'; }
    if (vb) { vb.textContent = vulns;         vb.style.display = vulns > 0 ? 'inline-block' : 'none'; }
    if (gb) { gb.textContent = garbagePending; gb.style.display = garbagePending > 0 ? 'inline-block' : 'none'; }
  } catch (_) {}
}

// Override the function
window._loadDetailBadges = _loadDetailBadgesPatched;

// ════════════════════════════════════════════════════════════════════════════
// FIX-UI-SCAN-STATUS: Better scan status polling for project detail
// Auto-refresh subdomains tab while project is scanning
// ════════════════════════════════════════════════════════════════════════════

let _detailScanPollTimer = null;
let _detailLastScanStatus = null;

function startDetailScanPoll(pid) {
  stopDetailScanPoll();
  _detailScanPollTimer = setInterval(async () => {
    if (!currentProjectId || currentProjectId !== pid) { stopDetailScanPoll(); return; }
    try {
      const p = await fetch('/api/projects/' + pid).then(r => r.ok ? r.json() : null);
      if (!p) return;
      // Update scan status pill
      const pill = document.getElementById('detailScanPill');
      if (pill) {
        const map = {
          pending: ['pill-gray', 'Pending'], done: ['pill-green', '✓ Done'],
          phase_a: ['pill-blue', '⚡ Phase A'], phase_a_done: ['pill-blue', 'Phase A ✓'],
          phase_b_done: ['pill-blue', 'Phase B ✓'], phase_c_done: ['pill-blue', 'Phase C ✓'],
          phase_d: ['pill-purple', '🛡 Nuclei'],
        };
        const [cls, label] = map[p.scan_status] || ['pill-gray', p.scan_status];
        pill.innerHTML = `<span class="pill ${cls}">${label}</span>`;
      }
      // Update counters in meta bar
      const aliveCnt = document.getElementById('detailAliveCount');
      if (aliveCnt) aliveCnt.textContent = fmt(p.sub_alive || 0);

      // If scan just completed, reload subs and stop polling
      if (_detailLastScanStatus && _detailLastScanStatus !== 'done' && p.scan_status === 'done') {
        showToast('✅ Scan complete for ' + p.name, 'success');
        loadSubs();
        _loadDetailBadges(pid);
        stopDetailScanPoll();
      }
      _detailLastScanStatus = p.scan_status;

      // Stop polling if not scanning
      if (['done', 'pending'].includes(p.scan_status)) stopDetailScanPoll();
    } catch (_) {}
  }, 5000);
}

function stopDetailScanPoll() {
  if (_detailScanPollTimer) { clearInterval(_detailScanPollTimer); _detailScanPollTimer = null; }
}

// ════════════════════════════════════════════════════════════════════════════
// FIX-UI-SCAN-PROGRESS: Inject pipeline widget into dashboard sidebar
// ════════════════════════════════════════════════════════════════════════════

function updateDashboardPipeline(stats) {
  if (!stats) return;
  const pp = stats.project_progress || [];
  renderPipelineStatus(pp);
}

// Hook into existing dashboard polling to update pipeline
const _origRenderScanProgress = window.renderScanProgress;
if (_origRenderScanProgress) {
  window.renderScanProgress = function(projects, job) {
    _origRenderScanProgress(projects, job);
    renderPipelineStatus(projects);
  };
}
