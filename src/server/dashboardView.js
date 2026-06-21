/**
 * dashboardView.js
 * ──────────────────────────────────────────────────────────────────────────────
 * Returns one self-contained HTML document: a live "threat radar" console.
 * No build step, no external fonts/CDNs/frameworks — everything needed to
 * render and animate the dashboard ships inline, so it also works if someone
 * saves the page and opens it offline (it'll just show the last live state).
 *
 * The page is a thin shell: almost all content is rendered client-side from
 * the JSON payloads pushed over the "/events" Server-Sent Events stream
 * opened by dashboardServer.js. Each payload is a fresh scan — workspace
 * file threats, dangerous env vars, and system anomalies, each carrying an
 * exact location (file + line, env key, or system metric).
 * ──────────────────────────────────────────────────────────────────────────────
 */

export function buildDashboardHtml({ interval = 20000 } = {}) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SysScope — Threat Watch</title>
<style>
  :root {
    --bg:        #060a08;
    --bg-grid:   #0a120d;
    --panel:     #0b130f;
    --panel-2:   #0e1a14;
    --border:    #18271e;
    --border-lt: #233428;
    --text:      #d9ebe0;
    --muted:     #6c8577;
    --dim:       #44594c;

    --crit:  #ff4d5e;
    --high:  #ffb84d;
    --med:   #f2c94c;
    --low:   #4dd2ff;
    --info:  #6c8577;
    --clean: #3dff8a;

    --mono: ui-monospace, 'SFMono-Regular', 'Cascadia Code', 'JetBrains Mono', 'Fira Code', Consolas, 'Liberation Mono', monospace;
    --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
  }

  * , *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { color-scheme: dark; }

  body {
    background:
      radial-gradient(ellipse 1200px 600px at 50% -10%, #0c1812 0%, transparent 60%),
      repeating-linear-gradient(180deg, rgba(61,255,138,0.012) 0px, rgba(61,255,138,0.012) 1px, transparent 1px, transparent 3px),
      var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.55;
    min-height: 100vh;
    padding-bottom: 60px;
  }

  a { color: inherit; }
  code, .mono { font-family: var(--mono); }

  /* ── Topbar ─────────────────────────────────────────────── */
  .topbar {
    position: sticky; top: 0; z-index: 50;
    display: flex; align-items: center; gap: 16px;
    padding: 14px 22px;
    background: rgba(6,10,8,0.92);
    backdrop-filter: blur(6px);
    border-bottom: 1px solid var(--border);
  }
  .brand { display: flex; align-items: baseline; gap: 10px; }
  .brand-mark {
    font-family: var(--mono); font-weight: 700; font-size: 16px;
    letter-spacing: 1px; color: var(--clean);
  }
  .brand-sub {
    font-family: var(--mono); font-size: 11px; color: var(--muted);
    letter-spacing: 2px; text-transform: uppercase;
  }
  .topbar-spacer { flex: 1; }
  .status-pill {
    display: flex; align-items: center; gap: 8px;
    font-family: var(--mono); font-size: 11px; letter-spacing: 1px;
    padding: 6px 12px; border-radius: 999px;
    border: 1px solid var(--border-lt); color: var(--muted);
  }
  .status-dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--dim);
  }
  .status-pill.live { color: var(--clean); border-color: #1d4a30; }
  .status-pill.live .status-dot { background: var(--clean); animation: blink 1.4s infinite; }
  .status-pill.reconnecting { color: var(--high); border-color: #4a3a1d; }
  .status-pill.reconnecting .status-dot { background: var(--high); animation: blink 0.6s infinite; }
  @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0.25; } }

  .scan-now {
    font-family: var(--mono); font-size: 11px; letter-spacing: 1px;
    color: var(--bg); background: var(--clean);
    border: none; border-radius: 6px; padding: 7px 14px;
    cursor: pointer; font-weight: 700;
    transition: filter 0.15s ease, transform 0.15s ease;
  }
  .scan-now:hover { filter: brightness(1.1); }
  .scan-now:active { transform: scale(0.97); }
  .scan-now:disabled { opacity: 0.5; cursor: progress; }

  .meta-line {
    font-family: var(--mono); font-size: 11px; color: var(--dim);
  }

  main { max-width: 1320px; margin: 0 auto; padding: 22px; }

  /* ── Stat strip ─────────────────────────────────────────── */
  .stat-strip {
    display: grid; grid-template-columns: 1.4fr repeat(4, 1fr);
    gap: 10px; margin-bottom: 18px;
  }
  .stat-box {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 14px 16px;
    display: flex; flex-direction: column; gap: 4px;
  }
  .stat-box .num { font-family: var(--mono); font-size: 26px; font-weight: 700; line-height: 1; }
  .stat-box .lbl { font-family: var(--mono); font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase; color: var(--muted); }
  .risk-box .num { font-size: 20px; }

  /* ── Console grid: radar / feed / vitals ───────────────────── */
  .console-grid {
    display: grid;
    grid-template-columns: 320px 1fr 280px;
    gap: 14px;
    margin-bottom: 18px;
  }
  .panel {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 16px;
    display: flex; flex-direction: column;
  }
  .panel-title {
    font-family: var(--mono); font-size: 11px; letter-spacing: 1.5px;
    text-transform: uppercase; color: var(--muted);
    margin-bottom: 12px; display: flex; align-items: center; justify-content: space-between;
  }

  /* ── Radar (signature element) ─────────────────────────────── */
  .radar-wrap { position: relative; width: 100%; aspect-ratio: 1 / 1; margin: 0 auto; }
  .radar-sweep {
    position: absolute; inset: 0; border-radius: 50%;
    background: conic-gradient(from 0deg, rgba(61,255,138,0.0) 0deg, rgba(61,255,138,0.22) 18deg, rgba(61,255,138,0) 40deg);
    animation: sweep 4s linear infinite;
    pointer-events: none;
  }
  @keyframes sweep { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
  .radar-svg { position: relative; width: 100%; height: 100%; }
  .radar-ring { fill: none; stroke: var(--border-lt); stroke-width: 1; }
  .radar-spoke { stroke: var(--border); stroke-width: 1; }
  .radar-center { fill: var(--dim); }
  .blip { cursor: pointer; transition: r 0.15s ease; }
  .blip:hover { stroke: var(--text); stroke-width: 1.5; }
  .blip.flash { animation: blipPulse 0.9s ease 2; }
  @keyframes blipPulse { 0%,100% { r: 4.5; } 50% { r: 8; } }
  .radar-caption {
    position: absolute; font-family: var(--mono); font-size: 9px;
    letter-spacing: 1.5px; color: var(--dim); text-transform: uppercase;
  }
  .radar-clean-label {
    position: absolute; inset: 0; display: flex; align-items: center; justify-content: center;
    flex-direction: column; gap: 4px; pointer-events: none;
  }
  .radar-clean-label .glyph { font-size: 26px; }
  .radar-clean-label .txt { font-family: var(--mono); font-size: 10px; letter-spacing: 2px; color: var(--clean); }

  /* ── Live feed ──────────────────────────────────────────────── */
  .feed { flex: 1; overflow-y: auto; max-height: 360px; display: flex; flex-direction: column; gap: 6px; padding-right: 4px; }
  .feed::-webkit-scrollbar { width: 6px; }
  .feed::-webkit-scrollbar-thumb { background: var(--border-lt); border-radius: 3px; }
  .feed-empty { color: var(--dim); font-family: var(--mono); font-size: 12px; padding: 20px 0; text-align: center; }
  .feed-line {
    font-family: var(--mono); font-size: 11.5px; padding: 7px 10px;
    border-radius: 6px; border-left: 3px solid var(--border-lt);
    background: var(--panel-2); animation: slideIn 0.25s ease;
  }
  @keyframes slideIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
  .feed-line .t { color: var(--dim); margin-right: 6px; }
  .feed-line.crit  { border-left-color: var(--crit); }
  .feed-line.high  { border-left-color: var(--high); }
  .feed-line.med   { border-left-color: var(--med); }
  .feed-line.low   { border-left-color: var(--low); }
  .feed-line.ok    { border-left-color: var(--clean); color: var(--clean); }
  .feed-line.sys   { border-left-color: var(--border-lt); color: var(--muted); }

  /* ── Vitals ─────────────────────────────────────────────────── */
  .vital { margin-bottom: 14px; }
  .vital-row { display: flex; justify-content: space-between; font-family: var(--mono); font-size: 11px; color: var(--muted); margin-bottom: 5px; }
  .vital-row b { color: var(--text); font-weight: 600; }
  .bar-track { height: 6px; border-radius: 4px; background: var(--panel-2); overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 4px; background: var(--clean); transition: width 0.4s ease, background 0.4s ease; }
  .kv { font-family: var(--mono); font-size: 11px; display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px dashed var(--border); color: var(--muted); }
  .kv b { color: var(--text); font-weight: 600; max-width: 60%; text-align: right; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  /* ── Filter chips ───────────────────────────────────────────── */
  .filters { display: flex; gap: 8px; margin-bottom: 14px; flex-wrap: wrap; }
  .chip {
    font-family: var(--mono); font-size: 11px; letter-spacing: 0.5px;
    padding: 6px 13px; border-radius: 999px; cursor: pointer;
    border: 1px solid var(--border-lt); background: var(--panel); color: var(--muted);
    transition: all 0.15s ease; user-select: none;
  }
  .chip:hover { color: var(--text); }
  .chip.active { color: var(--bg); background: var(--text); border-color: var(--text); font-weight: 700; }

  /* ── Findings ───────────────────────────────────────────────── */
  .section { margin-bottom: 22px; }
  .section-head {
    font-family: var(--mono); font-size: 12px; letter-spacing: 1.5px; text-transform: uppercase;
    color: var(--muted); padding-bottom: 8px; margin-bottom: 12px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 8px;
  }
  .section-head .count { color: var(--text); }
  .cards { display: flex; flex-direction: column; gap: 9px; }
  .card {
    background: var(--panel); border: 1px solid var(--border);
    border-left: 4px solid var(--border-lt); border-radius: 8px; padding: 13px 15px;
    transition: box-shadow 0.3s ease, border-color 0.3s ease;
  }
  .card.hidden { display: none; }
  .card.flash { animation: cardFlash 1.8s ease 1; }
  @keyframes cardFlash {
    0%   { box-shadow: 0 0 0 2px var(--flash-color, var(--clean)); }
    100% { box-shadow: 0 0 0 0 transparent; }
  }
  .card-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 7px; }
  .card-type { font-weight: 700; font-size: 13px; }
  .badge {
    font-family: var(--mono); font-size: 9.5px; font-weight: 700;
    letter-spacing: 1px; text-transform: uppercase;
    padding: 3px 8px; border-radius: 4px;
  }
  .card-id { font-family: var(--mono); font-size: 10.5px; color: var(--dim); margin-left: auto; }
  .card-desc { font-size: 12.5px; color: #aebfb4; margin-bottom: 7px; }
  .card-loc { font-family: var(--mono); font-size: 11.5px; color: var(--muted); margin-bottom: 6px; }
  .card-loc .pin { color: var(--low); }
  .card-loc b { color: #8fe6c9; font-weight: 600; }
  .card-excerpt {
    font-family: var(--mono); font-size: 10.5px; color: var(--dim);
    background: #050907; border: 1px solid var(--border); border-radius: 5px;
    padding: 7px 10px; overflow-x: auto; white-space: pre;
  }
  .clean-banner {
    text-align: center; padding: 50px 24px; background: var(--panel);
    border: 1px solid var(--border); border-radius: 12px;
  }
  .clean-banner .glyph { font-size: 44px; margin-bottom: 10px; }
  .clean-banner .title { font-family: var(--mono); font-weight: 700; color: var(--clean); letter-spacing: 1px; margin-bottom: 6px; }
  .clean-banner .sub { color: var(--muted); font-size: 12.5px; }

  footer {
    max-width: 1320px; margin: 30px auto 0; padding: 18px 22px;
    border-top: 1px solid var(--border); color: var(--dim);
    font-family: var(--mono); font-size: 10.5px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 6px;
  }

  @media (max-width: 980px) {
    .console-grid { grid-template-columns: 1fr; }
    .stat-strip { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>

<div class="topbar">
  <div class="brand">
    <span class="brand-mark">SYSSCOPE</span>
    <span class="brand-sub">// Threat Watch</span>
  </div>
  <div class="topbar-spacer"></div>
  <span class="meta-line" id="scanMeta">awaiting first scan…</span>
  <div class="status-pill" id="statusPill"><span class="status-dot"></span><span id="statusText">CONNECTING</span></div>
  <button class="scan-now" id="scanNowBtn">SCAN NOW</button>
</div>

<main>

  <div class="stat-strip">
    <div class="stat-box risk-box">
      <div class="num" id="riskNum" style="color:var(--clean)">—</div>
      <div class="lbl">Overall risk</div>
    </div>
    <div class="stat-box"><div class="num" id="critNum" style="color:var(--crit)">0</div><div class="lbl">Critical</div></div>
    <div class="stat-box"><div class="num" id="highNum" style="color:var(--high)">0</div><div class="lbl">High</div></div>
    <div class="stat-box"><div class="num" id="medNum" style="color:var(--med)">0</div><div class="lbl">Medium</div></div>
    <div class="stat-box"><div class="num" id="lowNum" style="color:var(--low)">0</div><div class="lbl">Low</div></div>
  </div>

  <div class="console-grid">
    <div class="panel">
      <div class="panel-title">Threat Radar</div>
      <div class="radar-wrap">
        <div class="radar-sweep"></div>
        <svg class="radar-svg" viewBox="0 0 300 300" id="radarSvg">
          <circle class="radar-ring" cx="150" cy="150" r="40"/>
          <circle class="radar-ring" cx="150" cy="150" r="75"/>
          <circle class="radar-ring" cx="150" cy="150" r="110"/>
          <circle class="radar-ring" cx="150" cy="150" r="145"/>
          <line class="radar-spoke" x1="150" y1="150" x2="150" y2="5"/>
          <line class="radar-spoke" x1="150" y1="150" x2="254.6" y2="210"/>
          <line class="radar-spoke" x1="150" y1="150" x2="45.4" y2="210"/>
          <circle class="radar-center" cx="150" cy="150" r="2.5"/>
          <g id="blipLayer"></g>
        </svg>
        <span class="radar-caption" style="top:2%; left:50%; transform:translateX(-50%)">workspace</span>
        <span class="radar-caption" style="bottom:6%; right:2%">environment</span>
        <span class="radar-caption" style="bottom:6%; left:2%">system</span>
        <div class="radar-clean-label" id="radarClean" style="display:none">
          <div class="glyph">🛡️</div>
          <div class="txt">ALL CLEAR</div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">Live Feed<span id="feedCount" class="meta-line"></span></div>
      <div class="feed" id="feed"><div class="feed-empty">Listening for activity…</div></div>
    </div>

    <div class="panel">
      <div class="panel-title">System Vitals</div>
      <div class="vital">
        <div class="vital-row"><span>Memory</span><b id="memPct">—</b></div>
        <div class="bar-track"><div class="bar-fill" id="memBar" style="width:0%"></div></div>
      </div>
      <div class="kv"><span>Host</span><b id="vHost">—</b></div>
      <div class="kv"><span>OS</span><b id="vOs">—</b></div>
      <div class="kv"><span>Node.js</span><b id="vNode">—</b></div>
      <div class="kv"><span>CPU</span><b id="vCpu">—</b></div>
      <div class="kv"><span>Uptime</span><b id="vUptime">—</b></div>
    </div>
  </div>

  <div class="filters" id="filters">
    <span class="chip active" data-f="ALL">ALL</span>
    <span class="chip" data-f="CRITICAL">CRITICAL</span>
    <span class="chip" data-f="HIGH">HIGH</span>
    <span class="chip" data-f="MEDIUM">MEDIUM</span>
    <span class="chip" data-f="LOW">LOW</span>
  </div>

  <div id="findings"></div>

</main>

<footer>
  <span>SysScope Live Dashboard · heartbeat ${interval}ms · file changes trigger instant scans</span>
  <span id="footSeq">scan #0</span>
</footer>

<script>
(function () {
  const SEV_COLOR = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)', INFO: 'var(--info)' };
  const SEV_CLASS = { CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low', INFO: 'sys' };
  const SEV_RADIUS = { CRITICAL: 40, HIGH: 75, MEDIUM: 110, LOW: 145, INFO: 145 };
  const SECTOR = {
    workspace:   { start: -90, span: 120 },
    environment: { start: 30,  span: 120 },
    system:      { start: 150, span: 120 },
  };

  let activeFilter = 'ALL';
  let lastSeq = 0;

  const el = (id) => document.getElementById(id);
  const escapeHtml = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

  function setStatus(state) {
    const pill = el('statusPill');
    pill.className = 'status-pill ' + state;
    el('statusText').textContent = state === 'live' ? 'LIVE' : state === 'reconnecting' ? 'RECONNECTING' : 'CONNECTING';
  }

  function fmtUptime(sec) {
    if (sec == null) return '—';
    const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
    if (d > 0) return d + 'd ' + h + 'h';
    if (h > 0) return h + 'h ' + m + 'm';
    return m + 'm ' + Math.floor(sec % 60) + 's';
  }

  function triggerLabel(t) {
    return ({
      startup: 'Startup scan',
      interval: 'Scheduled scan',
      'file-change': 'File change detected',
      manual: 'Manual scan',
      'client-connect': 'Viewer connected',
    })[t] || t;
  }

  function hashAngleJitter(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
    return (h % 9) - 4; // -4..4 degrees
  }

  function categoryOf(report, finding) {
    if (report.sections.workspace.includes(finding)) return 'workspace';
    if (report.sections.environment.includes(finding)) return 'environment';
    return 'system';
  }

  function renderRadar(report) {
    const layer = el('blipLayer');
    layer.innerHTML = '';
    const clean = report.findings.length === 0;
    el('radarClean').style.display = clean ? 'flex' : 'none';

    const byCategory = { workspace: [], environment: [], system: [] };
    for (const f of report.findings) byCategory[categoryOf(report, f)].push(f);

    for (const cat of Object.keys(byCategory)) {
      const items = byCategory[cat];
      const { start, span } = SECTOR[cat];
      items.forEach((f, i) => {
        const angleDeg = start + ((i + 0.5) / items.length) * span + hashAngleJitter(f.id + i);
        const rad = (angleDeg - 90) * Math.PI / 180;
        const radius = (SEV_RADIUS[f.severity] || 145) - 8;
        const cx = 150 + radius * Math.cos(rad);
        const cy = 150 + radius * Math.sin(rad);
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', cx.toFixed(1));
        circle.setAttribute('cy', cy.toFixed(1));
        circle.setAttribute('r', '4.5');
        circle.setAttribute('class', 'blip');
        circle.setAttribute('fill', SEV_COLOR[f.severity] || 'var(--info)');
        circle.dataset.target = f.__cardId;
        const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
        title.textContent = f.severity + ' — ' + f.type + (f.location?.file ? ' (' + f.location.file + ')' : '');
        circle.appendChild(title);
        circle.addEventListener('click', () => {
          const card = document.getElementById(f.__cardId);
          if (card) { card.scrollIntoView({ behavior: 'smooth', block: 'center' }); flashCard(card, SEV_COLOR[f.severity]); }
        });
        layer.appendChild(circle);
      });
    }
  }

  function flashCard(card, colorVar) {
    card.style.setProperty('--flash-color', colorVar || 'var(--clean)');
    card.classList.remove('flash'); void card.offsetWidth; card.classList.add('flash');
  }

  function findingCardHtml(f, idx) {
    f.__cardId = 'f-' + idx;
    const sev = f.severity;
    const loc = [];
    if (f.location?.file) loc.push('<span class="pin">📍</span> <b>' + escapeHtml(f.location.file) + '</b>');
    if (f.location?.line) loc.push('Line ' + escapeHtml(f.location.line));
    const locHtml = loc.length ? '<div class="card-loc">' + loc.join(' &nbsp;·&nbsp; ') + '</div>' : '';
    const excerptHtml = f.location?.excerpt ? '<pre class="card-excerpt">' + escapeHtml(String(f.location.excerpt).slice(0, 160)) + '</pre>' : '';
    return '<div class="card" id="' + f.__cardId + '" data-sev="' + sev + '" style="border-left-color:' + (SEV_COLOR[sev] || 'var(--info)') + '">' +
      '<div class="card-head">' +
        '<span class="card-type">' + escapeHtml(f.type) + '</span>' +
        '<span class="badge" style="color:' + (SEV_COLOR[sev]||'var(--info)') + ';background:color-mix(in srgb, ' + (SEV_COLOR[sev]||'var(--info)') + ' 16%, transparent);border:1px solid color-mix(in srgb, ' + (SEV_COLOR[sev]||'var(--info)') + ' 40%, transparent)">' + escapeHtml(sev) + '</span>' +
        '<span class="card-id">#' + escapeHtml(f.id) + '</span>' +
      '</div>' +
      '<div class="card-desc">' + escapeHtml(f.description) + '</div>' +
      locHtml + excerptHtml +
    '</div>';
  }

  function renderFindings(report) {
    const sections = [
      { key: 'workspace',   title: '🗂  Workspace Findings',   items: report.sections.workspace },
      { key: 'environment', title: '🔑  Environment Findings', items: report.sections.environment },
      { key: 'system',      title: '🖥  System Anomalies',     items: report.sections.system },
    ];
    const root = el('findings');

    if (report.findings.length === 0) {
      root.innerHTML = '<div class="clean-banner"><div class="glyph">🛡️</div><div class="title">SYSTEM CLEAN — NO THREATS DETECTED</div>' +
        '<div class="sub">Workspace files, environment variables, and system metrics all passed inspection.</div></div>';
      return;
    }

    let idx = 0;
    let html = '';
    for (const s of sections) {
      if (s.items.length === 0) continue;
      html += '<div class="section"><div class="section-head">' + s.title + ' <span class="count">(' + s.items.length + ')</span></div><div class="cards">';
      for (const f of s.items) { html += findingCardHtml(f, idx); idx++; }
      html += '</div></div>';
    }
    root.innerHTML = html;
    applyFilter();
  }

  function applyFilter() {
    document.querySelectorAll('.card').forEach((card) => {
      const sev = card.dataset.sev;
      card.classList.toggle('hidden', activeFilter !== 'ALL' && sev !== activeFilter);
    });
  }

  el('filters').addEventListener('click', (e) => {
    const chip = e.target.closest('.chip');
    if (!chip) return;
    document.querySelectorAll('.chip').forEach((c) => c.classList.remove('active'));
    chip.classList.add('active');
    activeFilter = chip.dataset.f;
    applyFilter();
  });

  function pushFeedLine(cls, html) {
    const feed = el('feed');
    const empty = feed.querySelector('.feed-empty');
    if (empty) empty.remove();
    const time = new Date().toLocaleTimeString();
    const line = document.createElement('div');
    line.className = 'feed-line ' + cls;
    line.innerHTML = '<span class="t">' + time + '</span>' + html;
    feed.prepend(line);
    while (feed.children.length > 60) feed.removeChild(feed.lastChild);
    el('feedCount').textContent = ' · ' + feed.children.length;
  }

  function renderVitals(sysInfo) {
    if (!sysInfo) return;
    const pct = sysInfo.memory?.usedPercent ?? 0;
    el('memPct').textContent = pct + '% (' + (sysInfo.memory?.usedMB ?? '—') + ' / ' + (sysInfo.memory?.totalMB ?? '—') + ' MB)';
    const bar = el('memBar');
    bar.style.width = pct + '%';
    bar.style.background = pct >= 90 ? 'var(--crit)' : pct >= 75 ? 'var(--high)' : 'var(--clean)';
    el('vHost').textContent = sysInfo.hostname || '—';
    el('vOs').textContent = (sysInfo.os?.type || '—') + ' (' + (sysInfo.os?.arch || '—') + ')';
    el('vNode').textContent = sysInfo.nodeVersion || '—';
    el('vCpu').textContent = (sysInfo.cpu?.model ? sysInfo.cpu.model.slice(0, 22) + (sysInfo.cpu.model.length > 22 ? '…' : '') : '—') + ' ×' + (sysInfo.cpu?.cores ?? '—');
    el('vUptime').textContent = fmtUptime(sysInfo.uptimeSec);
  }

  function render(data) {
    lastSeq = data.seq;
    el('footSeq').textContent = 'scan #' + data.seq;
    el('scanMeta').textContent = triggerLabel(data.trigger) + ' · ' + new Date(data.generatedAt).toLocaleTimeString();

    const r = data.report;
    const riskEl = el('riskNum');
    riskEl.textContent = r.riskRating;
    riskEl.style.color = r.riskRating === 'CLEAN' ? 'var(--clean)'
      : r.riskRating === 'CRITICAL' ? 'var(--crit)'
      : r.riskRating === 'HIGH' ? 'var(--high)'
      : r.riskRating === 'MEDIUM' ? 'var(--med)' : 'var(--low)';

    el('critNum').textContent = r.summary.critical;
    el('highNum').textContent = r.summary.high;
    el('medNum').textContent = r.summary.medium;
    el('lowNum').textContent = r.summary.low;

    renderVitals(data.sysInfo);
    renderFindings(r);
    renderRadar(r);

    if (data.seq === 1) {
      pushFeedLine('ok', '<b>Initial scan complete</b> — ' + r.findings.length + ' finding(s), risk: ' + r.riskRating);
    } else {
      for (const f of data.newFindings || []) {
        const loc = f.location?.file ? ' → <b>' + escapeHtml(f.location.file) + (f.location.line ? ':' + f.location.line : '') + '</b>' : '';
        pushFeedLine(SEV_CLASS[f.severity] || 'sys', '<b>' + escapeHtml(f.severity) + '</b> ' + escapeHtml(f.type) + loc);
      }
      for (const f of data.resolvedFindings || []) {
        pushFeedLine('ok', '✓ RESOLVED — ' + escapeHtml(f.type) + (f.location?.file ? ' in ' + escapeHtml(f.location.file) : ''));
      }
      if (!(data.newFindings||[]).length && !(data.resolvedFindings||[]).length) {
        pushFeedLine('sys', triggerLabel(data.trigger) + ' — no change (' + r.findings.length + ' finding(s))');
      }
    }

    // flash newly-appeared cards
    for (const f of data.newFindings || []) {
      const card = document.getElementById(f.__cardId);
      if (card && data.seq > 1) flashCard(card, SEV_COLOR[f.severity]);
    }
  }

  const es = new EventSource('/events');
  es.addEventListener('scan', (e) => render(JSON.parse(e.data)));
  es.addEventListener('scan-error', (e) => pushFeedLine('crit', 'Scan error: ' + escapeHtml(JSON.parse(e.data).message)));
  es.onopen = () => setStatus('live');
  es.onerror = () => setStatus('reconnecting');
  setStatus('connecting');

  el('scanNowBtn').addEventListener('click', () => {
    const btn = el('scanNowBtn');
    btn.disabled = true; btn.textContent = 'SCANNING…';
    fetch('/api/scan').finally(() => { btn.disabled = false; btn.textContent = 'SCAN NOW'; });
  });
})();
</script>
</body>
</html>`;
}
