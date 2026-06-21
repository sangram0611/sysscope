/**
 * reporter.js
 * ──────────────────────────────────────────────────────────────────────────────
 * Generates multi-format, detailed security and system reports from scan data.
 * Formats:
 *   • console  — colored terminal output with sections and severity badges
 *   • json     — structured JSON to stdout
 *   • html     — full standalone dashboard HTML file
 * ──────────────────────────────────────────────────────────────────────────────
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { Severity } from '../scanner/threatScanner.js';
import { color, printHeader, printRow, printSuccess, printWarning, printError, printInfo } from '../utils/formatter.js';

// ── Severity badge helpers ────────────────────────────────────────────────────

const SEVERITY_EMOJI = {
  [Severity.CRITICAL]: '🔴',
  [Severity.HIGH]:     '🟠',
  [Severity.MEDIUM]:   '🟡',
  [Severity.LOW]:      '🔵',
  [Severity.INFO]:     '⚪',
};

const SEVERITY_COLOR = {
  [Severity.CRITICAL]: color.red,
  [Severity.HIGH]:     color.yellow,
  [Severity.MEDIUM]:   color.magenta,
  [Severity.LOW]:      color.cyan,
  [Severity.INFO]:     color.dim,
};

const RISK_COLOR = {
  CLEAN:    color.green,
  LOW:      color.cyan,
  MEDIUM:   color.magenta,
  HIGH:     color.yellow,
  CRITICAL: color.red,
};

// ── Console reporter ──────────────────────────────────────────────────────────

export function printScanReport(report) {
  printHeader('SysScope — Threat Scan Report');

  // Overall risk badge
  const riskFn = RISK_COLOR[report.riskRating] ?? color.dim;
  console.log();
  console.log(`  Overall Risk:  ${riskFn(color.bold(report.riskRating))}`);
  console.log(`  Scanned At:    ${color.dim(report.scannedAt)}`);
  console.log(`  Duration:      ${color.dim(report.durationMs + 'ms')}`);
  console.log();

  // Summary table
  console.log(color.bold('  Summary'));
  printRow('Total findings', String(report.summary.total));
  printRow('Critical',       color.red(String(report.summary.critical)));
  printRow('High',           color.yellow(String(report.summary.high)));
  printRow('Medium',         color.magenta(String(report.summary.medium)));
  printRow('Low',            color.cyan(String(report.summary.low)));
  console.log();

  if (report.findings.length === 0) {
    printSuccess('No threats detected. System looks clean.');
    return;
  }

  // Sections
  const sections = [
    { title: 'Workspace Findings',    items: report.sections.workspace },
    { title: 'Environment Findings',  items: report.sections.environment },
    { title: 'System Anomalies',      items: report.sections.system },
  ];

  for (const section of sections) {
    if (section.items.length === 0) continue;

    printHeader(section.title);
    for (const finding of section.items) {
      const badge = SEVERITY_EMOJI[finding.severity] ?? '❔';
      const colorFn = SEVERITY_COLOR[finding.severity] ?? color.dim;

      console.log(`\n  ${badge}  ${colorFn(color.bold(finding.severity))}  —  ${color.bold(finding.type)}`);
      console.log(`     ID:          ${color.dim(finding.id)}`);
      console.log(`     Description: ${finding.description}`);

      if (finding.location?.file) {
        const locParts = [`File: ${finding.location.file}`];
        if (finding.location.line)   locParts.push(`Line ${finding.location.line}`);
        console.log(`     Location:    ${color.cyan(locParts.join('  •  '))}`);
      }

      if (finding.location?.excerpt) {
        console.log(`     Excerpt:     ${color.dim('"' + finding.location.excerpt.slice(0, 100) + '"')}`);
      }
    }
    console.log();
  }
}

// ── JSON reporter ─────────────────────────────────────────────────────────────

export function printJsonReport(report) {
  console.log(JSON.stringify(report, null, 2));
}

// ── HTML Dashboard reporter ───────────────────────────────────────────────────

const SEVERITY_HEX = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#3b82f6',
  INFO:     '#6b7280',
  CLEAN:    '#22c55e',
};

function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function severityBadge(sev) {
  const col = SEVERITY_HEX[sev] ?? '#6b7280';
  return `<span class="badge" style="background:${col}20;color:${col};border:1px solid ${col}40">${escHtml(sev)}</span>`;
}

function findingCard(f) {
  const col = SEVERITY_HEX[f.severity] ?? '#6b7280';
  const locationParts = [];
  if (f.location?.file) locationParts.push(`<strong>File:</strong> <code>${escHtml(f.location.file)}</code>`);
  if (f.location?.line) locationParts.push(`<strong>Line:</strong> ${escHtml(f.location.line)}`);
  const locationHtml = locationParts.length
    ? `<div class="finding-loc">${locationParts.join(' &nbsp;•&nbsp; ')}</div>`
    : '';
  const excerptHtml = f.location?.excerpt
    ? `<pre class="finding-excerpt">${escHtml(f.location.excerpt.slice(0, 120))}</pre>`
    : '';

  return `
  <div class="finding-card" style="border-left:4px solid ${col}">
    <div class="finding-header">
      <span class="finding-type">${escHtml(f.type)}</span>
      ${severityBadge(f.severity)}
      <span class="finding-id">#${escHtml(f.id)}</span>
    </div>
    <p class="finding-desc">${escHtml(f.description)}</p>
    ${locationHtml}
    ${excerptHtml}
  </div>`;
}

function buildSectionHtml(title, items) {
  if (items.length === 0) return '';
  return `
  <section class="report-section">
    <h2 class="section-title">${escHtml(title)}</h2>
    <div class="findings-list">
      ${items.map(findingCard).join('\n')}
    </div>
  </section>`;
}

export function generateHtml(report, sysInfo) {
  const riskCol = SEVERITY_HEX[report.riskRating] ?? '#22c55e';
  const clean   = report.findings.length === 0;
  const ts      = new Date(report.scannedAt).toLocaleString();

  const sysRows = sysInfo ? [
    ['OS',          `${sysInfo.os?.type ?? '-'} / ${sysInfo.os?.platform ?? '-'} (${sysInfo.os?.arch ?? '-'})`],
    ['Release',     sysInfo.os?.release ?? '-'],
    ['Hostname',    sysInfo.hostname ?? '-'],
    ['Node.js',     sysInfo.nodeVersion ?? '-'],
    ['CPU',         `${sysInfo.cpu?.model ?? '-'} × ${sysInfo.cpu?.cores ?? '-'} cores`],
    ['Memory',      sysInfo.memory ? `${sysInfo.memory.usedMB} MB / ${sysInfo.memory.totalMB} MB (${sysInfo.memory.usedPercent}%)` : '-'],
    ['User',        sysInfo.username ?? '-'],
  ] : [];

  const sysTableHtml = sysRows.map(([k, v]) =>
    `<tr><td class="sys-key">${escHtml(k)}</td><td class="sys-val">${escHtml(v)}</td></tr>`
  ).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SysScope — Security Report</title>
<style>
  :root {
    --bg:       #0d0f14;
    --surface:  #161922;
    --border:   #1e2330;
    --text:     #e2e8f0;
    --muted:    #64748b;
    --accent:   #6366f1;
    --risk-col: ${riskCol};
    --font-mono: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    --font-sans: 'Inter', 'Segoe UI', system-ui, sans-serif;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-sans);
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
  }

  /* ── Header ─── */
  .app-header {
    background: linear-gradient(135deg, #0d0f14 0%, #12152080 50%, #1a1040 100%);
    border-bottom: 1px solid var(--border);
    padding: 28px 32px 22px;
    display: flex;
    align-items: center;
    gap: 20px;
  }
  .app-logo {
    font-size: 22px;
    font-weight: 800;
    letter-spacing: -0.5px;
    color: var(--text);
  }
  .app-logo span { color: var(--accent); }
  .app-tagline { font-size: 12px; color: var(--muted); margin-top: 2px; }
  .header-meta { margin-left: auto; text-align: right; font-size: 12px; color: var(--muted); }

  /* ── Layout ─── */
  .container { max-width: 1100px; margin: 0 auto; padding: 28px 24px; }

  /* ── Risk Hero ─── */
  .risk-hero {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 28px 32px;
    display: grid;
    grid-template-columns: auto 1fr auto auto auto;
    align-items: center;
    gap: 32px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
  }
  .risk-hero::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: radial-gradient(ellipse at 0% 50%, ${riskCol}12 0%, transparent 60%);
    pointer-events: none;
  }
  .risk-indicator {
    width: 64px; height: 64px;
    border-radius: 50%;
    border: 3px solid ${riskCol};
    background: ${riskCol}18;
    display: flex; align-items: center; justify-content: center;
    font-size: 28px;
  }
  .risk-label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }
  .risk-value { font-size: 32px; font-weight: 800; color: ${riskCol}; letter-spacing: -1px; }
  .stat-box { text-align: center; }
  .stat-num { font-size: 28px; font-weight: 700; font-family: var(--font-mono); }
  .stat-lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }

  /* ── Summary cards ─── */
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 24px;
  }
  .summary-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 20px;
    position: relative;
    overflow: hidden;
  }
  .summary-card::after {
    content: '';
    position: absolute; bottom: 0; left: 0; right: 0; height: 3px;
    background: var(--c);
  }
  .summary-count { font-size: 36px; font-weight: 800; font-family: var(--font-mono); color: var(--c); }
  .summary-label { font-size: 12px; color: var(--muted); margin-top: 2px; }

  /* ── System Info ─── */
  .sys-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
    margin-bottom: 24px;
  }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 24px;
  }
  .card-title {
    font-size: 11px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 1px;
    color: var(--accent); margin-bottom: 14px;
  }
  table.sys-table { width: 100%; border-collapse: collapse; }
  .sys-key { color: var(--muted); padding: 5px 12px 5px 0; font-size: 12px; white-space: nowrap; }
  .sys-val { color: var(--text); padding: 5px 0; font-size: 12px; font-family: var(--font-mono); }
  tr:not(:last-child) td { border-bottom: 1px solid var(--border); }

  /* ── Findings ─── */
  .report-section { margin-bottom: 28px; }
  .section-title {
    font-size: 13px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 1px;
    color: var(--muted); margin-bottom: 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }
  .findings-list { display: flex; flex-direction: column; gap: 10px; }
  .finding-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 16px;
  }
  .finding-header {
    display: flex; align-items: center; gap: 10px;
    flex-wrap: wrap; margin-bottom: 8px;
  }
  .finding-type { font-weight: 700; font-size: 13px; color: var(--text); }
  .badge {
    font-size: 10px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.5px;
    padding: 2px 8px; border-radius: 4px;
  }
  .finding-id { font-size: 11px; color: var(--muted); font-family: var(--font-mono); margin-left: auto; }
  .finding-desc { font-size: 13px; color: #94a3b8; margin-bottom: 8px; }
  .finding-loc  { font-size: 12px; color: var(--muted); margin-bottom: 6px; }
  .finding-loc code { color: #67e8f9; font-family: var(--font-mono); }
  .finding-excerpt {
    font-size: 11px; font-family: var(--font-mono);
    color: #64748b; background: #0a0c10;
    border: 1px solid var(--border); border-radius: 4px;
    padding: 6px 10px; overflow-x: auto;
    white-space: pre;
  }

  /* ── Clean state ─── */
  .clean-banner {
    text-align: center; padding: 60px 24px;
    background: var(--surface);
    border: 1px solid var(--border); border-radius: 12px;
  }
  .clean-icon { font-size: 64px; margin-bottom: 16px; }
  .clean-title { font-size: 22px; font-weight: 700; color: #22c55e; margin-bottom: 8px; }
  .clean-sub { font-size: 14px; color: var(--muted); }

  /* ── Real-time ticker ─── */
  .rt-bar {
    background: #0a0c10; border: 1px solid var(--border);
    border-radius: 8px; padding: 10px 16px;
    font-family: var(--font-mono); font-size: 12px;
    color: #22c55e; margin-bottom: 24px;
    display: flex; align-items: center; gap: 10px;
  }
  .rt-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: #22c55e;
    animation: pulse 1.5s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50%       { opacity: 0.4; transform: scale(0.8); }
  }
  .rt-text { flex: 1; overflow: hidden; white-space: nowrap; }

  /* ── Footer ─── */
  footer {
    text-align: center; padding: 24px;
    border-top: 1px solid var(--border);
    color: var(--muted); font-size: 12px;
    margin-top: 40px;
  }

  @media (max-width: 700px) {
    .risk-hero { grid-template-columns: 1fr 1fr; }
    .summary-grid { grid-template-columns: repeat(2, 1fr); }
    .sys-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<header class="app-header">
  <div>
    <div class="app-logo">Sys<span>Scope</span></div>
    <div class="app-tagline">Developer System &amp; Security Auditing CLI</div>
  </div>
  <div class="header-meta">
    <div>Scanned: ${escHtml(ts)}</div>
    <div>Duration: ${escHtml(String(report.durationMs))}ms</div>
  </div>
</header>

<main class="container">

  <!-- Real-time ticker -->
  <div class="rt-bar">
    <div class="rt-dot"></div>
    <div class="rt-text" id="rtText">
      Scan complete — ${escHtml(String(report.summary.total))} finding(s) detected &nbsp;|&nbsp;
      Risk Level: ${escHtml(report.riskRating)} &nbsp;|&nbsp;
      Workspace scanned &nbsp;|&nbsp;
      Environment checked &nbsp;|&nbsp;
      System anomalies inspected
    </div>
  </div>

  <!-- Risk Hero -->
  <div class="risk-hero">
    <div class="risk-indicator">${clean ? '🛡️' : '⚠️'}</div>
    <div>
      <div class="risk-label">Risk Level</div>
      <div class="risk-value">${escHtml(report.riskRating)}</div>
    </div>
    <div class="stat-box">
      <div class="stat-num" style="color:#ef4444">${escHtml(String(report.summary.critical))}</div>
      <div class="stat-lbl">Critical</div>
    </div>
    <div class="stat-box">
      <div class="stat-num" style="color:#f97316">${escHtml(String(report.summary.high))}</div>
      <div class="stat-lbl">High</div>
    </div>
    <div class="stat-box">
      <div class="stat-num" style="color:#eab308">${escHtml(String(report.summary.medium))}</div>
      <div class="stat-lbl">Medium</div>
    </div>
    <div class="stat-box">
      <div class="stat-num" style="color:#3b82f6">${escHtml(String(report.summary.low))}</div>
      <div class="stat-lbl">Low</div>
    </div>
  </div>

  <!-- Summary cards -->
  <div class="summary-grid">
    <div class="summary-card" style="--c:#ef4444">
      <div class="summary-count">${escHtml(String(report.sections.workspace.length))}</div>
      <div class="summary-label">Workspace Threats</div>
    </div>
    <div class="summary-card" style="--c:#f97316">
      <div class="summary-count">${escHtml(String(report.sections.environment.length))}</div>
      <div class="summary-label">Env Var Risks</div>
    </div>
    <div class="summary-card" style="--c:#eab308">
      <div class="summary-count">${escHtml(String(report.sections.system.length))}</div>
      <div class="summary-label">System Anomalies</div>
    </div>
    <div class="summary-card" style="--c:#6366f1">
      <div class="summary-count">${escHtml(String(Object.keys(report.sections).reduce((a, k) => a + report.sections[k].length, 0)))}</div>
      <div class="summary-label">Total Findings</div>
    </div>
  </div>

  <!-- System Info -->
  ${sysRows.length > 0 ? `
  <div class="sys-grid">
    <div class="card">
      <div class="card-title">System Information</div>
      <table class="sys-table">
        ${sysTableHtml}
      </table>
    </div>
    <div class="card">
      <div class="card-title">Scan Coverage</div>
      <table class="sys-table">
        <tr><td class="sys-key">Workspace files</td><td class="sys-val">✔ Scanned</td></tr>
        <tr><td class="sys-key">Code signatures</td><td class="sys-val">✔ 12 patterns</td></tr>
        <tr><td class="sys-key">Env variables</td><td class="sys-val">✔ 9 dangerous keys</td></tr>
        <tr><td class="sys-key">Hidden files</td><td class="sys-val">✔ Checked</td></tr>
        <tr><td class="sys-key">Memory pressure</td><td class="sys-val">✔ Analyzed</td></tr>
        <tr><td class="sys-key">System uptime</td><td class="sys-val">✔ Monitored</td></tr>
      </table>
    </div>
  </div>
  ` : ''}

  <!-- Findings -->
  ${clean
    ? `<div class="clean-banner">
        <div class="clean-icon">🛡️</div>
        <div class="clean-title">System Clean — No Threats Detected</div>
        <div class="clean-sub">All workspace files, environment variables, and system metrics passed inspection.</div>
       </div>`
    : `
    ${buildSectionHtml('🔴 Workspace Findings', report.sections.workspace)}
    ${buildSectionHtml('🟠 Environment Findings', report.sections.environment)}
    ${buildSectionHtml('🟡 System Anomalies', report.sections.system)}
    `
  }

</main>

<footer>
  SysScope v1.1.0 &nbsp;•&nbsp; Thunder Hackathon 3.0 &nbsp;•&nbsp; Report generated ${escHtml(ts)}
</footer>

<script>
  // Animated ticker
  const ticker = document.getElementById('rtText');
  const msgs = [
    'Scan complete — ${escHtml(String(report.summary.total))} finding(s) detected',
    'Risk Level: ${escHtml(report.riskRating)}',
    '${escHtml(String(report.sections.workspace.length))} workspace threat(s) found',
    '${escHtml(String(report.sections.environment.length))} env variable risk(s) found',
    '${escHtml(String(report.sections.system.length))} system anomaly(s) detected',
    'Scan duration: ${escHtml(String(report.durationMs))}ms',
    'Report generated at ${escHtml(ts)}',
  ];
  let mi = 0;
  setInterval(() => {
    mi = (mi + 1) % msgs.length;
    ticker.textContent = msgs[mi];
  }, 3000);
</script>
</body>
</html>`;
}

// ── Write HTML report to disk ─────────────────────────────────────────────────

export async function saveHtmlReport(report, sysInfo, outputDir) {
  const html     = generateHtml(report, sysInfo);
  const filename = `sysscope-report-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}.html`;
  const fullPath = path.join(outputDir, filename);
  await fs.writeFile(fullPath, html, 'utf8');
  return fullPath;
}
