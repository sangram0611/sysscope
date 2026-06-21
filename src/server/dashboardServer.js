/**
 * dashboardServer.js
 * ──────────────────────────────────────────────────────────────────────────────
 * Zero-dependency live web dashboard.
 *
 * Starts a plain `node:http` server that:
 *   1. Serves a single self-contained HTML/CSS/JS app shell at "/".
 *   2. Streams live scan results to that page over Server-Sent Events ("/events").
 *   3. Watches the workspace directory with fs.watch and re-runs a full scan
 *      the instant a file is created, edited, or deleted — no manual refresh,
 *      no polling delay. This is what makes the dashboard "real-time":
 *      run a command → the page updates on its own, within ~250ms.
 *   4. Also re-scans on a fixed heartbeat (default 5s) to catch things that
 *      aren't filesystem events — env var changes, memory pressure, uptime.
 *
 * No external packages are used — only Node's built-in http/fs/path/os.
 * ──────────────────────────────────────────────────────────────────────────────
 */

import http from 'node:http';
import fs from 'node:fs';
import { exec } from 'node:child_process';

import { runFullScan } from '../scanner/threatScanner.js';
import { getSystemInfo } from '../system/systemInfo.js';
import { getWorkspaceDir, ensureWorkspaceExists } from '../utils/validator.js';
import { buildDashboardHtml } from './dashboardView.js';
import { color } from '../utils/formatter.js';

// A stable identity for a finding so we can diff scan-to-scan and know what's
// genuinely new vs. what was already there (and what just got fixed).
function findingKey(f) {
  return `${f.id}|${f.location?.file ?? ''}|${f.location?.line ?? ''}`;
}

function openInBrowser(url) {
  const cmd =
    process.platform === 'darwin' ? `open "${url}"` :
    process.platform === 'win32'  ? `start "" "${url}"` :
                                     `xdg-open "${url}"`;
  exec(cmd, () => {}); // best-effort, never fatal
}

export function startDashboardServer({ port = 4500, interval = 20000, open = true } = {}) {
  ensureWorkspaceExists();
  const workspaceDir = getWorkspaceDir();

  /** @type {Set<import('http').ServerResponse>} */
  const clients = new Set();

  let scanSeq = 0;
  let scanning = false;
  let previousFindings = new Map(); // key -> finding, from the last completed scan

  function sendEvent(res, event, data) {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  }

  function broadcast(event, data) {
    for (const res of clients) {
      try { sendEvent(res, event, data); } catch { /* client likely gone */ }
    }
  }

  async function runScanAndBroadcast(trigger = 'interval') {
    if (scanning) return;
    scanning = true;
    try {
      const startedAt = Date.now();
      const [report, sysInfo] = await Promise.all([
        runFullScan(workspaceDir),
        getSystemInfo(),
      ]);

      const currentMap = new Map(report.findings.map((f) => [findingKey(f), f]));
      const newFindings = report.findings.filter((f) => !previousFindings.has(findingKey(f)));
      const resolvedFindings = [...previousFindings.entries()]
        .filter(([key]) => !currentMap.has(key))
        .map(([, f]) => f);

      scanSeq += 1;
      previousFindings = currentMap;

      broadcast('scan', {
        seq: scanSeq,
        trigger,
        generatedAt: new Date().toISOString(),
        clientLatencyMs: Date.now() - startedAt,
        report,
        sysInfo,
        newFindings,
        resolvedFindings,
      });
    } catch (err) {
      broadcast('scan-error', { message: err.message });
    } finally {
      scanning = false;
    }
  }

  // ── Instant reaction to filesystem activity in the workspace ────────────────
  let debounceTimer = null;
  function scheduleRescan(reason) {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => runScanAndBroadcast(reason), 200);
  }

  let watcher = null;
  try {
    watcher = fs.watch(workspaceDir, { recursive: true }, () => scheduleRescan('file-change'));
  } catch {
    try {
      watcher = fs.watch(workspaceDir, () => scheduleRescan('file-change'));
    } catch {
      /* watching unsupported on this platform/filesystem — heartbeat still covers it */
    }
  }

  // ── Steady heartbeat for non-filesystem signals (env, memory, uptime) ───────
  const heartbeat = setInterval(() => runScanAndBroadcast('interval'), Math.max(1000, interval));

  // ── HTTP server ───────────────────────────────────────────────────────────
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);

    if (url.pathname === '/' || url.pathname === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(buildDashboardHtml({ interval }));
      return;
    }

    if (url.pathname === '/events') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',
      });
      res.write('retry: 1500\n\n');
      clients.add(res);

      // Send whatever we already know immediately, then force a fresh scan
      // so a newly-opened tab is never looking at stale data.
      if (scanSeq > 0) {
        sendEvent(res, 'hello', { seq: scanSeq });
      }
      runScanAndBroadcast(scanSeq === 0 ? 'startup' : 'client-connect');

      const keepAlive = setInterval(() => {
        try { res.write(': ping\n\n'); } catch { /* ignore */ }
      }, 15000);

      req.on('close', () => {
        clearInterval(keepAlive);
        clients.delete(res);
      });
      return;
    }

    if (url.pathname === '/api/scan') {
      runScanAndBroadcast('manual').then(() => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, seq: scanSeq }));
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(color.red(`✘ Port ${port} is already in use. Try: sysscope serve --port ${port + 1}`));
      process.exitCode = 1;
      return;
    }
    console.error(color.red(`✘ Dashboard server error: ${err.message}`));
  });

  server.listen(port, () => {
    const url = `http://localhost:${port}`;
    console.log(color.green(`✔ SysScope live dashboard running at ${color.bold(url)}`));
    console.log(color.dim(`  Watching ${workspaceDir}`));
    console.log(color.dim(`  Heartbeat scan every ${interval}ms — file changes trigger an instant scan`));
    console.log(color.dim('  Press Ctrl+C to stop.'));
    if (open) openInBrowser(url);
  });

  function shutdown() {
    clearInterval(heartbeat);
    clearTimeout(debounceTimer);
    try { watcher?.close(); } catch { /* ignore */ }
    for (const res of clients) { try { res.end(); } catch { /* ignore */ } }
    server.close(() => process.exit(0));
    // Force-exit if something keeps the event loop alive
    setTimeout(() => process.exit(0), 500).unref();
  }

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  return server;
}
