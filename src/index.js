#!/usr/bin/env node
/**
 * SysScope — index.js
 * Entry point. Dispatches to system info, file CRUD, threat scanning,
 * and report generation commands.
 */

import readline from 'node:readline';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { getSystemInfo }  from './system/systemInfo.js';
import * as fileManager   from './files/fileManager.js';
import { ValidationError, getWorkspaceDir } from './utils/validator.js';
import {
  color,
  printHeader,
  printRow,
  printSuccess,
  printError,
  printWarning,
  printInfo,
  printSystemInfo,
  formatBytes,
} from './utils/formatter.js';

import { runFullScan }    from './scanner/threatScanner.js';
import {
  printScanReport,
  printJsonReport,
  saveHtmlReport,
} from './reports/reporter.js';
import { startDashboardServer } from './server/dashboardServer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Reports directory lives next to the workspace
const REPORTS_DIR = path.resolve(__dirname, '../reports');

import fs from 'node:fs/promises';
async function ensureReportsDir() {
  try { await fs.mkdir(REPORTS_DIR, { recursive: true }); } catch {}
}

// ── Help text ──────────────────────────────────────────────────────────────────

const HELP_TEXT = `
${color.bold('SysScope')} — developer system, security & workspace auditing CLI

${color.bold('Usage:')}
  sysscope sysinfo
  sysscope scan [--format console|json|html]
  sysscope serve [--port 4500] [--interval 5000] [--no-open]
  sysscope files list
  sysscope files create <filename> [--content "text"]
  sysscope files read  <filename>
  sysscope files update <filename> [--content "text"]
  sysscope files delete <filename> [--force]
  sysscope report [--format console|json|html]
  sysscope help

${color.bold('Scan options:')}
  --format console   Coloured terminal output (default)
  --format json      Machine-readable JSON to stdout
  --format html      Standalone HTML dashboard saved to ./reports/

${color.bold('Serve options (live dashboard):')}
  --port <n>      Port to listen on (default 4500)
  --interval <ms> Heartbeat re-scan interval in ms (default 5000)
  --no-open       Don't auto-open the dashboard in your browser

${color.bold('Examples:')}
  sysscope sysinfo
  sysscope scan
  sysscope scan --format html
  sysscope serve
  sysscope serve --port 8080 --interval 3000
  sysscope files create notes.md --content "# Hello"
  sysscope files read notes.md
  echo "new content" | sysscope files update notes.md
  sysscope files delete notes.md

${color.dim('File operations are sandboxed to the ./workspace directory.')}
${color.dim('HTML reports are saved to the ./reports directory.')}
${color.dim('"serve" opens a live browser dashboard that re-scans instantly on every file change.')}
`;

// ── Arg parsing ───────────────────────────────────────────────────────────────

function parseArgs(args) {
  const positional = [];
  const flags = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg.startsWith('--')) { positional.push(arg); continue; }

    const eqIndex = arg.indexOf('=');
    if (eqIndex !== -1) {
      flags[arg.slice(2, eqIndex)] = arg.slice(eqIndex + 1);
      continue;
    }

    const next = args[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      flags[arg.slice(2)] = next;
      i++;
    } else {
      flags[arg.slice(2)] = true;
    }
  }

  return { positional, flags };
}

async function readStdin() {
  if (process.stdin.isTTY) return null;
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return chunks.length ? Buffer.concat(chunks).toString('utf8') : null;
}

async function resolveContent(flags) {
  if (typeof flags.content === 'string') return flags.content;
  const piped = await readStdin();
  return piped ?? '';
}

async function confirm(question) {
  if (!process.stdin.isTTY) return false;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise((resolve) => rl.question(question, resolve));
  rl.close();
  return /^y(es)?$/i.test(answer.trim());
}

// ── Command handlers ───────────────────────────────────────────────────────────

async function runSysinfo() {
  printHeader('SysScope — System Information');
  const info = await getSystemInfo();
  printSystemInfo(info);
}

async function runScan(flags) {
  const fmt = (flags.format ?? 'console').toLowerCase();

  printInfo(`Starting threat scan (format: ${fmt}) …`);
  const workspaceDir = getWorkspaceDir();
  const [report, sysInfo] = await Promise.all([
    runFullScan(workspaceDir),
    getSystemInfo(),
  ]);

  if (fmt === 'json') {
    printJsonReport(report);
    return;
  }

  if (fmt === 'html') {
    await ensureReportsDir();
    const htmlPath = await saveHtmlReport(report, sysInfo, REPORTS_DIR);
    printScanReport(report);          // also print to console
    printSuccess(`HTML report saved → ${color.cyan(htmlPath)}`);
    printInfo('Open that file in your browser to view the interactive dashboard.');
    return;
  }

  // default: console
  printScanReport(report);
}

async function runReport(flags) {
  // Alias for scan — identical behaviour
  return runScan(flags);
}

async function runServe(flags) {
  const port = Number.parseInt(flags.port, 10) || 4500;
  const interval = Number.parseInt(flags.interval, 10) || 5000;
  const open = !flags['no-open'];
  printHeader('SysScope — Live Dashboard');
  startDashboardServer({ port, interval, open });
  // Keep the process alive — the server's own listeners do the rest.
  await new Promise(() => {});
}

async function runFilesList() {
  printHeader('SysScope — Workspace Files');
  const files = await fileManager.listFiles();

  if (files.length === 0) {
    printInfo('Workspace is empty. Create one with: sysscope files create <filename>');
    return;
  }

  for (const file of files) {
    printRow(file.name, `${formatBytes(file.sizeBytes).padStart(9)}  ${color.dim(file.modified.toLocaleString())}`);
  }
}

async function runFilesCreate(positional, flags) {
  const [filename] = positional;
  if (!filename) throw new ValidationError('Usage: sysscope files create <filename> [--content "text"]');
  const content = await resolveContent(flags);
  const fullPath = await fileManager.createFile(filename, content);
  printSuccess(`Created ${color.bold(filename)} (${formatBytes(Buffer.byteLength(content))})`);
  printInfo(`Path: ${fullPath}`);
}

async function runFilesRead(positional) {
  const [filename] = positional;
  if (!filename) throw new ValidationError('Usage: sysscope files read <filename>');
  const content = await fileManager.readFile(filename);
  printHeader(`File: ${filename}`);
  console.log(content.length > 0 ? content : color.dim('(empty file)'));
}

async function runFilesUpdate(positional, flags) {
  const [filename] = positional;
  if (!filename) throw new ValidationError('Usage: sysscope files update <filename> [--content "text"]');
  const content = await resolveContent(flags);
  const fullPath = await fileManager.updateFile(filename, content);
  printSuccess(`Updated ${color.bold(filename)} (${formatBytes(Buffer.byteLength(content))})`);
  printInfo(`Path: ${fullPath}`);
}

async function runFilesDelete(positional, flags) {
  const [filename] = positional;
  if (!filename) throw new ValidationError('Usage: sysscope files delete <filename> [--force]');

  if (!flags.force) {
    const confirmed = await confirm(`${color.yellow('⚠')}  Delete "${filename}" permanently? (y/N) `);
    if (!confirmed) {
      printWarning('Delete cancelled. Pass --force to skip this prompt in scripts.');
      return;
    }
  }

  const fullPath = await fileManager.deleteFile(filename);
  printSuccess(`Deleted ${color.bold(filename)}`);
  printInfo(`Path: ${fullPath}`);
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

async function main() {
  const [command, ...rest] = process.argv.slice(2);

  if (!command || ['help', '--help', '-h'].includes(command)) {
    console.log(HELP_TEXT);
    return;
  }

  try {
    if (command === 'sysinfo') {
      await runSysinfo();
      return;
    }

    if (command === 'scan' || command === 'report') {
      const { flags } = parseArgs(rest);
      await (command === 'report' ? runReport(flags) : runScan(flags));
      return;
    }

    if (command === 'serve' || command === 'dashboard' || command === 'watch') {
      const { flags } = parseArgs(rest);
      await runServe(flags);
      return;
    }

    if (command === 'files') {
      const [subcommand, ...subArgs] = rest;
      const { positional, flags } = parseArgs(subArgs);

      switch (subcommand) {
        case 'list':   await runFilesList();                   break;
        case 'create': await runFilesCreate(positional, flags); break;
        case 'read':   await runFilesRead(positional);         break;
        case 'update': await runFilesUpdate(positional, flags); break;
        case 'delete': await runFilesDelete(positional, flags); break;
        default:
          printError(`Unknown files subcommand: "${subcommand ?? ''}"`);
          console.log(HELP_TEXT);
          process.exitCode = 1;
      }
      return;
    }

    printError(`Unknown command: "${command}"`);
    console.log(HELP_TEXT);
    process.exitCode = 1;

  } catch (err) {
    if (err instanceof ValidationError) {
      printError(err.message);
    } else {
      printError(`Unexpected error: ${err.message}`);
    }
    process.exitCode = 1;
  }
}

main();
