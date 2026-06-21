# 🛡️ SysScope v1.2.0

> **Thunder Hackathon 3.0** — Real-time System Auditor, Threat Scanner, Live Web Dashboard & File Manager CLI

SysScope is a Node.js CLI that collects system information, performs real-time virus/threat scanning across your workspace files and environment, generates detailed security reports in multiple formats (console, JSON, HTML dashboard, **live browser dashboard**), and provides sandboxed CRUD operations on code files.

**New in v1.2.0:** `sysscope serve` opens a live, auto-refreshing dashboard in your browser. It watches your workspace in real time — the instant you create, edit, or delete a file (in another terminal, an editor, anything), the page re-scans and updates itself automatically. No manual refresh, ever.

---

## 📁 Project Structure

```
sysscope/
├── src/
│   ├── index.js                  ← Entry point & command dispatcher
│   ├── system/
│   │   └── systemInfo.js         ← OS, CPU, memory, uptime, env data collector
│   ├── scanner/
│   │   └── threatScanner.js      ← Virus/threat detection engine
│   ├── reports/
│   │   └── reporter.js           ← Console, JSON, static HTML report generator
│   ├── server/
│   │   ├── dashboardServer.js    ← Live web server (HTTP + Server-Sent Events)
│   │   └── dashboardView.js      ← Self-contained live dashboard HTML/CSS/JS
│   ├── files/
│   │   └── fileManager.js        ← Sandboxed CRUD for workspace files
│   └── utils/
│       ├── formatter.js          ← Terminal color/formatting helpers
│       └── validator.js          ← Path sanitization & ValidationError
├── workspace/                    ← Sandboxed file area (CRUD target, also what gets scanned/watched)
├── reports/                      ← Static HTML reports are saved here (auto-created)
├── package.json
└── README.md
```

---

## 🚀 Quick Start

```bash
npm install        # no-op — zero dependencies, but keeps the workflow familiar
node src/index.js help

# Open the live dashboard (this is the fun part):
node src/index.js serve
```

---

## 💡 Commands

### `sysinfo` — System Information Report

```bash
node src/index.js sysinfo
```

Collects and displays:

| Field             | Source                              |
|-------------------|-------------------------------------|
| OS Type           | `os.type()`                         |
| Platform          | `os.platform()`                     |
| OS Release        | `os.release()`                      |
| CPU Architecture  | `os.arch()`                         |
| Hostname          | `os.hostname()`                     |
| Node.js Version   | `process.version`                   |
| Username          | `os.userInfo().username`            |
| Home Directory    | `os.homedir()`                      |
| CPU Model & Cores | `os.cpus()`                         |
| Memory (total/used/free) | `os.totalmem()` / `os.freemem()` |
| PATH / HOME / SHELL / NODE_ENV | `process.env.*`        |

All fields degrade gracefully to `'-'` if unavailable (e.g. sandboxed/containerized systems).

---

### `scan` — Real-Time Threat Scanner ⚠️ NEW

```bash
node src/index.js scan                    # coloured console report
node src/index.js scan --format json      # machine-readable JSON
node src/index.js scan --format html      # full HTML dashboard  ← saved to ./reports/
```

The scanner runs three independent passes in parallel:

#### 1. Workspace File Scan
Reads every file in `./workspace/` and matches against 12 code-level threat signatures:

| Signature ID       | Type                  | Severity | What it catches |
|--------------------|-----------------------|----------|-----------------|
| `EVAL_DYNAMIC`     | Virus Pattern         | CRITICAL | `eval(atob(...))` — base64 payload dropper |
| `HEX_OBFUSCATION`  | Code Obfuscation      | HIGH     | Long hex-escape chains |
| `BASE64_EXEC`      | Virus Pattern         | CRITICAL | `exec(Buffer.from(..., 'base64'))` |
| `SHELL_SPAWN`      | Shell Injection       | CRITICAL | `child_process.exec('curl / rm / bash ...')` |
| `ENV_EXFIL`        | Data Exfiltration     | HIGH     | `process.env` sent via `fetch`/`axios` |
| `CRYPTO_WALLET`    | Crypto Miner          | CRITICAL | `stratum+tcp`, `xmrig`, `nicehash` |
| `REVERSE_SHELL`    | Backdoor              | CRITICAL | `bash -i`, `/dev/tcp/`, `mkfifo` |
| `DROPPER_FETCH`    | Virus Pattern         | HIGH     | `fetch().then(writeFile)` dropper pattern |
| `MASS_DELETE`      | Shell Injection       | HIGH     | `fs.unlink('/')` wiper |
| `LONG_STRING_OBFUS`| Code Obfuscation      | MEDIUM   | 300+ char base64-like strings |
| `DOCUMENT_WRITE`   | Code Obfuscation      | MEDIUM   | `document.write(unescape(...))` XSS dropper |
| `HIDDEN_FILE`      | Hidden File           | MEDIUM   | Any `.dotfile` in workspace |
| `RISKY_EXT`        | Suspicious Extension  | HIGH     | `.exe`, `.bat`, `.sh`, `.dll` etc. in workspace |

For every finding, the scanner reports:
- **Severity** (CRITICAL / HIGH / MEDIUM / LOW)
- **Type** (human-readable threat category)
- **Exact file path** (location of the threat)
- **Line number** within the file
- **Code excerpt** showing the matching region

#### 2. Environment Variable Scan
Checks `process.env` against 9 known-dangerous key names:

| Key                      | Severity | Risk |
|--------------------------|----------|------|
| `LD_PRELOAD`             | CRITICAL | Library injection |
| `DYLD_INSERT_LIBRARIES`  | CRITICAL | macOS library injection |
| `NODE_OPTIONS`           | HIGH     | `--require` malicious modules |
| `NODE_PATH`              | MEDIUM   | Module resolution hijack |
| `NPM_TOKEN`              | HIGH     | Registry credential leak |
| `AWS_SECRET_ACCESS_KEY`  | CRITICAL | AWS credential exposure |
| `GITHUB_TOKEN`           | HIGH     | GitHub token exposure |
| `DATABASE_URL`           | HIGH     | DB connection string exposure |
| `PRIVATE_KEY`            | CRITICAL | Cryptographic key in env |

#### 3. System Anomaly Scan
Inspects OS-level metrics:

| Check               | Threshold       | Severity |
|---------------------|-----------------|----------|
| Memory usage        | ≥ 90%           | CRITICAL |
| Memory usage        | ≥ 75%           | MEDIUM   |
| System uptime       | < 120 seconds   | LOW (recent restart) |

---

### `report` — Alias for scan

```bash
node src/index.js report --format html
```

---

### `serve` — Live Web Dashboard 🆕 (real-time, in your browser)

```bash
node src/index.js serve                          # http://localhost:4500, opens automatically
node src/index.js serve --port 8080               # custom port
node src/index.js serve --interval 3000            # heartbeat re-scan every 3s instead of 5s
node src/index.js serve --no-open                   # don't auto-launch the browser
```

This starts a small local web server and opens a **live threat-radar dashboard** in your browser. Unlike `scan --format html` (which writes one static snapshot to disk), `serve` keeps running and keeps the page live:

- **Instant, automatic reports.** The server watches `./workspace/` with `fs.watch`. The moment a file is created, edited, renamed, or deleted — by you, by a script, by `sysscope files create/update/delete` in another terminal, by your editor's autosave — it re-runs the full scan and pushes the new report to the open page in well under a second. You never click refresh.
- **A heartbeat scan** (every 5s by default, configurable with `--interval`) also runs continuously, so things that aren't file events — a dangerous env var being exported, memory pressure climbing, a fresh reboot — still surface in real time.
- **Threat Radar.** A circular radar sweep plots every finding as a blip: angle = which layer it came from (workspace / environment / system), distance from center = severity (critical findings sit closest to the core). Click a blip to jump straight to its detail card.
- **Live feed.** A scrolling, timestamped console log announces each new finding the instant it's detected, and each one that gets resolved (e.g. you delete the offending file) — `NEW`, `RESOLVED`, with severity and exact location.
- **Exact location, every time.** Every card and every blip carries the same location data as the console/JSON/static-HTML reports: file path + line number for code findings, the env var name for environment leaks, the metric name for system anomalies.
- **System vitals panel.** Live memory usage bar, CPU, hostname, OS, Node version, and uptime — refreshed on every scan.
- **Severity filter chips** to instantly narrow the findings list to Critical / High / Medium / Low.
- **Connection status indicator** (`LIVE` / `RECONNECTING`) so you always know whether you're looking at current data.
- **Zero dependencies, fully self-contained.** Built with Node's built-in `http` module and Server-Sent Events (no Express, no Socket.IO, no WebSocket library) and a single inline HTML/CSS/JS page (no React, no CDN fonts, no build step).

**Try it:** run `node src/index.js serve`, then in a second terminal run
`node src/index.js files create payload.js --content "eval(atob('bWFsd2FyZQ=='))"`
and watch the dashboard update itself the instant the file hits disk.

Stop the server with `Ctrl+C`.

---

### `files` — Sandboxed CRUD File Manager

All operations are **sandboxed to `./workspace/`** — path traversal (`../`) and absolute paths are blocked at the validation layer.

```bash
# List all workspace files
node src/index.js files list

# Create a new file (allowed extensions: .js .ts .json .md .py .html .css .sh ...)
node src/index.js files create notes.md --content "# Hello World"
echo "content here" | node src/index.js files create script.js

# Read a file
node src/index.js files read notes.md

# Update an existing file
node src/index.js files update notes.md --content "# Updated"

# Delete (interactive confirmation unless --force)
node src/index.js files delete notes.md
node src/index.js files delete notes.md --force
```

---

## 🏗️ Code Flow & Strategy

```
process.argv
    │
    ▼
parseArgs()                         Splits positional args from --flags
    │
    ▼
main() dispatcher
    │
    ├─ sysinfo ──► getSystemInfo()  Collects os/cpu/mem/env (pure, no side effects)
    │                  │
    │              printSystemInfo() Renders colored terminal table
    │
    ├─ scan ─────► runFullScan(workspaceDir)      ← threatScanner.js
    │              ┌──────────────────────────────────────────────┐
    │              │  Promise.all([                               │
    │              │    scanWorkspace(dir)    ← reads files       │
    │              │    scanEnvironment()    ← checks process.env │
    │              │    scanSystemAnomalies() ← checks os.*       │
    │              │  ])                                          │
    │              └──────────────────────────────────────────────┘
    │                  │
    │              reporter.js (format switch)
    │              ├─ console → printScanReport()
    │              ├─ json    → printJsonReport()
    │              └─ html    → generateHtml() → saveHtmlReport()
    │                                              (./reports/*.html)
    │
    ├─ serve ────► startDashboardServer()         ← dashboardServer.js
    │              ┌──────────────────────────────────────────────┐
    │              │  http.createServer()                         │
    │              │    GET /        → dashboardView.js (HTML shell) │
    │              │    GET /events  → Server-Sent Events stream  │
    │              │    GET /api/scan → force an immediate rescan │
    │              │                                              │
    │              │  fs.watch(workspaceDir) ─► debounce(200ms) ─►│
    │              │    runScanAndBroadcast('file-change')        │
    │              │                                              │
    │              │  setInterval(..., interval) ─►               │
    │              │    runScanAndBroadcast('interval')           │
    │              └──────────────────────────────────────────────┘
    │                  Each scan diffs against the previous one to
    │                  compute newFindings/resolvedFindings, then
    │                  broadcasts one SSE "scan" event to every
    │                  connected browser tab.
    │
    └─ files ────► fileManager.js
                   ├─ listFiles()    fs.readdir + fs.stat
                   ├─ createFile()   resolveWorkspacePath + fs.writeFile
                   ├─ readFile()     fs.readFile
                   ├─ updateFile()   fs.writeFile (must exist)
                   └─ deleteFile()   fs.unlink (with confirmation)
```

### Key Design Decisions

**1. Pure data / pure render separation**  
`systemInfo.js` and `threatScanner.js` return plain JS objects with zero console output. Rendering is handled entirely by `reporter.js` and `formatter.js`. This makes the scanner easily testable and JSON-pipeable.

**2. Parallel scanning**  
`runFullScan()` runs workspace, env, and system checks simultaneously with `Promise.all`, minimising latency.

**3. Regex-based signature matching**  
Each threat signature is a `{ id, pattern, type, severity, description }` object. Adding a new threat requires one array entry, not changes to control flow.

**4. Safe fallbacks everywhere**  
Every `os.*` call is wrapped in a `safe(fn, fallback)` helper that catches throws and returns a default. The scanner never crashes due to a missing syscall.

**5. Sandbox enforcement**  
`resolveWorkspacePath()` resolves the user-supplied filename to an absolute path and verifies it is a descendant of `WORKSPACE_DIR`. Any `..` traversal or absolute path is rejected with a `ValidationError` before any filesystem call is made.

**6. HTML report as a standalone file**  
The HTML dashboard is fully self-contained (no CDN dependencies) — it uses only inline CSS and vanilla JS, so it opens correctly offline.

**7. Real-time without a frontend framework or extra dependencies**  
`serve` is built entirely from Node's built-in `http` module and the browser's native `EventSource` API (Server-Sent Events) — no Express, no Socket.IO, no React, no bundler. `fs.watch` on the workspace directory turns filesystem activity into an immediate re-scan (debounced 200ms to coalesce rapid writes), so "run a command → see it on the page" happens automatically, with no manual refresh and no polling lag. A periodic heartbeat scan covers everything that isn't a file event (env vars, memory, uptime). Each scan is diffed against the previous one so the dashboard can announce exactly what's new and what just got resolved, instead of just re-rendering an undifferentiated list.

---

## 📊 Output Formats

| Format    | Best for                          | How to use                          |
|-----------|-----------------------------------|-------------------------------------|
| `console` | Interactive terminal review       | `node src/index.js scan`            |
| `json`    | CI/CD pipeline integration        | `node src/index.js scan --format json \| jq .` |
| `html`    | One-off static snapshot, sharing  | `node src/index.js scan --format html` → open `./reports/*.html` |
| `live`    | Real-time monitoring while you work | `node src/index.js serve` → auto-opens in browser, updates itself |

---

## 🛡️ Error Handling

| Scenario                          | Handling |
|-----------------------------------|----------|
| `os.*` call throws (containerized)| `safe()` returns fallback, report continues |
| File is binary (not UTF-8)        | `readFile` error caught silently, file skipped |
| Workspace doesn't exist yet       | `scanWorkspace` returns `[]`, no crash |
| `--format` not recognised         | Falls back to `console` |
| Path traversal in `files` command | `ValidationError` thrown, message printed, exit 1 |
| File not found in workspace       | `ValidationError` with helpful message |
| Unknown command                   | Error + help text printed, exit 1 |
| `serve` port already in use       | Clear error message suggesting `--port <next>`, exit 1 |
| `fs.watch` recursive unsupported (some Linux setups) | Falls back to non-recursive watch; heartbeat scan still covers everything |
| Browser tab disconnects/reconnects | `EventSource` auto-reconnects; status pill shows `RECONNECTING` |
| Overlapping scans (fast edits)    | A scan-in-progress flag skips redundant runs; the debounce + heartbeat ensure nothing is missed |

---

## 📦 Requirements

- Node.js ≥ 18.0.0
- No external dependencies (zero-dep) — including the live dashboard, which uses only Node's built-in `http`/`fs` and the browser's native `EventSource`
- A modern browser for `sysscope serve` (Chrome, Firefox, Safari, Edge — anything with SSE support)

---


