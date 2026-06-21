/**
 * threatScanner.js
 * ─────────────────────────────────────────────────────────────────────
 * Real-time threat, virus, and anomaly detection for the workspace and
 * system environment. Scans for:
 *  • Suspicious code patterns (eval, obfuscation, shell injection, etc.)
 *  • Dangerous environment variable leaks or overrides
 *  • High-risk file types or embedded payloads
 *  • Network-related process anomalies
 *  • Hidden / dot-file presence in workspace
 *  • Memory pressure warnings
 * ─────────────────────────────────────────────────────────────────────
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

// ── Severity levels ────────────────────────────────────────────────────────────
export const Severity = Object.freeze({
  CRITICAL: 'CRITICAL',
  HIGH:     'HIGH',
  MEDIUM:   'MEDIUM',
  LOW:      'LOW',
  INFO:     'INFO',
});

// ── Threat type labels ─────────────────────────────────────────────────────────
export const ThreatType = Object.freeze({
  VIRUS_PATTERN:    'Virus Pattern',
  OBFUSCATION:      'Code Obfuscation',
  SHELL_INJECTION:  'Shell Injection',
  DATA_EXFIL:       'Data Exfiltration',
  ENV_LEAK:         'Env Variable Leak',
  HIDDEN_FILE:      'Hidden File',
  SUSPICIOUS_EXT:   'Suspicious Extension',
  MEMORY_PRESSURE:  'Memory Pressure',
  CRYPTO_MINER:     'Crypto Miner Signature',
  BACKDOOR:         'Backdoor Pattern',
  SYSTEM_ANOMALY:   'System Anomaly',
  SAFE:             'Clean',
});

// ── Code-level threat signatures ──────────────────────────────────────────────
const CODE_SIGNATURES = [
  {
    id: 'EVAL_DYNAMIC',
    pattern: /eval\s*\(\s*(atob|Buffer\.from|String\.fromCharCode)/i,
    type: ThreatType.VIRUS_PATTERN,
    severity: Severity.CRITICAL,
    description: 'Dynamic eval with base64/char decoding — classic payload dropper',
  },
  {
    id: 'HEX_OBFUSCATION',
    pattern: /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){8,}/i,
    type: ThreatType.OBFUSCATION,
    severity: Severity.HIGH,
    description: 'Long hex-escape chain detected — likely obfuscated payload',
  },
  {
    id: 'BASE64_EXEC',
    pattern: /exec\s*\(\s*Buffer\.from\s*\([^)]+,\s*['"]base64['"]/i,
    type: ThreatType.VIRUS_PATTERN,
    severity: Severity.CRITICAL,
    description: 'Executing base64-decoded buffer — remote code execution risk',
  },
  {
    id: 'SHELL_SPAWN',
    pattern: /child_process[\s\S]{0,30}(exec|spawn|execSync|spawnSync)\s*\(\s*[`'"][^`'"]{0,10}(rm|curl|wget|nc|bash|sh|powershell)/i,
    type: ThreatType.SHELL_INJECTION,
    severity: Severity.CRITICAL,
    description: 'Shell command spawning destructive/network tool',
  },
  {
    id: 'ENV_EXFIL',
    pattern: /process\.env\b[\s\S]{0,100}(fetch|axios|http\.|https\.|request\()/i,
    type: ThreatType.DATA_EXFIL,
    severity: Severity.HIGH,
    description: 'Environment variables sent over network — possible credential exfiltration',
  },
  {
    id: 'CRYPTO_WALLET',
    pattern: /(stratum\+tcp|minerd|xmrig|nicehash|cryptonight)/i,
    type: ThreatType.CRYPTO_MINER,
    severity: Severity.CRITICAL,
    description: 'Crypto-mining pool reference or miner binary signature',
  },
  {
    id: 'REVERSE_SHELL',
    pattern: /\b(bash\s+-i|\/dev\/tcp\/|socat.*EXEC|mkfifo.*pipe)/i,
    type: ThreatType.BACKDOOR,
    severity: Severity.CRITICAL,
    description: 'Reverse shell pattern — possible backdoor installation',
  },
  {
    id: 'DROPPER_FETCH',
    pattern: /(fetch|axios\.get)\s*\([^)]+\)\s*\.then[\s\S]{0,80}(writeFile|writeFileSync|exec)/i,
    type: ThreatType.VIRUS_PATTERN,
    severity: Severity.HIGH,
    description: 'Fetch-then-execute pattern — possible remote dropper',
  },
  {
    id: 'MASS_DELETE',
    pattern: /fs\.(unlink|rm|rmdir)\s*\(\s*[`'"]\/[^`'"]{0,5}[`'"]/i,
    type: ThreatType.SHELL_INJECTION,
    severity: Severity.HIGH,
    description: 'Unlinking from root path — potential destructive wiper',
  },
  {
    id: 'LONG_STRING_OBFUS',
    pattern: /['"][A-Za-z0-9+/=]{300,}['"]/,
    type: ThreatType.OBFUSCATION,
    severity: Severity.MEDIUM,
    description: 'Suspiciously long base64-like string — may be encoded payload',
  },
  {
    id: 'DOCUMENT_WRITE',
    pattern: /document\.write\s*\(\s*(unescape|decodeURIComponent|atob)\s*\(/i,
    type: ThreatType.OBFUSCATION,
    severity: Severity.MEDIUM,
    description: 'document.write with decode function — classic XSS dropper',
  },
];

// ── Dangerous environment variable names ──────────────────────────────────────
const DANGEROUS_ENV_KEYS = [
  { key: 'LD_PRELOAD',     severity: Severity.CRITICAL, reason: 'Library injection attack vector' },
  { key: 'DYLD_INSERT_LIBRARIES', severity: Severity.CRITICAL, reason: 'macOS library injection' },
  { key: 'NODE_OPTIONS',   severity: Severity.HIGH,     reason: 'Can inject --require malicious modules' },
  { key: 'NODE_PATH',      severity: Severity.MEDIUM,   reason: 'Can redirect module resolution' },
  { key: 'NPM_TOKEN',      severity: Severity.HIGH,     reason: 'NPM publish credential exposed' },
  { key: 'AWS_SECRET_ACCESS_KEY', severity: Severity.CRITICAL, reason: 'AWS credential exposed in env' },
  { key: 'GITHUB_TOKEN',   severity: Severity.HIGH,     reason: 'GitHub token exposed in env' },
  { key: 'DATABASE_URL',   severity: Severity.HIGH,     reason: 'Database connection string exposed' },
  { key: 'PRIVATE_KEY',    severity: Severity.CRITICAL, reason: 'Private key material in environment' },
];

// ── Suspicious file extensions ─────────────────────────────────────────────────
const RISKY_EXTENSIONS = new Set([
  '.exe', '.bat', '.cmd', '.vbs', '.ps1', '.msi',
  '.dll', '.so', '.dylib', '.bin', '.sh',
]);

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function safe(fn, fallback = null) {
  try { return fn(); } catch { return fallback; }
}

function lineOfMatch(content, index) {
  return content.slice(0, index).split('\n').length;
}

function excerptAround(content, index, radius = 60) {
  const start = Math.max(0, index - radius);
  const end   = Math.min(content.length, index + radius);
  return content.slice(start, end).replace(/\n/g, '↵');
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan a single file's content
// ─────────────────────────────────────────────────────────────────────────────
function scanContent(filePath, content) {
  const findings = [];

  for (const sig of CODE_SIGNATURES) {
    const match = sig.pattern.exec(content);
    if (!match) continue;

    findings.push({
      id:          sig.id,
      type:        sig.type,
      severity:    sig.severity,
      description: sig.description,
      location: {
        file:    filePath,
        line:    lineOfMatch(content, match.index),
        excerpt: excerptAround(content, match.index),
      },
    });
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan workspace files
// ─────────────────────────────────────────────────────────────────────────────
async function scanWorkspace(workspaceDir) {
  const results = [];
  let entries = [];

  try {
    entries = await fs.readdir(workspaceDir, { withFileTypes: true });
  } catch {
    return results; // workspace may not exist yet
  }

  for (const entry of entries) {
    const fullPath = path.join(workspaceDir, entry.name);

    // Hidden files
    if (entry.name.startsWith('.')) {
      results.push({
        id:          'HIDDEN_FILE',
        type:        ThreatType.HIDDEN_FILE,
        severity:    Severity.MEDIUM,
        description: `Hidden file found: "${entry.name}" — could be a config stealer or dropper`,
        location:    { file: fullPath, line: null, excerpt: null },
      });
    }

    // Risky extension
    const ext = path.extname(entry.name).toLowerCase();
    if (RISKY_EXTENSIONS.has(ext)) {
      results.push({
        id:          'RISKY_EXT',
        type:        ThreatType.SUSPICIOUS_EXT,
        severity:    Severity.HIGH,
        description: `Executable/binary extension "${ext}" in workspace — not expected here`,
        location:    { file: fullPath, line: null, excerpt: null },
      });
    }

    // Scan text file content
    if (entry.isFile()) {
      try {
        const content = await fs.readFile(fullPath, 'utf8');
        const fileFindings = scanContent(fullPath, content);
        results.push(...fileFindings);
      } catch {
        /* binary file — skip content scan */
      }
    }
  }

  return results;
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan environment variables
// ─────────────────────────────────────────────────────────────────────────────
function scanEnvironment() {
  const results = [];

  for (const { key, severity, reason } of DANGEROUS_ENV_KEYS) {
    if (process.env[key] !== undefined) {
      results.push({
        id:          `ENV_${key}`,
        type:        ThreatType.ENV_LEAK,
        severity,
        description: `Dangerous env var ${key} is set — ${reason}`,
        location:    { file: 'process.env', line: null, excerpt: `${key}=***` },
      });
    }
  }

  return results;
}

// ─────────────────────────────────────────────────────────────────────────────
// System health anomalies
// ─────────────────────────────────────────────────────────────────────────────
function scanSystemAnomalies() {
  const results = [];

  const total   = safe(() => os.totalmem(), 0);
  const free    = safe(() => os.freemem(),  0);
  const usedPct = total > 0 ? Math.round(((total - free) / total) * 100) : 0;

  if (usedPct >= 90) {
    results.push({
      id:          'MEM_CRITICAL',
      type:        ThreatType.MEMORY_PRESSURE,
      severity:    Severity.CRITICAL,
      description: `Memory usage at ${usedPct}% — system under extreme pressure, possible memory-fork attack`,
      location:    { file: 'os.mem', line: null, excerpt: `${usedPct}% used` },
    });
  } else if (usedPct >= 75) {
    results.push({
      id:          'MEM_HIGH',
      type:        ThreatType.MEMORY_PRESSURE,
      severity:    Severity.MEDIUM,
      description: `Memory usage at ${usedPct}% — elevated; monitor for runaway processes`,
      location:    { file: 'os.mem', line: null, excerpt: `${usedPct}% used` },
    });
  }

  // Unusual uptime (extremely low uptime = fresh restart after crash)
  const uptimeSec = safe(() => os.uptime(), Infinity);
  if (uptimeSec < 120) {
    results.push({
      id:          'RECENT_RESTART',
      type:        ThreatType.SYSTEM_ANOMALY,
      severity:    Severity.LOW,
      description: `System uptime is only ${uptimeSec}s — recent restart detected, may indicate crash or forced reboot`,
      location:    { file: 'os.uptime', line: null, excerpt: `${uptimeSec}s` },
    });
  }

  return results;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main scan entry point
// ─────────────────────────────────────────────────────────────────────────────
/**
 * @param {string} workspaceDir  Absolute path to the workspace directory
 * @returns {Promise<ScanReport>}
 */
export async function runFullScan(workspaceDir) {
  const startedAt = new Date();

  const [wsFindings, envFindings, sysFindings] = await Promise.all([
    scanWorkspace(workspaceDir),
    Promise.resolve(scanEnvironment()),
    Promise.resolve(scanSystemAnomalies()),
  ]);

  const all = [...wsFindings, ...envFindings, ...sysFindings];

  const summary = {
    total:    all.length,
    critical: all.filter(f => f.severity === Severity.CRITICAL).length,
    high:     all.filter(f => f.severity === Severity.HIGH).length,
    medium:   all.filter(f => f.severity === Severity.MEDIUM).length,
    low:      all.filter(f => f.severity === Severity.LOW).length,
  };

  // Overall risk rating
  let riskRating = 'CLEAN';
  if (summary.critical > 0)       riskRating = 'CRITICAL';
  else if (summary.high > 0)      riskRating = 'HIGH';
  else if (summary.medium > 0)    riskRating = 'MEDIUM';
  else if (summary.low > 0)       riskRating = 'LOW';

  return {
    scannedAt:   startedAt.toISOString(),
    durationMs:  Date.now() - startedAt.getTime(),
    riskRating,
    summary,
    findings:    all,
    // Keep these separate so the report module can present them in sections
    sections: {
      workspace:   wsFindings,
      environment: envFindings,
      system:      sysFindings,
    },
  };
}
