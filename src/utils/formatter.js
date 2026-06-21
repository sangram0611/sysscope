// Lightweight, dependency-free terminal formatting. Falls back to plain text
// automatically when not running in a TTY (e.g. piped output, CI logs).
const codes = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
};

const supportsColor = Boolean(process.stdout.isTTY) && process.env.NO_COLOR === undefined;

function paint(code, text) {
  return supportsColor ? `${code}${text}${codes.reset}` : text;
}

export const color = {
  bold: (t) => paint(codes.bold, t),
  dim: (t) => paint(codes.dim, t),
  red: (t) => paint(codes.red, t),
  green: (t) => paint(codes.green, t),
  yellow: (t) => paint(codes.yellow, t),
  blue: (t) => paint(codes.blue, t),
  magenta: (t) => paint(codes.magenta, t),
  cyan: (t) => paint(codes.cyan, t),
};

export function printHeader(title) {
  const line = '─'.repeat(Math.max(title.length + 4, 40));
  console.log(color.cyan(line));
  console.log(color.bold(color.cyan(`  ${title}`)));
  console.log(color.cyan(line));
}

export function printRow(label, value) {
  console.log(`  ${color.dim(String(label).padEnd(16, ' '))} ${value}`);
}

export function printSuccess(message) {
  console.log(color.green(`✔ ${message}`));
}

export function printError(message) {
  console.error(color.red(`✘ ${message}`));
}

export function printWarning(message) {
  console.log(color.yellow(`⚠ ${message}`));
}

export function printInfo(message) {
  console.log(color.blue(`ℹ ${message}`));
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const exp = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** exp;
  return `${exp === 0 ? value : value.toFixed(2)} ${units[exp]}`;
}

function truncate(str, max) {
  if (typeof str !== 'string') return str ?? '-';
  return str.length > max ? `${str.slice(0, max)}…` : str;
}

/**
 * Renders the structured system info object from systemInfo.js as a
 * readable, sectioned console report.
 */
export function printSystemInfo(info) {
  console.log();
  console.log(color.bold('  Operating System'));
  printRow('Type', info.os?.type ?? '-');
  printRow('Platform', info.os?.platform ?? '-');
  printRow('Release', info.os?.release ?? '-');
  printRow('Architecture', info.os?.arch ?? '-');
  printRow('Hostname', info.hostname ?? '-');

  console.log();
  console.log(color.bold('  Node.js'));
  printRow('Version', info.nodeVersion ?? '-');

  console.log();
  console.log(color.bold('  User'));
  printRow('Username', info.username ?? '-');
  printRow('Home Dir', info.homeDir ?? '-');

  console.log();
  console.log(color.bold('  CPU'));
  printRow('Model', info.cpu?.model ?? '-');
  printRow('Cores', info.cpu?.cores ?? '-');
  printRow('Speed', info.cpu?.speedMHz ? `${info.cpu.speedMHz} MHz` : '-');

  console.log();
  console.log(color.bold('  Memory'));
  printRow('Total', info.memory?.totalMB !== undefined ? `${info.memory.totalMB} MB` : '-');
  printRow(
    'Used',
    info.memory?.usedMB !== undefined ? `${info.memory.usedMB} MB (${info.memory.usedPercent}%)` : '-'
  );
  printRow('Free', info.memory?.freeMB !== undefined ? `${info.memory.freeMB} MB` : '-');

  console.log();
  console.log(color.bold('  Environment Variables'));
  printRow('PATH', truncate(info.env?.PATH, 60));
  printRow('HOME', info.env?.HOME ?? '-');
  printRow('SHELL', info.env?.SHELL ?? '-');
  printRow('NODE_ENV', info.env?.NODE_ENV ?? '-');
  console.log();
}
