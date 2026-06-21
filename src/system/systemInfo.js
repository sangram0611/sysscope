import os from 'node:os';

/**
 * Wraps a lookup so a single failed field (e.g. os.userInfo() throwing on
 * some sandboxed/containerized systems) can never crash the whole report.
 */
function safe(fn, fallback = null) {
  try {
    const result = fn();
    return result === undefined ? fallback : result;
  } catch {
    return fallback;
  }
}

/**
 * Collects system, hardware, and environment information into a plain,
 * structured object. Pure data — no console output, no side effects.
 * Every field degrades to a safe fallback instead of throwing.
 */
export async function getSystemInfo() {
  return {
    os: safe(() => ({
      type: os.type(),
      platform: os.platform(),
      release: os.release(),
      arch: os.arch(),
    }), {}),

    hostname: safe(() => os.hostname()),
    nodeVersion: safe(() => process.version),
    homeDir: safe(() => os.homedir()),
    username: safe(() => os.userInfo().username),
    uptimeSec: safe(() => Math.round(os.uptime())),
    loadAvg: safe(() => os.loadavg(), [0, 0, 0]),

    memory: safe(() => {
      const total = os.totalmem();
      const free = os.freemem();
      const used = total - free;
      return {
        totalMB: Math.round(total / 1024 / 1024),
        freeMB: Math.round(free / 1024 / 1024),
        usedMB: Math.round(used / 1024 / 1024),
        usedPercent: total > 0 ? Math.round((used / total) * 100) : 0,
      };
    }, {}),

    cpu: safe(() => {
      const cpus = os.cpus() ?? [];
      return {
        model: cpus[0]?.model?.trim() ?? 'unknown',
        cores: cpus.length,
        speedMHz: cpus[0]?.speed ?? null,
      };
    }, {}),

    // Only these four variables are ever read — never the full environment.
    env: {
      PATH: process.env.PATH ?? null,
      HOME: process.env.HOME ?? process.env.USERPROFILE ?? null,
      SHELL: process.env.SHELL ?? null,
      NODE_ENV: process.env.NODE_ENV ?? 'not set',
    },
  };
}
