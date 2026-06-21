import fs from 'node:fs/promises';
import path from 'node:path';
import {
  resolveWorkspacePath,
  ensureWorkspaceExists,
  getWorkspaceDir,
  ValidationError,
} from '../utils/validator.js';

// Create/update are restricted to these extensions so the tool stays a
// "code file" manager rather than a general-purpose file writer.
const ALLOWED_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx', '.json',
  '.md', '.txt', '.py', '.java', '.c', '.cpp', '.h',
  '.go', '.rs', '.rb', '.php', '.html', '.css', '.yml', '.yaml', '.sh',
]);

function assertAllowedExtension(filename) {
  const ext = path.extname(filename).toLowerCase();
  if (!ALLOWED_EXTENSIONS.has(ext)) {
    throw new ValidationError(
      `Extension "${ext || '(none)'}" is not permitted for write operations. Allowed: ${[...ALLOWED_EXTENSIONS].join(', ')}`
    );
  }
}

export async function listFiles() {
  ensureWorkspaceExists();
  const entries = await fs.readdir(getWorkspaceDir(), { withFileTypes: true });
  const files = entries.filter((entry) => entry.isFile());

  return Promise.all(
    files.map(async (entry) => {
      const fullPath = path.join(getWorkspaceDir(), entry.name);
      const stats = await fs.stat(fullPath);
      return { name: entry.name, sizeBytes: stats.size, modified: stats.mtime };
    })
  ).then((list) => list.sort((a, b) => a.name.localeCompare(b.name)));
}

export async function createFile(filename, content = '') {
  assertAllowedExtension(filename);
  const fullPath = resolveWorkspacePath(filename);
  ensureWorkspaceExists();

  const exists = await fs
    .access(fullPath)
    .then(() => true)
    .catch(() => false);

  if (exists) {
    throw new ValidationError(`File "${filename}" already exists. Use "files update" to modify it.`);
  }

  await fs.writeFile(fullPath, content, 'utf8');
  return fullPath;
}

export async function readFile(filename) {
  const fullPath = resolveWorkspacePath(filename);
  try {
    return await fs.readFile(fullPath, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new ValidationError(`File "${filename}" does not exist in the workspace.`);
    }
    throw err;
  }
}

export async function updateFile(filename, content) {
  assertAllowedExtension(filename);
  const fullPath = resolveWorkspacePath(filename);

  const exists = await fs
    .access(fullPath)
    .then(() => true)
    .catch(() => false);

  if (!exists) {
    throw new ValidationError(`File "${filename}" does not exist. Use "files create" first.`);
  }

  await fs.writeFile(fullPath, content, 'utf8');
  return fullPath;
}

export async function deleteFile(filename) {
  const fullPath = resolveWorkspacePath(filename);
  try {
    await fs.unlink(fullPath);
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new ValidationError(`File "${filename}" does not exist in the workspace.`);
    }
    throw err;
  }
  return fullPath;
}
