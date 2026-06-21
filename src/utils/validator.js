import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Workspace is anchored to the package location (src/utils -> ../../workspace),
// not process.cwd(), so the sandbox boundary holds no matter where the CLI is invoked from.
const WORKSPACE_DIR = path.resolve(__dirname, '../../workspace');

export class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ValidationError';
  }
}

export function getWorkspaceDir() {
  return WORKSPACE_DIR;
}

export function ensureWorkspaceExists() {
  if (!fs.existsSync(WORKSPACE_DIR)) {
    fs.mkdirSync(WORKSPACE_DIR, { recursive: true });
  }
}

/**
 * Resolves a user-supplied filename to an absolute path guaranteed to live
 * inside the workspace directory. Throws ValidationError on anything that
 * looks like an attempt to escape the sandbox (absolute paths, "..", symlinked
 * traversal, empty input).
 */
export function resolveWorkspacePath(filename) {
  if (typeof filename !== 'string' || filename.trim() === '') {
    throw new ValidationError('Filename cannot be empty.');
  }

  if (filename.includes('\0')) {
    throw new ValidationError('Filename contains invalid characters.');
  }

  if (path.isAbsolute(filename)) {
    throw new ValidationError('Absolute paths are not allowed. Use a name relative to the workspace.');
  }

  const resolved = path.resolve(WORKSPACE_DIR, filename);
  const relative = path.relative(WORKSPACE_DIR, resolved);

  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new ValidationError(`"${filename}" resolves outside the workspace directory and was blocked.`);
  }

  return resolved;
}
