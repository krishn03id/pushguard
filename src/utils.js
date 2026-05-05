'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const SKIP_DIRS = new Set([
  '.git', 'node_modules', '.venv', 'venv', 'env', 'dist', 'build', '.next',
  '.cache', '__pycache__', 'coverage', '.gradle', '.idea', '.vscode', 'target',
  '.turbo', '.parcel-cache', '.pytest_cache', '.mypy_cache', '.ruff_cache',
  'Pods', 'vendor/bundle'
]);

const SKIP_FILE_NAMES = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'Cargo.lock',
  'Gemfile.lock', 'composer.lock'
]);

function parseSize(value, fallback = 5 * 1024 * 1024) {
  if (value === undefined || value === null || value === '') return fallback;
  const s = String(value).trim().toLowerCase();
  const m = s.match(/^(\d+(?:\.\d+)?)(kb|k|mb|m|gb|g|b)?$/);
  if (!m) return fallback;
  const n = Number(m[1]);
  const unit = m[2] || 'b';
  if (unit === 'gb' || unit === 'g') return Math.floor(n * 1024 * 1024 * 1024);
  if (unit === 'mb' || unit === 'm') return Math.floor(n * 1024 * 1024);
  if (unit === 'kb' || unit === 'k') return Math.floor(n * 1024);
  return Math.floor(n);
}

function isProbablyTextBuffer(buf) {
  if (!buf || buf.length === 0) return true;
  if (buf.includes(0)) return false;

  const sample = buf.subarray(0, Math.min(buf.length, 8192));
  let suspiciousControls = 0;
  for (const b of sample) {
    // Allow tab, LF, CR, ESC. Treat other C0 controls as binary-ish.
    if (b < 32 && ![9, 10, 13, 27].includes(b)) suspiciousControls++;
  }
  return suspiciousControls / sample.length < 0.03;
}

function safeRead(filePath, options = {}) {
  try {
    const maxSizeBytes = options.maxSizeBytes || 5 * 1024 * 1024;
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return null;
    if (stat.size > maxSizeBytes) return null;
    const buf = fs.readFileSync(filePath);
    if (!isProbablyTextBuffer(buf)) return null;
    return buf.toString('utf8');
  } catch (_) {
    return null;
  }
}

function shouldSkipFile(filePath, options = {}) {
  if (options.includeLocks) return false;
  return SKIP_FILE_NAMES.has(path.basename(filePath));
}

function walk(dir, out = [], options = {}) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (_) {
    return out;
  }

  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, out, options);
    } else if (entry.isFile()) {
      if (!shouldSkipFile(full, options)) out.push(full);
    }
  }
  return out;
}

function gitRoot(cwd = process.cwd()) {
  try {
    return execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch (_) {
    return null;
  }
}

function getTrackedFiles(cwd = process.cwd(), options = {}) {
  try {
    const root = gitRoot(cwd) || cwd;
    const output = execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' });
    return output
      .split(/\r?\n/)
      .filter(Boolean)
      .map(p => path.join(root, p))
      .filter(p => fs.existsSync(p) && fs.statSync(p).isFile() && !shouldSkipFile(p, options));
  } catch (_) {
    return [];
  }
}

function getStagedFiles(cwd = process.cwd(), options = {}) {
  try {
    const root = gitRoot(cwd) || cwd;
    const output = execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACMR'], { cwd: root, encoding: 'utf8' });
    return output
      .split(/\r?\n/)
      .filter(Boolean)
      .map(p => path.join(root, p))
      .filter(p => fs.existsSync(p) && fs.statSync(p).isFile() && !shouldSkipFile(p, options));
  } catch (_) {
    return [];
  }
}

function redact(value) {
  if (!value) return value;
  const s = String(value);
  if (s.length <= 8) return '*'.repeat(s.length);
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

function lineNumberAt(text, index) {
  return text.slice(0, index).split(/\r?\n/).length;
}

function ensureFileLine(filePath, line) {
  const existing = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
  if (existing.split(/\r?\n/).includes(line)) return false;
  const prefix = existing && !existing.endsWith('\n') ? '\n' : '';
  fs.appendFileSync(filePath, prefix + line + '\n');
  return true;
}

function uniqueEnvName(base, used) {
  let name = base.replace(/[^A-Z0-9_]/g, '_').replace(/_+/g, '_').replace(/^_+|_+$/g, '') || 'SECRET_VALUE';
  if (!/^[A-Z_]/.test(name)) name = `SECRET_${name}`;
  let candidate = name;
  let n = 2;
  while (used.has(candidate)) {
    candidate = `${name}_${n++}`;
  }
  used.add(candidate);
  return candidate;
}

function parseDotEnvKeys(content) {
  const keys = new Set();
  for (const line of content.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/);
    if (m) keys.add(m[1]);
  }
  return keys;
}

const ZERO_SHA_RE = /^0{40,64}$/;

function isZeroSha(sha) {
  return !sha || ZERO_SHA_RE.test(String(sha));
}

function gitOutput(args, cwd = process.cwd(), options = {}) {
  return execFileSync('git', args, {
    cwd,
    encoding: options.encoding || 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
    maxBuffer: options.maxBuffer || 20 * 1024 * 1024
  }).trim();
}

function emptyTreeSha(cwd = process.cwd()) {
  return gitOutput(['hash-object', '-t', 'tree', '/dev/null'], cwd);
}

function parsePrePushInput(input = '') {
  const specs = [];
  for (const rawLine of String(input || '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 4) continue;
    const [localRef, localSha, remoteRef, remoteSha] = parts;
    if (isZeroSha(localSha)) continue; // branch deletion; nothing new to scan
    specs.push({ localRef, localSha, remoteRef, remoteSha });
  }
  return specs;
}

function defaultPushSpecs(cwd = process.cwd()) {
  // Useful for manual debugging: `pushguard scan --pre-push` outside an actual hook.
  try {
    const root = gitRoot(cwd) || cwd;
    const localSha = gitOutput(['rev-parse', 'HEAD'], root);
    let remoteSha = '';
    try {
      remoteSha = gitOutput(['merge-base', 'HEAD', '@{u}'], root);
    } catch (_) {
      remoteSha = emptyTreeSha(root);
    }
    return [{ localRef: 'HEAD', localSha, remoteRef: '@{u}', remoteSha }];
  } catch (_) {
    return [];
  }
}

function getPrePushSpecs(input = '', cwd = process.cwd()) {
  const parsed = parsePrePushInput(input);
  return parsed.length ? parsed : defaultPushSpecs(cwd);
}

function getOutgoingCommits(root, baseSha, localSha) {
  if (!localSha || isZeroSha(localSha)) return [];
  try {
    const range = isZeroSha(baseSha) ? [localSha] : [`${baseSha}..${localSha}`];
    const output = gitOutput(['rev-list', '--reverse', ...range], root, { maxBuffer: 50 * 1024 * 1024 });
    return output.split(/\r?\n/).filter(Boolean);
  } catch (_) {
    return [];
  }
}

function getChangedFilesForCommit(root, commitSha, options = {}) {
  let output = '';
  try {
    output = gitOutput(['diff-tree', '--root', '--no-commit-id', '--name-only', '-r', '--diff-filter=ACMR', commitSha], root, { maxBuffer: 50 * 1024 * 1024 });
  } catch (_) {
    return [];
  }
  return output
    .split(/\r?\n/)
    .filter(Boolean)
    .filter(file => !shouldSkipFile(path.join(root, file), options));
}

function getPushedFileSpecs(input = '', cwd = process.cwd(), options = {}) {
  const root = gitRoot(cwd) || cwd;
  const refs = getPrePushSpecs(input, root);
  const seen = new Map();

  for (const refSpec of refs) {
    const commits = getOutgoingCommits(root, refSpec.remoteSha, refSpec.localSha);
    for (const commitSha of commits) {
      const files = getChangedFilesForCommit(root, commitSha, options);
      for (const file of files) {
        const key = `${commitSha}:${file}`;
        if (seen.has(key)) continue;
        seen.set(key, {
          root,
          path: file,
          filePath: path.join(root, file),
          ref: commitSha,
          localRef: refSpec.localRef,
          remoteRef: refSpec.remoteRef,
          remoteSha: refSpec.remoteSha,
          localSha: refSpec.localSha
        });
      }
    }
  }

  return Array.from(seen.values());
}

function readGitBlobText(spec, options = {}) {
  try {
    const maxSizeBytes = options.maxSizeBytes || 5 * 1024 * 1024;
    const objectRef = `${spec.ref}:${spec.path}`;
    const sizeRaw = gitOutput(['cat-file', '-s', objectRef], spec.root);
    const size = Number(sizeRaw);
    if (!Number.isFinite(size) || size > maxSizeBytes) return null;
    const buf = execFileSync('git', ['show', objectRef], {
      cwd: spec.root,
      encoding: 'buffer',
      stdio: ['ignore', 'pipe', 'ignore'],
      maxBuffer: Math.max(maxSizeBytes + 1024, 1024 * 1024)
    });
    if (!isProbablyTextBuffer(buf)) return null;
    return buf.toString('utf8');
  } catch (_) {
    return null;
  }
}

module.exports = {
  SKIP_DIRS,
  SKIP_FILE_NAMES,
  parseSize,
  isProbablyTextBuffer,
  safeRead,
  walk,
  gitRoot,
  getStagedFiles,
  getTrackedFiles,
  redact,
  lineNumberAt,
  ensureFileLine,
  uniqueEnvName,
  parseDotEnvKeys,
  isZeroSha,
  parsePrePushInput,
  getPrePushSpecs,
  getOutgoingCommits,
  getChangedFilesForCommit,
  getPushedFileSpecs,
  readGitBlobText
};
