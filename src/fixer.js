'use strict';

const fs = require('fs');
const path = require('path');
const { scan } = require('./scanner');
const { gitRoot, ensureFileLine, uniqueEnvName, parseDotEnvKeys } = require('./utils');

function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function replacementFor(filePath, envName) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.py') return `os.getenv("${envName}")`;
  if (['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].includes(ext)) return `process.env.${envName}`;
  return null;
}

function addPythonImportIfNeeded(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext !== '.py') return false;
  let text = fs.readFileSync(filePath, 'utf8');
  if (/^\s*import\s+os\b/m.test(text) || /^\s*from\s+os\s+import\b/m.test(text)) return false;

  const lines = text.split(/\r?\n/);
  let insertAt = 0;
  if (lines[0] && lines[0].startsWith('#!')) insertAt = 1;
  if (lines[insertAt] && /coding[:=]\s*[-\w.]+/.test(lines[insertAt])) insertAt += 1;
  lines.splice(insertAt, 0, 'import os');
  fs.writeFileSync(filePath, lines.join('\n'));
  return true;
}

function replaceStringLiteral(filePath, secret, envName) {
  const repl = replacementFor(filePath, envName);
  if (!repl) return { changed: false, reason: 'Unsupported file type for safe auto-fix' };

  const before = fs.readFileSync(filePath, 'utf8');
  const escaped = escapeRegExp(secret);
  const quoteClass = path.extname(filePath).toLowerCase() === '.py' ? `(['"])` : `(['"\`])`;
  const literalRe = new RegExp(`${quoteClass}${escaped}\\1`, 'g');
  if (!literalRe.test(before)) {
    return { changed: false, reason: 'Secret was not a standalone quoted string literal' };
  }

  const after = before.replace(literalRe, () => repl);
  if (before === after) return { changed: false, reason: 'No replacement made' };
  fs.writeFileSync(filePath, after);
  const imported = addPythonImportIfNeeded(filePath);
  return { changed: true, imported };
}

function ensureEnvFiles(root, envPairs, apply) {
  const envPath = path.join(root, '.env');
  const examplePath = path.join(root, '.env.example');
  const gitignorePath = path.join(root, '.gitignore');
  const actions = [];

  for (const [name, value] of envPairs) {
    actions.push({ type: 'env', file: '.env', line: `${name}=${value}` });
    actions.push({ type: 'env-example', file: '.env.example', line: `${name}=your_${name.toLowerCase()}_here` });
  }
  actions.push({ type: 'gitignore', file: '.gitignore', line: '.env' });

  if (!apply) return actions;

  for (const [name, value] of envPairs) {
    ensureFileLine(envPath, `${name}=${value}`);
    ensureFileLine(examplePath, `${name}=your_${name.toLowerCase()}_here`);
  }
  ensureFileLine(gitignorePath, '.env');
  return actions;
}

function fix(target = '.', options = {}) {
  const root = gitRoot() || process.cwd();
  const findings = scan(target, {
    staged: options.staged,
    tracked: options.tracked,
    pushFiles: options.pushFiles,
    prePushInput: options.prePushInput,
    paranoid: options.paranoid,
    includeLocks: options.includeLocks,
    maxSizeBytes: options.maxSizeBytes
  });
  const fixable = findings.filter(f => f.autoFixable && f.match && f.envName);
  const existingEnv = fs.existsSync(path.join(root, '.env')) ? fs.readFileSync(path.join(root, '.env'), 'utf8') : '';
  const usedEnvNames = parseDotEnvKeys(existingEnv);
  const secretToEnvName = new Map();
  const envPairs = [];
  const fileActions = [];
  const processedOccurrences = new Set();

  for (const finding of fixable) {
    const occurrenceKey = `${finding.file}:${finding.match}`;
    if (processedOccurrences.has(occurrenceKey)) continue;
    processedOccurrences.add(occurrenceKey);
    let envName = secretToEnvName.get(finding.match);
    if (!envName) {
      envName = uniqueEnvName(finding.envName, usedEnvNames);
      secretToEnvName.set(finding.match, envName);
      envPairs.push([envName, finding.match]);
    }

    const relFile = path.relative(root, finding.file) || finding.file;
    if (!options.apply) {
      fileActions.push({ file: relFile, line: finding.line, envName, status: 'would-replace' });
      continue;
    }

    const result = replaceStringLiteral(finding.file, finding.match, envName);
    fileActions.push({ file: relFile, line: finding.line, envName, status: result.changed ? 'replaced' : 'skipped', reason: result.reason, imported: result.imported });
  }

  const envActions = ensureEnvFiles(root, envPairs, options.apply);

  return {
    root,
    totalFindings: findings.length,
    fixableCount: fixable.length,
    fileActions,
    envActions,
    remainingUnfixable: findings.filter(f => !f.autoFixable).map(f => ({
      file: path.relative(root, f.file) || f.file,
      line: f.line,
      title: f.title,
      redacted: f.redacted,
      help: f.help
    }))
  };
}

module.exports = { fix };
