'use strict';

const path = require('path');
const fs = require('fs');
const { RULES, ENV_FILE_NAMES, SECRET_KEYWORD_RE } = require('./rules');
const { findProvider } = require('./providers');
const { walk, safeRead, lineNumberAt, redact, getStagedFiles, getTrackedFiles, gitRoot, getPushedFileSpecs, readGitBlobText } = require('./utils');

const PLACEHOLDER_RE = /(?:your_|example|placeholder|change[_-]?me|xxxxx|dummy|sample|test[_-]?key|not[_-]?real|real[_-]?secret|secret[_-]?here|todo|insert[_-]?here|replace[_-]?me|changeme|fake|mock)/i;
const ALLOW_RE = /pushguard:\s*allow/i;
const ENV_REF_RE = /(?:process\.env\.|os\.getenv\(|getenv\(|env\(|Deno\.env|get_config\(|settings\.)/i;
const SAFE_WORD_RE = /^(?:true|false|null|none|undefined|admin|root|password|secret|token|localhost|127\.0\.0\.1)$/i;

function shannonEntropy(s) {
  if (!s) return 0;
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function charClassScore(s) {
  let score = 0;
  if (/[a-z]/.test(s)) score++;
  if (/[A-Z]/.test(s)) score++;
  if (/\d/.test(s)) score++;
  if (/[_\-.+/=]/.test(s)) score++;
  return score;
}

function cleanSecretValue(value) {
  return String(value || '')
    .trim()
    .replace(/^[`'"\s]+|[`'"\s,;]+$/g, '')
    .replace(/\\n/g, '\n');
}


function isPlaceholderSecret(secret) {
  const s = String(secret || '');
  if (looksLikeKnownSecretShape(s) || looksLikeCredentialUrl(s)) return false;
  return PLACEHOLDER_RE.test(s);
}

function normalizeFinding(rule, rawMatch) {
  let secret = typeof rule.extract === 'function' ? rule.extract(rawMatch) : rawMatch;
  const quoted = String(secret).match(/[`'"]([^`'"]{8,})[`'"]\s*$/);
  if (quoted) secret = quoted[1];
  return { secret: cleanSecretValue(secret), envName: rule.envName };
}

function shouldIgnoreMatch(filePath, line, secret) {
  const base = path.basename(filePath);
  if (ALLOW_RE.test(line)) return true;
  if (base.endsWith('.example') || base === '.env.example' || filePath.endsWith('.sample')) return true;
  if (!secret || isPlaceholderSecret(secret)) return true;
  if (ENV_REF_RE.test(secret)) return true;
  if (SAFE_WORD_RE.test(secret)) return true;
  return false;
}

function severityForGeneric(key, value) {
  const k = key.toLowerCase();
  if (/private[_-]?key|database[_-]?url|db[_-]?url|connection[_-]?string|client[_-]?secret|signing[_-]?secret|webhook/.test(k)) return 'critical';
  if (/password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key/.test(k)) return 'high';
  return 'medium';
}

function envNameFromKey(key) {
  return key
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/^_+|_+$/g, '')
    .toUpperCase() || 'SECRET_VALUE';
}

function providerSecretScore(value, key = '') {
  const v = cleanSecretValue(value);
  if (!v || v.length < 8 || v.length > 4096) return false;
  if (PLACEHOLDER_RE.test(v) || ENV_REF_RE.test(v) || SAFE_WORD_RE.test(v)) return false;
  if (looksLikeKnownSecretShape(v) || looksLikeCredentialUrl(v)) return true;
  if (/^[A-Z][A-Z0-9_]{7,}$/.test(v)) return false;
  if (/^[a-z]+(?:-[a-z0-9]+){2,}$/.test(v)) return false;

  const entropy = shannonEntropy(v);
  const diversity = charClassScore(v);
  const strongSecretContext = /(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token|secret|client[_-]?secret|app[_-]?secret|webhook|private[_-]?key|service[_-]?role|service[_-]?key|bearer|refresh[_-]?token|password|passwd|pwd|dsn|connection[_-]?string)/i.test(key);
  const tokenish = /^[A-Za-z0-9_\-+.=/]{12,}$/.test(v);

  if (strongSecretContext && tokenish && v.length >= 12 && entropy >= 2.7 && diversity >= 2) return true;
  if (tokenish && v.length >= 20 && entropy >= 3.25 && diversity >= 2) return true;
  if (tokenish && v.length >= 32 && entropy >= 3.0) return true;
  if (/^[A-Za-z0-9_\-+/=]{24,}$/.test(v) && entropy >= 3.1) return true;
  return false;
}

function providerTitle(provider) {
  return provider && provider.title ? provider.title : 'known provider';
}

function looksLikeKnownSecretShape(value) {
  return /^(?:sk-|sk_live_|rk_live_|gh[pousr]_|github_pat_|glpat-|glrt-|gloas-|xox[baprs]-|hf_|nvapi-|r8_|SG\.|AIza|ya29\.|pypi-|npm_|key-|lin_api_|dop_v1_|shpat_|shpss_|shppa_|shpca_|gsk_|sk-or-v1-|eyJ)/.test(value)
    || /^\d{6,12}:[A-Za-z0-9_-]{30,}$/.test(value)
    || /^https:\/\/hooks\.slack\.com\/services\//.test(value)
    || /^https:\/\/discord(?:app)?\.com\/api\/webhooks\//.test(value)
    || /^[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,}$/.test(value);
}

function looksLikeCredentialUrl(value) {
  return /^(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s:@/]+:[^\s:@/]{6,}@/i.test(value);
}

function isLikelySecretValue(value, key = '') {
  const v = cleanSecretValue(value);
  if (!v || shouldIgnoreMatch('', '', v)) return false;
  if (v.length > 4096) return false;
  if (ENV_REF_RE.test(v)) return false;
  if (/^(?:https?:\/\/)?(?:localhost|127\.0\.0\.1)(?::\d+)?\/?$/i.test(v)) return false;
  if (v.startsWith('/')) return false;
  if (/[()]/.test(v)) return false;
  if (/^[A-Z][A-Z0-9_]{7,}$/.test(v)) return false;
  if (/^[a-z]+(?:-[a-z0-9]+){2,}$/.test(v)) return false;

  if (looksLikeKnownSecretShape(v) || looksLikeCredentialUrl(v)) return true;

  const secretishKey = SECRET_KEYWORD_RE.test(key);
  const entropy = shannonEntropy(v);
  const diversity = charClassScore(v);

  if (/password|passwd|pwd/i.test(key)) return v.length >= 8 && !PLACEHOLDER_RE.test(v);
  if (/database[_-]?url|db[_-]?url|connection[_-]?string|dsn/i.test(key)) return looksLikeCredentialUrl(v) || v.length >= 16;

  if (!secretishKey) {
    return v.length >= 40 && entropy >= 4.35 && diversity >= 3;
  }

  if (v.length >= 16 && entropy >= 3.15 && diversity >= 2) return true;
  if (v.length >= 24 && entropy >= 3.0) return true;
  if (/^[a-f0-9]{32,}$/i.test(v) && entropy >= 3.0) return true;
  if (/^[A-Za-z0-9_\-+/=]{24,}$/.test(v) && entropy >= 3.3) return true;

  return false;
}

function isAutoFixable(filePath, line, secret) {
  const ext = path.extname(filePath).toLowerCase();
  if (['.json', '.yaml', '.yml', '.toml', '.ini', '.env'].includes(ext)) return false;
  const escaped = escapeRegExp(secret);
  const jsLike = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].includes(ext);
  const pyLike = ext === '.py';
  if (!jsLike && !pyLike) return false;
  const quoteClass = pyLike ? `(['"])` : `(['"\`])`;
  const literalRe = new RegExp(`${quoteClass}${escaped}\\1`);
  return literalRe.test(line);
}

function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function addFinding(findings, seen, finding) {
  const normalizedSecret = cleanSecretValue(finding.match);
  if (shouldIgnoreMatch(finding.file, finding.sourceLine || '', normalizedSecret)) return;
  const keyRulePart = finding.ruleId === 'provider-secret-assignment' ? ':provider' : '';
  const key = `${finding.file}:${finding.line}:${normalizedSecret}${keyRulePart}`;
  if (seen.has(key)) return;
  seen.add(key);
  findings.push({
    ...finding,
    match: normalizedSecret,
    redacted: redact(normalizedSecret),
    autoFixable: isAutoFixable(finding.file, finding.sourceLine || '', normalizedSecret)
  });
}

function scanEnvFile(filePath, lines, findings, seen) {
  const base = path.basename(filePath);
  if (!ENV_FILE_NAMES.has(base) || base.endsWith('.example')) return;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!/^\s*[A-Za-z_][A-Za-z0-9_]*\s*=/.test(line)) continue;
    if (PLACEHOLDER_RE.test(line) || ALLOW_RE.test(line)) continue;
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$/);
    if (!m) continue;
    const value = cleanSecretValue(m[2]);
    if (value.length < 8) continue;
    addFinding(findings, seen, {
      ruleId: 'env-file-committed',
      title: '.env file should not be committed',
      severity: 'critical',
      file: filePath,
      line: i + 1,
      match: value,
      envName: m[1],
      help: 'Do not push .env files. Add .env to .gitignore and commit .env.example instead.',
      sourceLine: line
    });
  }
}

function scanKnownRules(filePath, text, lines, findings, seen) {
  for (const rule of RULES) {
    rule.regex.lastIndex = 0;
    let m;
    while ((m = rule.regex.exec(text)) !== null) {
      const raw = m[0];
      const lineNo = lineNumberAt(text, m.index);
      const line = lines[lineNo - 1] || '';
      const normalized = normalizeFinding(rule, raw);
      if (rule.contextRegex && !rule.contextRegex.test(line)) continue;
      if (rule.validator && !rule.validator(normalized.secret, line, text, m.index)) continue;
      addFinding(findings, seen, {
        ruleId: rule.id,
        title: rule.title,
        severity: rule.severity,
        file: filePath,
        line: lineNo,
        match: normalized.secret,
        envName: normalized.envName,
        help: rule.help,
        sourceLine: line
      });
    }
  }
}

function assignmentCandidatesFromLine(line) {
  const out = [];
  if (!line || /^\s*(?:#|\/\/|\*)/.test(line)) return out;

  const patterns = [
    // KEY = "value", key: 'value', export KEY=value
    /(?:^|[\s,{(])(?:export\s+)?[`'"]?([A-Za-z_][A-Za-z0-9_.-]{1,80})[`'"]?\s*[:=]\s*([`'"])([^`'"]{8,4096})\2/g,
    // KEY = unquoted_token
    /(?:^|[\s,{(])(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]{1,80})\s*=\s*([^\s#;,]{12,4096})/g,
    // --token abc, token: abc in config-like text
    /(?:^|[\s,{(])(?:--)?([A-Za-z_][A-Za-z0-9_.-]*(?:key|token|secret|password|passwd|pwd|auth)[A-Za-z0-9_.-]*)\s+([^\s#;,]{12,4096})/gi
  ];

  for (const re of patterns) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(line)) !== null) {
      out.push({ key: m[1], value: m[3] || m[2] });
    }
  }

  return out;
}

function scanGenericAssignments(filePath, lines, findings, seen) {
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (ALLOW_RE.test(line)) continue;
    const candidates = assignmentCandidatesFromLine(line);
    for (const c of candidates) {
      if (!SECRET_KEYWORD_RE.test(c.key)) continue;
      const value = cleanSecretValue(c.value);
      if (!isLikelySecretValue(value, c.key)) continue;
      addFinding(findings, seen, {
        ruleId: 'generic-secret-assignment',
        title: 'Hardcoded secret-like assignment',
        severity: severityForGeneric(c.key, value),
        file: filePath,
        line: i + 1,
        match: value,
        envName: envNameFromKey(c.key),
        help: 'This looks like a hardcoded credential. Move it to .env/environment variables.',
        sourceLine: line
      });
    }
  }
}

function scanProviderAssignments(filePath, lines, findings, seen) {
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (ALLOW_RE.test(line)) continue;
    const candidates = assignmentCandidatesFromLine(line);
    for (const c of candidates) {
      const provider = findProvider(`${c.key} ${line}`);
      if (!provider) continue;
      const value = cleanSecretValue(c.value);
      if (!providerSecretScore(value, c.key)) continue;

      const secretContext = SECRET_KEYWORD_RE.test(c.key);
      addFinding(findings, seen, {
        ruleId: 'provider-secret-assignment',
        title: `${providerTitle(provider)} credential-like value`,
        severity: secretContext || looksLikeKnownSecretShape(value) || looksLikeCredentialUrl(value) ? 'high' : 'medium',
        file: filePath,
        line: i + 1,
        match: value,
        envName: envNameFromKey(c.key.includes('.') ? c.key.split('.').pop() : c.key),
        help: `This looks like a ${providerTitle(provider)} credential or provider token. Move it to .env/environment variables.`,
        sourceLine: line
      });
    }
  }
}

function scanHighEntropyLiterals(filePath, lines, findings, seen, options = {}) {
  if (!options.paranoid) return;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (ALLOW_RE.test(line)) continue;
    const re = /([`'"])([A-Za-z0-9_\-+.=/]{24,256})\1/g;
    let m;
    while ((m = re.exec(line)) !== null) {
      const value = cleanSecretValue(m[2]);
      if (!isLikelySecretValue(value, line)) continue;
      addFinding(findings, seen, {
        ruleId: 'high-entropy-string',
        title: 'High-entropy string that may be a token',
        severity: 'medium',
        file: filePath,
        line: i + 1,
        match: value,
        envName: 'SECRET_VALUE',
        help: 'This random-looking string may be a token. If real, move it to .env. If safe, add `pushguard: allow` on the line.',
        sourceLine: line
      });
    }
  }
}

function scanText(filePath, text, options = {}) {
  const findings = [];
  const seen = new Set();
  const lines = text.split(/\r?\n/);

  scanEnvFile(filePath, lines, findings, seen);
  scanKnownRules(filePath, text, lines, findings, seen);
  scanGenericAssignments(filePath, lines, findings, seen);
  scanProviderAssignments(filePath, lines, findings, seen);
  scanHighEntropyLiterals(filePath, lines, findings, seen, options);

  return findings.map(({ sourceLine, ...f }) => f);
}

function scanFiles(files, options = {}) {
  const allFindings = [];
  for (const file of files) {
    const text = safeRead(file, options);
    if (text === null) continue;
    allFindings.push(...scanText(file, text, options));
  }
  return allFindings;
}


function scanPushed(input = '', options = {}) {
  const allFindings = [];
  const specs = getPushedFileSpecs(input, process.cwd(), options);
  for (const spec of specs) {
    const text = readGitBlobText(spec, options);
    if (text === null) continue;
    // Display as the repo path, but scan the exact blob from each outgoing commit.
    const commitFindings = scanText(spec.filePath, text, options)
      .map(f => ({ ...f, commit: spec.ref.slice(0, 8) }));
    allFindings.push(...commitFindings);
  }
  return allFindings;
}

function pushedWorkingTreeFiles(input = '', options = {}) {
  return getPushedFileSpecs(input, process.cwd(), options)
    .map(spec => spec.filePath)
    .filter(file => fs.existsSync(file) && fs.statSync(file).isFile());
}

function resolveFiles(target = '.', options = {}) {
  const cwd = process.cwd();
  if (options.pushFiles) return pushedWorkingTreeFiles(options.prePushInput || '', options);
  if (options.staged) return getStagedFiles(cwd, options);
  if (options.tracked) return getTrackedFiles(cwd, options);
  const abs = path.resolve(cwd, target);
  if (!fs.existsSync(abs)) return [];
  const stat = fs.statSync(abs);
  if (stat.isFile()) return [abs];
  return walk(abs, [], options);
}

function scan(target = '.', options = {}) {
  if (options.prePush) return scanPushed(options.prePushInput || '', options);
  const files = resolveFiles(target, options);
  return scanFiles(files, options);
}

function relativeFindings(findings, cwd = gitRoot() || process.cwd()) {
  return findings.map(f => ({ ...f, file: path.relative(cwd, f.file) || f.file }));
}

module.exports = { scan, scanFiles, scanText, scanPushed, relativeFindings, shannonEntropy, isLikelySecretValue };
