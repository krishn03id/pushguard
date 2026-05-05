#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs');
const { scan, relativeFindings } = require('../src/scanner');
const { fix } = require('../src/fixer');
const { installLocal, installGlobal, uninstallLocal, uninstallGlobal, statusGlobal } = require('../src/hooks');
const { RULES } = require('../src/rules');
const { providerStats } = require('../src/providers');
const { parseSize } = require('../src/utils');

const pkg = require('../package.json');
const VERSION = pkg.version;
const PACKAGE_NAME = pkg.name;

function parseArgs(argv) {
  const args = [];
  const flags = new Set();
  const values = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const [k, inlineValue] = a.slice(2).split('=');
      if (inlineValue !== undefined) values[k] = inlineValue;
      else if (i + 1 < argv.length && !argv[i + 1].startsWith('-') && ['max-size'].includes(k)) values[k] = argv[++i];
      else flags.add(k);
    } else if (a.startsWith('-') && a.length > 1) {
      for (const ch of a.slice(1)) flags.add(ch);
    } else {
      args.push(a);
    }
  }
  return { args, flags, values };
}

function printHelp() {
  console.log(`PushGuard v${VERSION}

One-time install protection for git push: after npm install -g ${PACKAGE_NAME}, every normal git push scans outgoing commits for leaked tokens before they reach GitHub.

Usage:
  pushguard scan [path] [--staged|--tracked|--pre-push] [--json] [--paranoid] [--max-size 5mb]
  pushguard fix [path] [--yes] [--staged|--tracked|--push-files] [--paranoid] [--max-size 5mb]
  pushguard install [--local] [--pre-commit|--both] [--auto-fix] [--paranoid]
  pushguard status
  pushguard uninstall [--local]
  pushguard rules
  pushguard providers

Examples:
  pushguard scan .
  npm install -g ${PACKAGE_NAME}       # installs global pre-push protection automatically
  pushguard install              # re-install/repair global protection
  pushguard status
  pushguard install --local      # current repo only
  pushguard install --both --auto-fix
  pushguard fix --yes

Notes:
  - Scans all readable text files, not just known code extensions.
  - Known providers are detected with regex rules plus a 1000+ provider fingerprint layer.
  - Unknown tokens are detected with secret-looking variable names + entropy.
  - --paranoid also flags random-looking strings even with weak context.
  - pre-push hook scans only files changed in outgoing commits being pushed.
  - pre-commit hook scans staged files before commit.
  - Auto-fix only edits simple standalone quoted string tokens in Python/JS/TS files.
`);
}

function severityIcon(sev) {
  if (sev === 'critical') return '🚨';
  if (sev === 'high') return '⚠️';
  if (sev === 'medium') return '⚠';
  return '•';
}



function readStdinIfAvailable() {
  try {
    if (process.stdin.isTTY) return '';
    return fs.readFileSync(0, 'utf8');
  } catch (_) {
    return '';
  }
}

function buildScanOptions(flags, values) {
  return {
    staged: flags.has('staged'),
    tracked: flags.has('tracked'),
    prePush: flags.has('pre-push'),
    pushFiles: flags.has('push-files'),
    paranoid: flags.has('paranoid'),
    includeLocks: flags.has('include-locks'),
    maxSizeBytes: parseSize(values['max-size'], 5 * 1024 * 1024)
  };
}

function printScan(findings) {
  if (findings.length === 0) {
    console.log('✅ PushGuard: no obvious secrets found.');
    return;
  }

  console.log(`🚨 PushGuard found ${findings.length} possible secret${findings.length === 1 ? '' : 's'}:\n`);
  for (const f of findings) {
    console.log(`${severityIcon(f.severity)} ${f.title}`);
    console.log(`   File: ${f.file}:${f.line}${f.commit ? ` (commit ${f.commit})` : ''}`);
    console.log(`   Match: ${f.redacted}`);
    console.log(`   Fix: ${f.help}`);
    if (f.autoFixable) console.log('   Auto-fix: pushguard fix --yes');
    console.log('');
  }
  console.log('🛑 Push/commit blocked. Fix secrets, git add changes, then retry.');
}

function printFix(result, apply) {
  if (result.fixableCount === 0) {
    if (result.totalFindings === 0) {
      console.log('✅ No secrets found. Nothing to fix.');
    } else {
      console.log('⚠️ Secrets found, but none are safe for auto-fix. Manual fix needed.');
    }
  }

  if (!apply) {
    console.log('Preview only. Use `pushguard fix --yes` to apply safe fixes.\n');
  }

  if (result.fileActions.length) {
    console.log(apply ? 'Changed files:' : 'Would change files:');
    for (const a of result.fileActions) {
      const extra = a.imported ? ' + added import os' : '';
      const reason = a.reason ? ` (${a.reason})` : '';
      console.log(`  ${a.status} ${a.file}:${a.line} -> ${a.envName}${extra}${reason}`);
    }
    console.log('');
  }

  if (result.envActions.length && result.fixableCount > 0) {
    console.log(apply ? 'Updated helper files:' : 'Would update helper files:');
    for (const a of result.envActions) console.log(`  ${a.file}: ${a.line}`);
    console.log('');
  }

  if (result.remainingUnfixable.length) {
    console.log('Manual fixes still needed:');
    for (const f of result.remainingUnfixable) {
      console.log(`  ${f.file}:${f.line} ${f.title} (${f.redacted})`);
    }
    console.log('');
  }

  if (apply && result.fixableCount > 0) {
    console.log('✅ Safe fixes applied. Review changes, run tests, then:');
    console.log('   git add .env.example .gitignore <changed-files>');
    console.log('   git commit -m "Move secrets to environment variables"');
    console.log('');
    console.log('Important: if a real secret was already pushed before, rotate/revoke it.');
  }
}

function main() {
  const { args, flags, values } = parseArgs(process.argv.slice(2));
  const cmd = args.shift() || 'help';

  try {
    if (flags.has('version') || flags.has('v') || cmd === 'version') {
      console.log(VERSION);
      return;
    }

    if (cmd === 'help' || flags.has('help') || flags.has('h')) {
      printHelp();
      return;
    }

    if (cmd === 'scan') {
      const target = args[0] || '.';
      const options = buildScanOptions(flags, values);
      if (options.prePush) options.prePushInput = readStdinIfAvailable();
      const findings = relativeFindings(scan(target, options));
      if (flags.has('json')) console.log(JSON.stringify(findings, null, 2));
      else printScan(findings);
      process.exitCode = findings.length ? 1 : 0;
      return;
    }

    if (cmd === 'fix') {
      const target = args[0] || '.';
      const apply = flags.has('yes') || flags.has('y');
      const options = buildScanOptions(flags, values);
      if (options.pushFiles) options.prePushInput = readStdinIfAvailable();
      const result = fix(target, { apply, ...options });
      printFix(result, apply);
      process.exitCode = result.remainingUnfixable.length ? 1 : 0;
      return;
    }

    if (cmd === 'install') {
      const local = flags.has('local');
      const preCommit = flags.has('pre-commit');
      const autoFix = flags.has('auto-fix');
      const both = flags.has('both');
      const paranoid = flags.has('paranoid') || !local;
      const res = local ? installLocal({ preCommit, both, autoFix, paranoid }) : installGlobal({ preCommit, both, autoFix, paranoid });
      console.log(`✅ PushGuard installed (${res.scope})`);
      console.log(`Hook: ${res.hookName}`);
      console.log(local ? `Repo: ${res.root}` : `Hooks path: ${res.hooksPath}`);
      if (!local) console.log('Now every normal `git push` is protected globally.');
      if (autoFix) console.log('Mode: auto-fix safe standalone literals, then block so you can review.');
      else console.log('Mode: block push/commit when secrets are detected.');
      if (paranoid) console.log('Paranoid: enabled high-entropy string checks.');
      return;
    }

    if (cmd === 'status') {
      const s = statusGlobal();
      console.log(`PushGuard global status: ${s.active ? 'ACTIVE ✅' : 'NOT ACTIVE ❌'}`);
      console.log(`Configured hooksPath: ${s.configuredHooksPath || '(none)'}`);
      console.log(`Expected hooksPath:   ${s.hooksPath}`);
      console.log(`pre-push hook:        ${s.prePushExists ? 'installed' : 'missing'}`);
      if (!s.active) console.log('Fix: pushguard install');
      return;
    }

    if (cmd === 'uninstall') {
      if (flags.has('local')) {
        const res = uninstallLocal();
        console.log(`✅ Removed PushGuard from local hooks: ${res.removed.join(', ') || 'nothing to remove'}`);
      } else {
        const res = uninstallGlobal();
        console.log(`✅ Removed PushGuard global hooks: ${res.removed.join(', ') || 'nothing to remove'}`);
        if (res.configUnset) console.log('Unset global core.hooksPath.');
      }
      return;
    }

    if (cmd === 'rules') {
      const stats = providerStats();
      console.log('PushGuard fixed regex rules:\n');
      for (const r of RULES) console.log(`- ${r.id} [${r.severity}] ${r.title}`);
      console.log(`\nProvider intelligence: ${stats.providers} providers, ${stats.fingerprints} expanded provider/token fingerprints.`);
      console.log('Plus generic detection: secret-looking variable names, credential URLs, bearer tokens, .env leaks, and entropy-based unknown token detection with --paranoid.');
      return;
    }

    if (cmd === 'providers') {
      const stats = providerStats();
      console.log(`PushGuard provider intelligence: ${stats.providers} providers`);
      console.log(`Expanded fingerprints: ${stats.fingerprints}`);
      console.log(`Secret suffixes per provider: ${stats.secretSuffixes}`);
      console.log('Examples: AWS, Azure, GCP, Cloudflare, Supabase, Vercel, GitHub, OpenAI, Anthropic, Stripe, Slack, Discord, Twilio, Shopify, Linear, Notion, and hundreds more.');
      return;
    }

    console.error(`Unknown command: ${cmd}\n`);
    printHelp();
    process.exitCode = 2;
  } catch (err) {
    console.error(`pushguard: ${err.message}`);
    process.exitCode = 1;
  }
}

main();
