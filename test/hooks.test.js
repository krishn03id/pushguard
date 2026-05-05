'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { hookBody, passThroughHookBody, installLocal, uninstallLocal, MARKER_START } = require('../src/hooks');

const packageName = require('../package.json').name;

const prePush = hookBody({ hookName: 'pre-push', paranoid: true });
assert(prePush.includes(`npx --yes ${packageName}`), 'pre-push hook should use the scoped npm package fallback');
assert(!prePush.includes('npx --yes pushguard'), 'pre-push hook should not fall back to the unscoped package name');
assert(prePush.includes(`npm i -g ${packageName}`), 'pre-push hook should show the scoped install command');

const preCommit = hookBody({ hookName: 'pre-commit', paranoid: true });
assert(preCommit.includes(`npx --yes ${packageName}`), 'pre-commit hook should use the scoped npm package fallback');
assert(!preCommit.includes('npx --yes pushguard'), 'pre-commit hook should not fall back to the unscoped package name');
assert(preCommit.includes(`npm i -g ${packageName}`), 'pre-commit hook should show the scoped install command');
assert(preCommit.includes('$repo_git_dir/hooks/pre-commit'), 'pre-commit hook should chain repo-local pre-commit hooks');

const commitMsg = passThroughHookBody('commit-msg');
assert(commitMsg.includes('$repo_git_dir/hooks/commit-msg'), 'pass-through hooks should chain matching repo-local hooks');
assert(commitMsg.includes('git_pushguard_hook_input=$(cat)'), 'pass-through hooks should preserve stdin for hooks that use it');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pushguard-hooks-'));
const oldCwd = process.cwd();
try {
  execFileSync('git', ['init'], { cwd: tmp, stdio: 'ignore' });
  process.chdir(tmp);

  const hookPath = path.join(tmp, '.git', 'hooks', 'pre-push');
  fs.writeFileSync(hookPath, '#!/usr/bin/env sh\n\necho local-pre-push\n', { mode: 0o755 });

  installLocal({ paranoid: true });
  const installed = fs.readFileSync(hookPath, 'utf8');
  assert(installed.includes(MARKER_START), 'local install should append a managed hook block');
  assert(installed.includes('echo local-pre-push'), 'local install should preserve existing hook content');

  uninstallLocal();
  const uninstalled = fs.readFileSync(hookPath, 'utf8');
  assert(!uninstalled.includes(MARKER_START), 'local uninstall should remove the managed hook block');
  assert(uninstalled.includes('echo local-pre-push'), 'local uninstall should preserve existing hook content');

  console.log('✅ hooks tests passed');
} finally {
  process.chdir(oldCwd);
  fs.rmSync(tmp, { recursive: true, force: true });
}
