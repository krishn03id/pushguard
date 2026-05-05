#!/usr/bin/env node
'use strict';

// One-time auto setup after: npm install -g @namaa03/pushguard
// Creates ~/.pushguard/hooks/pre-push and sets Git global core.hooksPath.
// To skip: PUSHGUARD_SKIP_POSTINSTALL=1 npm install -g @namaa03/pushguard

const { installGlobal } = require('../src/hooks');

function main() {
  if (process.env.PUSHGUARD_SKIP_POSTINSTALL === '1' || process.env.PUSHGUARD_SKIP_POSTINSTALL === 'true') {
    console.log('PushGuard: skipped auto hook install because PUSHGUARD_SKIP_POSTINSTALL is set.');
    return;
  }

  try {
    const res = installGlobal({ paranoid: true, autoFix: false });
    console.log('');
    console.log('✅ PushGuard global pre-push protection installed.');
    console.log(`   Hooks path: ${res.hooksPath}`);
    console.log('   Now every normal `git push` scans only outgoing commit files before pushing.');
    console.log('   Check status: pushguard status');
    console.log('');
  } catch (err) {
    console.log('');
    console.log('⚠️ PushGuard installed, but automatic Git hook setup failed:');
    console.log(`   ${err.message}`);
    console.log('   Run this manually later: pushguard install --paranoid');
    console.log('');
    // Do not fail npm install. Some systems install packages before git is available.
  }
}

main();
