'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { fix } = require('../src/fixer');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pushguard-fixer-'));
const oldCwd = process.cwd();
try {
  process.chdir(tmp);
  fs.writeFileSync('app.js', 'const OPENAI_API_KEY = `sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEF`;\n');
  const result = fix('.', { apply: true });
  assert(result.fileActions.some(a => a.status === 'replaced'), 'should replace backtick template literal secret');
  const app = fs.readFileSync('app.js', 'utf8');
  assert(app.includes('process.env.OPENAI_API_KEY'), 'should replace with process.env');
  assert(!app.includes('sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEF'), 'should remove raw secret from code');
  assert(fs.readFileSync('.env', 'utf8').includes('OPENAI_API_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEF'), 'should write .env');
  assert(fs.readFileSync('.env.example', 'utf8').includes('OPENAI_API_KEY=your_openai_api_key_here'), 'should write .env.example placeholder');
  console.log('✅ fixer tests passed');
} finally {
  process.chdir(oldCwd);
  fs.rmSync(tmp, { recursive: true, force: true });
}
