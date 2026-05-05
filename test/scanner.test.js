'use strict';

const assert = require('assert');
const { scanText, isLikelySecretValue } = require('../src/scanner');
const { providerStats, findProvider } = require('../src/providers');

const py = 'BOT_TOKEN = "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ_1234567890"\n'; // pushguard: allow test fixture
const findings = scanText('/tmp/bot.py', py);
assert(findings.length >= 1, 'should detect Telegram token');
assert(findings.some(f => f.ruleId === 'telegram-bot-token'), 'should include telegram rule');
assert(findings.some(f => f.autoFixable), 'should be auto-fixable');

const placeholder = 'BOT_TOKEN = "your_telegram_bot_token_here"\n';
const noFindings = scanText('/tmp/bot.py', placeholder);
assert.strictEqual(noFindings.length, 0, 'should ignore placeholders');

const allowed = 'BOT_TOKEN = "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ_1234567890" # pushguard: allow\n';
assert.strictEqual(scanText('/tmp/bot.py', allowed).length, 0, 'should honor allow comment');

const unknown = 'MY_SUPER_API_KEY = "abcDEF1234567890abcDEF1234567890"\n'; // pushguard: allow test fixture
const unknownFindings = scanText('/tmp/app.py', unknown);
assert(unknownFindings.some(f => f.ruleId === 'generic-secret-assignment'), 'should detect unknown secret-looking assignment');
assert(unknownFindings.some(f => f.envName === 'MY_SUPER_API_KEY'), 'should preserve useful env name');

const db = 'DATABASE_URL="postgres://user:supersecretpass@example.com/db"\n'; // pushguard: allow test fixture
assert(scanText('/tmp/.env', db).some(f => f.ruleId === 'database-url-with-password'), 'should detect database URL with password');

const nvidia = 'NVIDIA_API_KEY="nvapi-abcdefghijklmnopqrstuvwxyz1234567890"\n'; // pushguard: allow test fixture
assert(scanText('/tmp/app.js', nvidia).some(f => f.ruleId === 'nvidia-api-key'), 'should detect NVIDIA API key-like values');

const provider = 'CLOUDFLARE_ZONE="a9b8c7d6e5f4A3B2C1D0x9y8z7w6v5u4"\n'; // pushguard: allow test fixture
assert(scanText('/tmp/app.env', provider, { paranoid: true }).some(f => f.ruleId === 'provider-secret-assignment'), 'should detect provider-contexted secret even without key/token word');

const supabase = 'SUPABASE_SERVICE_ROLE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcDEF1234567890.abcDEF1234567890"\n'; // pushguard: allow test fixture
assert(scanText('/tmp/app.py', supabase).some(f => /Supabase/.test(f.title)), 'should detect Supabase provider credential');


// Regression: JS template literals that contain standalone secrets should be auto-fixable.
const templateLiteral = 'const OPENAI_API_KEY = `sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEF`;\n'; // pushguard: allow test fixture
assert(scanText('/tmp/app.js', templateLiteral).some(f => f.autoFixable), 'JS backtick template literal should be auto-fixable');

// Regression: 40-char SHA1-like strings should not trigger AWS secret rule without AWS context.
const shaLike = 'const COMMIT_HASH = "0123456789abcdef0123456789abcdef01234567";\n';
assert(!scanText('/tmp/app.js', shaLike).some(f => f.ruleId === 'aws-secret-access-key'), 'AWS secret rule should not flag generic 40-char hex hash');

// AWS secret-like value should still be detected in AWS context.
const awsSecret = 'AWS_SECRET_ACCESS_KEY="AbCdEfGhIjKlMnOpQrStUvWxYz1234567890ABCD"\n'; // pushguard: allow test fixture
assert(scanText('/tmp/aws-config.js', awsSecret).some(f => f.ruleId === 'aws-secret-access-key'), 'AWS secret should be detected when AWS context is present');

const stats = providerStats();
assert(stats.providers >= 300, 'should include hundreds of providers');
assert(stats.fingerprints >= 1000, 'should include 1000+ expanded provider fingerprints');
assert(findProvider('CLOUDFLARE_API_TOKEN'), 'should find Cloudflare provider');
assert(findProvider('SUPABASE_SERVICE_ROLE'), 'should find Supabase provider');
assert(findProvider('OPENROUTER_API_KEY'), 'should find OpenRouter provider');
assert(!findProvider("const paranoid = flags.has('paranoid') || !local;"), 'provider matching should not join unrelated words into provider aliases');

assert(isLikelySecretValue('abcDEF1234567890abcDEF1234567890', 'api_key'), 'entropy detector should catch unknown API key'); // pushguard: allow test fixture

const hookPathCode = [
  "const hooksPath = path.join(os.homedir(), '.pushguard', 'hooks');",
  "const hookPath = path.join(hooksPath, hookName);",
  "const configuredHooksPath = currentGlobalHooksPath();",
  "const paranoid = flags.has('paranoid') || !local;"
].join('\n');
assert.strictEqual(scanText('/tmp/hooks.js', hookPathCode, { paranoid: true }).length, 0, 'hook path plumbing should not be flagged as secrets');

console.log('✅ scanner tests passed');
