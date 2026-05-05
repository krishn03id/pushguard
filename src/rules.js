'use strict';

// High-signal provider rules. Unknown/new formats are caught in scanner.js by
// generic secret-keyword + entropy detection.
const RULES = [
  {
    id: 'telegram-bot-token',
    title: 'Telegram bot token',
    severity: 'critical',
    envName: 'TELEGRAM_BOT_TOKEN',
    regex: /\b\d{6,12}:[A-Za-z0-9_-]{30,}\b/g,
    help: 'Move Telegram bot tokens to .env and read them with environment variables.'
  },
  {
    id: 'aws-access-key-id',
    title: 'AWS access key id',
    severity: 'critical',
    envName: 'AWS_ACCESS_KEY_ID',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    help: 'AWS access keys should never be committed. Rotate leaked keys immediately.'
  },
  {
    id: 'aws-secret-access-key',
    title: 'AWS secret access key-like value',
    severity: 'critical',
    envName: 'AWS_SECRET_ACCESS_KEY',
    // AWS secret keys do not have a stable prefix. Keep this rule context-gated
    // so random 40-char hashes/base64 blobs do not become noisy false positives.
    regex: /\b[A-Za-z0-9/+]{40}\b/g,
    contextRegex: /(?:aws|aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret|secret[_-]?access[_-]?key|amazonaws)/i,
    validator: (secret) => !/^[a-f0-9]{40}$/i.test(String(secret || '')),
    help: 'Looks like a 40-character AWS secret key in AWS-related context. Verify, rotate if real, and move it to .env.'
  },
  {
    id: 'github-token',
    title: 'GitHub token',
    severity: 'critical',
    envName: 'GITHUB_TOKEN',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b/g,
    help: 'Revoke leaked GitHub tokens and use environment variables or GitHub secrets.'
  },
  {
    id: 'gitlab-token',
    title: 'GitLab token',
    severity: 'critical',
    envName: 'GITLAB_TOKEN',
    regex: /\b(?:glpat|glrt|gloas)-[A-Za-z0-9_-]{20,}\b/g,
    help: 'Move GitLab tokens to .env/GitLab CI variables and rotate if exposed.'
  },
  {
    id: 'npm-token',
    title: 'npm token',
    severity: 'critical',
    envName: 'NPM_TOKEN',
    regex: /\bnpm_[A-Za-z0-9]{30,}\b/g,
    help: 'Move npm tokens to environment variables and revoke if exposed.'
  },
  {
    id: 'pypi-token',
    title: 'PyPI token',
    severity: 'critical',
    envName: 'PYPI_TOKEN',
    regex: /\bpypi-[A-Za-z0-9_-]{30,}\b/g,
    help: 'Move PyPI tokens to environment variables and revoke if exposed.'
  },
  {
    id: 'openai-key',
    title: 'OpenAI API key',
    severity: 'critical',
    envName: 'OPENAI_API_KEY',
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g,
    help: 'Move API keys to .env and rotate if the key was committed.'
  },
  {
    id: 'anthropic-key',
    title: 'Anthropic API key',
    severity: 'critical',
    envName: 'ANTHROPIC_API_KEY',
    regex: /\bsk-ant-[A-Za-z0-9_-]{30,}\b/g,
    help: 'Move Anthropic keys to .env and rotate if exposed.'
  },
  {
    id: 'google-api-key',
    title: 'Google/Gemini API key-like value',
    severity: 'high',
    envName: 'GOOGLE_API_KEY',
    regex: /\bAIza[0-9A-Za-z_-]{30,}\b/g,
    help: 'Move Google/Gemini keys to .env and restrict the key in Google Cloud.'
  },
  {
    id: 'google-oauth-access-token',
    title: 'Google OAuth access token',
    severity: 'critical',
    envName: 'GOOGLE_OAUTH_TOKEN',
    regex: /\bya29\.[0-9A-Za-z_-]{20,}\b/g,
    help: 'OAuth access tokens should never be committed. Revoke/expire exposed tokens.'
  },
  {
    id: 'huggingface-token',
    title: 'Hugging Face token',
    severity: 'critical',
    envName: 'HF_TOKEN',
    regex: /\bhf_[A-Za-z0-9]{30,}\b/g,
    help: 'Move Hugging Face tokens to .env and revoke if exposed.'
  },
  {
    id: 'nvidia-api-key',
    title: 'NVIDIA API key-like value',
    severity: 'critical',
    envName: 'NVIDIA_API_KEY',
    regex: /\bnvapi-[A-Za-z0-9_-]{20,}\b/g,
    help: 'Move NVIDIA API keys to .env and revoke if exposed.'
  },
  {
    id: 'replicate-token',
    title: 'Replicate API token',
    severity: 'critical',
    envName: 'REPLICATE_API_TOKEN',
    regex: /\br8_[A-Za-z0-9]{30,}\b/g,
    help: 'Move Replicate tokens to .env and revoke if exposed.'
  },
  {
    id: 'stripe-secret-key',
    title: 'Stripe secret/restricted key',
    severity: 'critical',
    envName: 'STRIPE_SECRET_KEY',
    regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
    help: 'Never commit Stripe secret keys. Move to env vars and rotate if exposed.'
  },
  {
    id: 'sendgrid-api-key',
    title: 'SendGrid API key',
    severity: 'critical',
    envName: 'SENDGRID_API_KEY',
    regex: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
    help: 'Move SendGrid keys to .env and rotate if exposed.'
  },
  {
    id: 'mailgun-api-key',
    title: 'Mailgun API key',
    severity: 'critical',
    envName: 'MAILGUN_API_KEY',
    regex: /\bkey-[0-9a-f]{32}\b/gi,
    help: 'Move Mailgun keys to .env and rotate if exposed.'
  },
  {
    id: 'slack-token',
    title: 'Slack token',
    severity: 'critical',
    envName: 'SLACK_TOKEN',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    help: 'Move Slack tokens to .env and rotate leaked tokens.'
  },
  {
    id: 'slack-webhook-url',
    title: 'Slack webhook URL',
    severity: 'critical',
    envName: 'SLACK_WEBHOOK_URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/-]{20,}/g,
    help: 'Slack webhook URLs are secrets. Move to env vars and rotate if exposed.'
  },
  {
    id: 'discord-token',
    title: 'Discord bot token-like value',
    severity: 'high',
    envName: 'DISCORD_BOT_TOKEN',
    regex: /\b[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,}\b/g,
    help: 'Move Discord bot tokens to .env and rotate if exposed.'
  },
  {
    id: 'discord-webhook-url',
    title: 'Discord webhook URL',
    severity: 'critical',
    envName: 'DISCORD_WEBHOOK_URL',
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{20,}/g,
    help: 'Discord webhook URLs are secrets. Move to env vars and rotate if exposed.'
  },
  {
    id: 'twilio-api-key',
    title: 'Twilio API key-like value',
    severity: 'high',
    envName: 'TWILIO_API_KEY',
    regex: /\bSK[0-9a-fA-F]{32}\b/g,
    help: 'Move Twilio API keys to .env and rotate if exposed.'
  },
  {
    id: 'jwt-token',
    title: 'JWT token',
    severity: 'high',
    envName: 'JWT_TOKEN',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    help: 'JWTs often grant access. Do not commit real tokens.'
  },
  {
    id: 'database-url-with-password',
    title: 'Database URL with password',
    severity: 'critical',
    envName: 'DATABASE_URL',
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s:@/]+:[^\s:@/]{6,}@[^\s'"`]+/gi,
    help: 'Database URLs with passwords must be moved to environment variables.'
  },
  {
    id: 'basic-auth-url',
    title: 'URL with embedded credentials',
    severity: 'high',
    envName: 'AUTH_URL',
    regex: /\bhttps?:\/\/[^\s:@/]+:[^\s:@/]{6,}@[^\s'"`]+/gi,
    help: 'URLs with username:password should not be committed.'
  },
  {
    id: 'private-key',
    title: 'Private key block',
    severity: 'critical',
    envName: 'PRIVATE_KEY',
    regex: /-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
    help: 'Private keys must not be committed. Remove and rotate the key.'
  },

  {
    id: 'cloudflare-api-token-context',
    title: 'Cloudflare API token-like value',
    severity: 'high',
    envName: 'CLOUDFLARE_API_TOKEN',
    regex: /\b(?:CLOUDFLARE|CF)_[A-Z0-9_]*(?:TOKEN|KEY|SECRET)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?/gi,
    extract: raw => (raw.match(/['\"]?([A-Za-z0-9_-]{20,})['\"]?\s*$/) || [])[1] || raw,
    help: 'Move Cloudflare API tokens/keys to environment variables and rotate if exposed.'
  },
  {
    id: 'digitalocean-token',
    title: 'DigitalOcean token',
    severity: 'critical',
    envName: 'DIGITALOCEAN_TOKEN',
    regex: /\bdop_v1_[A-Za-z0-9]{48,}\b/g,
    help: 'Move DigitalOcean tokens to environment variables and revoke if exposed.'
  },
  {
    id: 'linear-api-key',
    title: 'Linear API key',
    severity: 'critical',
    envName: 'LINEAR_API_KEY',
    regex: /\blin_api_[A-Za-z0-9]{20,}\b/g,
    help: 'Move Linear API keys to environment variables and revoke if exposed.'
  },
  {
    id: 'openrouter-api-key',
    title: 'OpenRouter API key',
    severity: 'critical',
    envName: 'OPENROUTER_API_KEY',
    regex: /\bsk-or-v1-[A-Za-z0-9_-]{20,}\b/g,
    help: 'Move OpenRouter keys to .env and rotate if exposed.'
  },
  {
    id: 'groq-api-key',
    title: 'Groq API key',
    severity: 'critical',
    envName: 'GROQ_API_KEY',
    regex: /\bgsk_[A-Za-z0-9_-]{20,}\b/g,
    help: 'Move Groq keys to .env and rotate if exposed.'
  },
  {
    id: 'shopify-access-token',
    title: 'Shopify access token',
    severity: 'critical',
    envName: 'SHOPIFY_ACCESS_TOKEN',
    regex: /\bshp(?:at|ss|pa|ca)_[A-Za-z0-9]{20,}\b/g,
    help: 'Move Shopify access tokens to environment variables and rotate if exposed.'
  },
  {
    id: 'stripe-publishable-key',
    title: 'Stripe publishable key',
    severity: 'medium',
    envName: 'STRIPE_PUBLISHABLE_KEY',
    regex: /\bpk_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
    help: 'Stripe publishable keys are less sensitive than secret keys, but avoid hardcoding production keys when possible.'
  },
  {
    id: 'azure-storage-connection-string',
    title: 'Azure Storage connection string with account key',
    severity: 'critical',
    envName: 'AZURE_STORAGE_CONNECTION_STRING',
    regex: /\bDefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=[A-Za-z0-9+/=]{20,};EndpointSuffix=[^\s'\"]+/gi,
    help: 'Azure Storage connection strings with AccountKey must not be committed.'
  },
  {
    id: 'cloudinary-url-with-secret',
    title: 'Cloudinary URL with API secret',
    severity: 'critical',
    envName: 'CLOUDINARY_URL',
    regex: /\bcloudinary:\/\/[0-9]+:[A-Za-z0-9_-]{12,}@[A-Za-z0-9_-]+\b/g,
    help: 'Cloudinary URLs with API secrets must be moved to environment variables.'
  },
  {
    id: 'private-key-inline-escaped',
    title: 'Escaped private key value',
    severity: 'critical',
    envName: 'PRIVATE_KEY',
    regex: /-----BEGIN\\n(?:RSA |OPENSSH |EC |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
    help: 'Escaped private keys must not be committed. Move them to secrets storage.'
  },
  {
    id: 'authorization-bearer-token',
    title: 'Authorization bearer token',
    severity: 'high',
    envName: 'BEARER_TOKEN',
    regex: /\bBearer\s+([A-Za-z0-9._~+/=-]{20,})\b/gi,
    extract: raw => raw.replace(/^Bearer\s+/i, ''),
    help: 'Bearer tokens should not be committed. Move to env vars and rotate if exposed.'
  }
];

const SECRET_KEYWORD_RE = /(?:api[_-]?key|apikey|access[_-]?key|secret|token|auth|authorization|bearer|credential|password|passwd|pwd|private[_-]?key|client[_-]?secret|signing[_-]?secret|webhook|session[_-]?secret|jwt|refresh[_-]?token|database[_-]?url|db[_-]?url|connection[_-]?string|dsn|service[_-]?role|service[_-]?key|app[_-]?secret|publishable[_-]?key|anon[_-]?key|pat|personal[_-]?access[_-]?token|oauth|consumer[_-]?secret|signing[_-]?key)/i;
const ENV_FILE_NAMES = new Set(['.env', '.env.local', '.env.production', '.env.development', '.env.test', '.env.staging']);

module.exports = { RULES, ENV_FILE_NAMES, SECRET_KEYWORD_RE };
