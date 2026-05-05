<!-- mcp-name: io.github.krishn03id/pushguard -->

<h1 align="center">
  <br>
  <strong>PushGuard 🛡️</strong>
  <br>
  <small>An airbag for <code>git push</code></small>
</h1>

<p align="center">
  <strong>One-time install protection that scans outgoing Git commits for leaked API keys, tokens, and secrets before they reach GitHub.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@namaa03/pushguard">
    <img alt="npm version" src="https://img.shields.io/npm/v/@namaa03/pushguard?style=flat&logo=npm&label=npm">
  </a>
  <a href="https://www.npmjs.com/package/@namaa03/pushguard">
    <img alt="npm downloads" src="https://img.shields.io/npm/dm/@namaa03/pushguard?style=flat&logo=npm">
  </a>
  <a href="https://github.com/krishn03id/pushguard/blob/main/LICENSE">
    <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  </a>
  <a href="https://nodejs.org">
    <img alt="Node.js" src="https://img.shields.io/badge/node-%3E%3D16-339933?logo=node.js&logoColor=white">
  </a>
  <a href="https://github.com/krishn03id/pushguard">
    <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/krishn03id/pushguard?style=social">
  </a>
</p>

<p align="center">
  <a href="#why-pushguard"><strong>Why</strong></a>
  &middot;
  <a href="#installation"><strong>Installation</strong></a>
  &middot;
  <a href="#quick-demo"><strong>Demo</strong></a>
  &middot;
  <a href="#features"><strong>Features</strong></a>
  &middot;
  <a href="#commands"><strong>CLI</strong></a>
  &middot;
  <a href="#security-model"><strong>Security Model</strong></a>
</p>

---

## Why PushGuard?

AI coding is fast. Leaking secrets is faster.

When beginners and vibe coders build with ChatGPT, Cursor, Claude, Codex, Gemini CLI, or copied snippets from the internet, it is very easy to accidentally commit something like:

```js
const token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
```

Then one normal command sends it public:

```bash
git push
```

**PushGuard protects that exact moment.**

It installs Git push protection once, then every normal `git push` automatically scans the outgoing commits and blocks the push if a leaked token is detected.

---

## Quick Demo

```bash
npm install -g @namaa03/pushguard
```

Check protection:

```bash
pushguard status
```

Expected output:

```txt
PushGuard global status: ACTIVE ✅
pre-push hook:        installed
```

Now use Git normally:

```bash
git add .
git commit -m "update"
git push
```

If a secret is found:

```txt
🚨 PushGuard blocked this push.

Possible Telegram bot token found in bot.js

Move it to .env before pushing.
```

---

## Installation

Install globally with npm:

```bash
npm install -g @namaa03/pushguard
```

PushGuard sets up global Git push protection automatically.

Verify:

```bash
pushguard status
```

Repair/reinstall protection anytime:

```bash
pushguard install
```

---

## What Makes PushGuard Different?

Most scanners scan your whole folder.

PushGuard is designed for the real Git workflow:

```txt
git push
   ↓
PushGuard reads outgoing commits
   ↓
Only files being pushed are scanned
   ↓
Push is blocked if secrets are detected
```

This means PushGuard does **not** waste time scanning your entire home directory, downloads folder, `node_modules`, `.venv`, or unrelated files.

It checks the code that is actually about to leave your machine.

---

## Features

### Git Push Protection

- 🛡️ **One-time global install**
- 🚦 **Automatically checks every normal `git push`**
- 🎯 **Scans only outgoing pushed files**
- 🧠 **Designed for AI-coding and vibe-coding workflows**
- ⚡ **Fast enough for daily Git usage**
- 🧩 **Works with normal Git commands**

### Secret Detection

PushGuard detects known and unknown secret patterns:

- Telegram bot tokens
- GitHub tokens
- GitLab tokens
- AWS access keys
- AWS secret keys
- OpenAI API keys
- Gemini / Google AI keys
- Anthropic API keys
- NVIDIA API keys
- Hugging Face tokens
- Stripe keys
- Discord tokens
- Slack tokens
- SendGrid keys
- Mailgun keys
- Twilio keys
- JWTs
- Database URLs
- Private keys
- Bearer tokens
- Secret-looking variables
- High-entropy unknown tokens
- 1000+ provider/token fingerprints

### AI-World Safety

PushGuard is useful when working with:

- ChatGPT
- Codex
- Cursor
- Claude Code
- Gemini CLI
- Windsurf
- Copilot
- OpenRouter
- NVIDIA NIM
- Telegram bots
- AWS projects
- `.env` based apps

---

## Getting Started

### 1. Install

```bash
npm install -g @namaa03/pushguard
```

### 2. Confirm status

```bash
pushguard status
```

### 3. Use Git normally

```bash
git add .
git commit -m "my update"
git push
```

That is it.

PushGuard runs automatically before the push.

---

## Manual Scanning

Scan current folder:

```bash
pushguard scan .
```

Run stronger paranoid scan:

```bash
pushguard scan . --paranoid
```

Scan staged files before commit:

```bash
pushguard scan . --staged --paranoid
```

Show provider detection stats:

```bash
pushguard providers
```

Show detection rules:

```bash
pushguard rules
```

---

## Auto Fix

PushGuard can auto-fix simple hardcoded tokens in Python, JavaScript, and TypeScript files.

Example unsafe code:

```js
const token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
```

Safer code:

```js
const token = process.env.TELEGRAM_BOT_TOKEN;
```

Run:

```bash
pushguard fix --yes
```

Or install with auto-fix enabled:

```bash
pushguard install --both --auto-fix --paranoid
```

> Auto-fix is intentionally conservative. It only edits simple standalone quoted string tokens.

---

## Commands

```txt
pushguard scan [path] [--staged|--tracked|--pre-push] [--json] [--paranoid] [--max-size 5mb]

pushguard fix [path] [--yes] [--staged|--tracked|--push-files] [--paranoid] [--max-size 5mb]

pushguard install [--local] [--pre-commit|--both] [--auto-fix] [--paranoid]

pushguard status

pushguard uninstall [--local]

pushguard rules

pushguard providers
```

Aliases:

```bash
pushgaurd
git-airbag
```

Yes, the typo alias `pushgaurd` is supported on purpose.

---

## Local Repo Mode

Install PushGuard only for the current repository:

```bash
pushguard install --local
```

Install both pre-push and pre-commit hooks locally:

```bash
pushguard install --local --both --paranoid
```

Uninstall local protection:

```bash
pushguard uninstall --local
```

---

## Global Mode

Install global Git protection:

```bash
pushguard install
```

Check global status:

```bash
pushguard status
```

Uninstall global protection:

```bash
pushguard uninstall
```

---

## Recommended `.env` Setup

Never commit real secrets.

Use local `.env`:

```env
TELEGRAM_BOT_TOKEN=123456789:real_secret_here
OPENAI_API_KEY=sk-real_secret_here
```

Commit safe `.env.example`:

```env
TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here
OPENAI_API_KEY=your_openai_key_here
```

Add `.env` to `.gitignore`:

```gitignore
.env
.env.*
!.env.example
```

---

## Security Model

PushGuard is a safety net, not magic.

It uses multiple detection layers:

1. **Known token regex rules**
2. **Provider fingerprint matching**
3. **Secret-looking variable name detection**
4. **Entropy-based unknown token detection**
5. **Git pre-push scanning of outgoing commits**

No scanner can detect every possible secret with 100% accuracy because providers create new token formats and some secrets look like normal strings.

For best protection:

- Keep secrets in `.env`
- Commit `.env.example`, not `.env`
- Add `.env` to `.gitignore`
- Rotate leaked keys immediately
- Use GitHub secret scanning too
- Review AI-generated code before pushing

---

## Example: Blocked Push

```txt
🚨 PushGuard blocked this push.

Found 2 possible secrets:

bot.js
  Possible Telegram bot token

config.py
  Possible OpenAI API key

Fix:
  Move secrets to .env
  Add .env to .gitignore
  Commit .env.example instead
```

---

## Works On

- Linux
- macOS
- Termux
- AWS EC2
- Most Unix-like Git environments

Windows support may work through Git Bash, WSL, or similar environments.

---

## Development

Clone:

```bash
git clone https://github.com/krishn03id/pushguard.git
cd pushguard
```

Install locally:

```bash
npm install -g .
```

Run tests:

```bash
npm test
```

Try scanner:

```bash
pushguard scan . --paranoid
```

Package preview:

```bash
npm pack --dry-run
```

---

## Roadmap

- Better Windows support
- More provider-specific patterns
- GitHub Actions integration
- JSON SARIF output
- More language-aware auto-fixes
- VS Code extension
- AI-agent safe mode
- Config file support

---

## Disclaimer

> [!CAUTION]
> PushGuard helps detect leaked secrets before Git push, but it is not a guarantee. Always rotate any secret that may have been exposed. The authors are not responsible for leaked credentials, misuse, false positives, or false negatives.

---

## License

MIT

---

<div align="center">
  <sub>Built for developers, beginners, and vibe coders who move fast but still want to push safely.</sub>
</div>
