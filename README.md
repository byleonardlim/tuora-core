# Tuora

> Pre-deployment code security in-flight interceptor for AI-generated code.

---

## Overview

Cursor and Windsurf ship code fast. So do the exploits hidden inside it. Tuora watches every file they touch and intercepts the bad stuff before it reaches production.

A security tool that slows you down has already failed. Tuora is built around that single conviction — watching silently, acting precisely, and never asking more of you than it has to. No alerts to dismiss. No gates to pass. A quiet layer underneath the work that catches what moves too fast to review — so you can keep moving.

The analysis engine runs entirely inside a **local WASM sandbox**. Your code never leaves your machine — not even for telemetry.

Current version: **0.4.15**.

---

## Why

AI tools don't review what they write. They inline secrets into client bundles, skip input sanitization, forget dependency arrays, and introduce injection paths — not maliciously, but structurally, because they optimize for plausible-looking output, not secure output.

The exploits are real. Common patterns Tuora catches:

- **Hardcoded secrets** — API keys, tokens, and database URLs baked directly into source files and shipped to the browser or a public repo.
- **SQL and NoSQL injection** — unsanitized user input passed directly into query strings or ORM methods.
- **Infinite re-render / runaway API calls** — missing `useEffect` dependency arrays that fire on every render and burn through quota.
- **Missing authentication checks** — AI-generated route handlers that expose data without verifying who is asking.
- **Structural loop failures** — agentic pipelines with no exit condition or recursion bounds.

Tuora flags what is demonstrably dangerous, not stylistic choices or imperfect-but-safe code. Rules are pattern-specific and conservative by design.

---

## How

Tuora runs a **6-stage execution pipeline** on every file change:

1. **Cloud Auth** — API key verification against the Tuora ledger service.
2. **WASM Rule Fetch** — Signed threat-signature bundles are pulled from the cloud and cached locally.
3. **Local File Ingest** — The workspace is scanned and files are read into memory. Supported extensions: `.py` `.ts` `.js` `.tsx` `.svelte` `.yaml` `.yml` `.json` `.rs` `.env*`
4. **WASM Rule Evaluation** — Each file is evaluated inside a local Wasmtime sandbox against the loaded rule set. No file content crosses the network boundary.
5. **ANSI Rendering** — Results are printed to the terminal with severity-coloured output and a 0–100 health score per file.
6. **Async Telemetry Flush** — Anonymised scan metadata (rule IDs, severity counts, no code content) is flushed asynchronously.

**Framework detection** is automatic. Tuora identifies which agentic framework is in use (CrewAI, LangGraph, LangChain, AutoGen, Mastra, Vercel AI, OpenAI Agents JS, LlamaIndex) and applies framework-specific rule overlays on top of the baseline SAST rules. If no known framework is detected, it falls back to traditional SAST mode.

**Rule taxonomy** maps violations to OWASP Agentic Top 10 (2026), OWASP Web Top 10, OWASP API Security, CWE, MITRE ATLAS, and NIST AI RMF — so findings can be mapped to whichever compliance standard your downstream process requires.

**Exit codes** are CI-friendly:

| Code | Meaning |
|------|---------|
| `0` | Clean scan or only medium/low issues |
| `1` | High severity issues found |
| `2` | Critical severity issues found |

---

## Workflow

Tuora is designed to slot directly into the AI-assisted coding loop:

1. **Run `tuora watch` in a terminal tab** alongside your editor. It monitors your project directory continuously.
2. **Your AI tool writes code.** Tuora picks up the file change and evaluates it immediately.
3. **A violation is found.** Tuora renders the finding in the terminal — rule ID, severity, file path, line number, and a plain-language description of the threat.
4. **Copy the finding.** Paste it into your AI editor's chat (Cursor, Windsurf, etc.) alongside a prompt like *"Fix this security issue."*
5. **Your AI tool understands the threat context** from the structured finding and applies the correct fix.
6. **Tuora re-evaluates on the next save.** Health score returns to 100/100 when the violation is resolved.

The loop is: **AI writes → Tuora catches → you paste → AI fixes.** No context switching, no separate audit step, no gates blocking your build.

The loop will change overtime as we scale how we interact with Tuora.

---

## Getting Started

### Install (macOS / Linux)

```bash
curl -fsSL https://get.runtuora.com/install.sh | sh
```

Installs `tuora` to `~/.local/bin/tuora`. No `sudo` required. The installer will prompt you to add the directory to `PATH` if it is not already there.

### Configure your API key

```bash
tuora init
```

Prompts for your API key and stores it securely in the OS keyring. If a key is already stored, you will be asked whether to reinitialize. Get a free key at [runtuora.com](https://runtuora.com).

### Watch your project

```bash
# Watch the current directory
tuora watch

# Watch a specific path
tuora watch ./my-agent-app

# Output as JSON (for CI/CD)
tuora watch ./my-agent-app --format json
```

Tuora re-evaluates on every file save. One terminal tab, no other setup required.

### Options

| Flag | Environment Variable | Default | Description |
|------|----------------------|---------|-------------|
| `--api-key` | `TUORA_API_KEY` | — | Tuora API key |
| `--format` | — | `ansi` | Output format: `ansi`, `json`, `plain` |

### Docker

```bash
docker pull tuora/tuora:latest

docker run --rm -v $(pwd):/app \
  -e TUORA_API_KEY=$TUORA_API_KEY \
  tuora/tuora:latest \
  watch /app
```

### CI/CD (GitHub Actions)

```yaml
- name: Security Scan
  env:
    TUORA_API_KEY: ${{ secrets.TUORA_API_KEY }}
  run: |
    tuora watch . --format json
```

---

## Build from Source

```bash
git clone https://github.com/byleonardlim/tuora-core.git
cd tuora-core

cargo build --release -p tuora

# Run locally
cargo run -p tuora -- watch ./my-project
```

Requires Rust stable. The `build.rs` script embeds the ledger URL and signing public key at compile time. For local development, set `TUORA_LEDGER_URL` as an environment variable to override the baked-in value.

---

## FAQ

**Does Tuora upload my code anywhere?**
No. The analysis engine runs entirely in a local WASM sandbox. Your source files, secrets, and logic never leave your environment — not even for telemetry.

**Does it work with any AI tool, or only Cursor and Windsurf?**
It works with any file your AI tool writes. Tuora watches the filesystem, not the editor — so it works with Cursor, Windsurf, ChatGPT, Claude, Copilot, or anything else that touches your project directory.

**Will it false-positive constantly?**
Rules are pattern-specific and conservative by design. Tuora flags what is demonstrably dangerous — hardcoded secrets, exploitable injection paths, structural loop failures — not stylistic choices or imperfect-but-safe code.

**Is it really free?**
Hobby is free, always. No time limit, no credit card required. Pro is in development — the Hobby tier stays free regardless of what Pro launches at.

**What file types does Tuora scan?**
`.py` `.ts` `.js` `.tsx` `.svelte` `.yaml` `.yml` `.json` `.rs` and `.env*` files. Build artifacts, `node_modules`, `target`, `.next`, and other non-source directories are skipped automatically.

**I see "Invalid Ed25519 signature" or "Signing public key not embedded".**
These indicate a signing key mismatch between the CLI client and the cloud API. See `documentation/key-management.md` for key generation, CI/CD secret configuration, build-time embedding, and key rotation procedures.

---

## License

Apache-2.0 — Open Core. The scanner engine is open source. Threat signature bundles are delivered as a SaaS service.
