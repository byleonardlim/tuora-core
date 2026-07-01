# Tuora

> Pre-deployment code security in-flight interceptor for AI-generated code.

[![Version](https://img.shields.io/badge/version-0.4.15-seagreen)](https://github.com/byleonardlim/tuora-core/releases) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) [![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](https://github.com/byleonardlim/tuora-core) [![Runs Locally](https://img.shields.io/badge/analysis-local%20WASM%20sandbox-seagreen)](https://runtuora.com)

---

## Overview

> *Cursor and Windsurf ship code fast.* So do the exploits hidden inside it. Tuora watches every file they touch and intercepts the bad stuff before it reaches production.

A security tool that slows you down has already failed. Tuora is built around that single conviction — watching silently, acting precisely, and never asking more of you than it has to. No alerts to dismiss. No gates to pass. A quiet layer underneath the work that catches what moves too fast to review — so you can keep moving.

The analysis engine runs entirely inside a **local WASM sandbox**. Your code never leaves your machine — not even for telemetry.

Current version: **0.4.15**.

---

## Why Tuora

Your AI just wrote 200 lines. It looks fine. Windsurf says "looks good." But the OpenAI key is hardcoded on line 14, the route handler has no auth check, and the `useEffect` has no dependency array — it will fire on every render and drain your quota.

AI tools optimize for plausible-looking output, not secure output. They don't review what they write. Tuora does.

Common patterns it catches:

- **Hardcoded secrets** — API keys, tokens, and database URLs baked directly into source files and shipped to the browser or a public repo.
- **SQL and NoSQL injection** — unsanitized user input passed directly into query strings or ORM methods.
- **Infinite re-render / runaway API calls** — missing `useEffect` dependency arrays that fire on every render and burn through quota.
- **Missing authentication checks** — AI-generated route handlers that expose data without verifying who is asking.
- **Structural loop failures** — agentic pipelines with no exit condition or recursion bounds.

> Rules are pattern-specific and conservative by design. Tuora flags what is demonstrably dangerous — not stylistic preferences or imperfect-but-safe code.

---

## How It Works

On every file save, Tuora runs a six-stage pipeline entirely on your machine:

1. **Verify identity** — your API key is checked against the Tuora ledger.
2. **Fetch rules** — signed threat-signature bundles are pulled from the cloud and cached locally.
3. **Ingest files** — the workspace is scanned. Supported: `.py` `.ts` `.js` `.tsx` `.svelte` `.yaml` `.yml` `.json` `.rs` `.env*`
4. **Evaluate in sandbox** — each file is run against the rule set inside a local Wasmtime WASM sandbox. No file content crosses the network.
5. **Render findings** — results hit your terminal with severity-coloured output and a 0–100 health score per file.
6. **Flush telemetry** — anonymised metadata only (rule IDs, severity counts — never code content) is sent asynchronously.

**Framework-aware.** Tuora auto-detects which agentic framework your project uses — CrewAI, LangGraph, LangChain, AutoGen, Mastra, Vercel AI, OpenAI Agents JS, LlamaIndex — and layers framework-specific rules on top of the baseline SAST set. Unknown framework? It falls back to standard SAST mode.

**Compliance-mapped.** Every finding is tagged to the relevant standard — OWASP Agentic Top 10 (2026), OWASP Web Top 10, OWASP API Security, CWE, MITRE ATLAS, or NIST AI RMF — so you can slot findings directly into whatever audit process you already run.

**Exit codes** are CI-friendly:

| Code | Meaning |
|------|---------|
| `0` | Clean scan or only medium/low issues |
| `1` | High severity issues found |
| `2` | Critical severity issues found |

---

## Workflow

One terminal tab. No configuration. The loop looks like this:

1. **Run `tuora watch`** alongside your editor. It monitors your project directory continuously.
2. **Your AI tool writes code.** Tuora picks up the file change and evaluates it immediately.
3. **A violation is found.** Tuora renders the finding in the terminal — rule ID, severity, file path, line number, and a plain-language description of the threat.
4. **Copy the finding.** Paste it into your AI editor's chat (Cursor, Windsurf, etc.) alongside a prompt like *"Fix this security issue."*
5. **Your AI tool understands the threat context** from the structured finding and applies the correct fix.
6. **Tuora re-evaluates on the next save.** Health score returns to 100/100 when the violation is resolved.

```
$ tuora watch

[14:32:05] ./src/lib/db.ts          No change (2ms)  Health: 100/100
[14:32:07] ./api/client.ts
  ↳ NEW  BZ-SEC-01  [CRITICAL]  hardcoded-api-key  :14
  ↳ Health: 0/100 • Blocked
```

> **AI writes → Tuora catches → you paste → AI fixes.** No context switching, no separate audit step, no gates blocking your build.

The loop will evolve as we scale how Tuora interacts with your editor.

---

## Getting Started

### 1. Install (macOS / Linux)

```bash
curl -fsSL https://get.runtuora.com/install.sh | sh
```

Installs `tuora` to `~/.local/bin/tuora`. No `sudo` required. The installer will prompt you to add the directory to `PATH` if it is not already there.

### 2. Configure your API key

```bash
tuora init
```

Prompts for your API key and stores it securely in the OS keyring. If a key is already stored, you will be asked whether to reinitialize. Get a free key at [runtuora.com](https://runtuora.com).

### 3. Watch your project

```bash
# Watch the current directory
tuora watch

# Watch a specific path
tuora watch ./my-agent-app

# Output as JSON (for CI/CD)
tuora watch ./my-agent-app --format json
```

Tuora re-evaluates on every file save. One terminal tab, no other setup required.

### Options & Flags

| Flag | Environment Variable | Default | Description |
|------|----------------------|---------|-------------|
| `--api-key` | `TUORA_API_KEY` | — | Tuora API key |
| `--format` | — | `ansi` | Output format: `ansi`, `json`, `plain` |

### Docker *(coming soon)*

Native Docker support is on the roadmap.

### CI/CD (GitHub Actions) *(coming soon)*

CI/CD integration is on the roadmap.

---

## Build from Source

> Requires Rust stable toolchain.

```bash
git clone https://github.com/byleonardlim/tuora-core.git
cd tuora-core/core

cargo build --release

# Run locally
cargo run -- watch ./my-project
```

The `build.rs` script embeds the ledger URL and signing public key at compile time. For local development, set `TUORA_LEDGER_URL` as an environment variable to override the baked-in value.

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

These indicate a signing key mismatch between the CLI client and the cloud API. Run `./debug_keys.sh` to diagnose the issue. For key generation, CI/CD secret configuration, build-time embedding, and key rotation procedures, see the comments in `core/build.rs`.

---

## License

Apache-2.0 — Open Core. The scanner engine is open source. Threat signature bundles are delivered as a SaaS service.
