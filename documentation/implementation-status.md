# Tuora Implementation Status

**Document Version:** 2026.6.4  
**Last Updated:** June 4, 2026

This document tracks the implementation status of Tuora components. For architecture details, see the Technical Requirements Document (`tech-req.md`).

---

## Core (Rust CLI)

| Component | Status | Location | Notes |
|-----------|--------|----------|-------|
| 6-Stage Pipeline | ✅ Complete | `core/src/main.rs` | Auth → Rules → Ingest → Evaluate → Render → Telemetry |
| Auth Client | ✅ Complete | `core/src/auth.rs` | Cloud handshake with 5-min cache, wallet validation |
| Credentials | ✅ Complete | `core/src/credentials.rs` | OS keyring + env var + CLI arg hierarchy |
| CLI/Config | ✅ Complete | `core/src/config.rs` | clap derive macros; commands: `init`, `watch`; no-arg shows help |
| File Scanner | ✅ Complete | `core/src/scanner.rs` | 10 framework patterns, zero-copy ingestion |
| Rule Engine (Native) | ✅ Complete | `core/src/rules/mod.rs` | 14 native rules, agentic + traditional SAST |
| Pattern Detection | ✅ Complete | `core/src/rules/patterns.rs` | 1000+ lines of detection logic |
| WASM Runtime | ✅ Complete | `core/src/rules/wasm_engine.rs` | wasmtime sandbox, bincode serialization |
| Remote Rules | ✅ Complete | `core/src/rules/remote.rs` | Version check → disk cache hit → download fallback; AES-256-GCM cache encryption; Ed25519 verify |
| Telemetry | ✅ Complete | `core/src/telemetry.rs` | Async batching, atomic ring buffer |
| Reporter | ✅ Complete | `core/src/reporter.rs` | ANSI (default), JSON, Plain formats |
| Progress | ✅ Complete | `core/src/progress.rs` | Animated spinner → ✓ pattern |
| Banner | ✅ Complete | `core/src/banner.rs` | ASCII shadow effect |
| Init Command | ✅ Complete | `core/src/commands/init.rs` | First-run setup; reinit prompt identifies keyring vs env var source |
| Watch Command | ✅ Complete | `core/src/commands/watch.rs` | Bootstrap scan + file-change watch loop; optional path arg |
| Types | ✅ Complete | `core/src/types.rs`, `types/src/lib.rs` | All schemas + serialization |

**Test Coverage:** Unit tests in each module. Run with `cargo test`.

---

## Cloud API (`api/`)

### Database Layer

| Component | Status | Location | Notes |
|-----------|--------|----------|-------|
| PostgreSQL Client | ✅ Complete | `src/db/postgres.ts` | Neon-compatible, SSL handling |
| MongoDB Client | ✅ Complete | `src/db/mongo.ts` | MongoDB Atlas driver |

### Services

| Component | Status | Location | Notes |
|-----------|--------|----------|-------|
| API Key Hashing | ✅ Complete | `src/services/keys.ts` | Argon2id (64MB, 3 iterations, 32-byte salt) |
| API Key Lookup | ✅ Complete | `src/services/keys.ts` | SHA-256 fast path + Argon2id verify |
| Wallet Balance Check | ✅ Complete | `src/services/wallet.ts` | Double-entry ledger aggregation |
| Scan Deduction | ✅ Complete | `src/services/wallet.ts` | Single + batch deduction |
| Auth Response Builder | ✅ Complete | `src/services/wallet.ts` | Tier calculation (Hobby/Standard/Volume); no JWT issued |

### API Endpoints

| Endpoint | Status | Location | Auth |
|----------|--------|----------|------|
| `POST /v1/auth` | ✅ Complete | `src/routes/auth.ts` | SHA-256 + Argon2id verify |
| `GET /v1/bundle-version` | ✅ Complete | `src/routes/rules-bundle.ts` | Bearer API key; returns `{ version, tier }` |
| `POST /v1/rules-bundle` | ✅ Complete | `src/routes/rules-bundle.ts` | Bearer API key; returns `rule-engine.wasm` |
| `POST /telemetry/batch` | ✅ Complete | `src/routes/telemetry.ts` | Bearer API key, batch insert |

---

## Dashboard (`cloud/dashboard/`)

### Database Schema (Neon)

| Table | Migration | Status |
|-------|-----------|--------|
| `workspaces` | `001_dashboard_schema.sql` | ✅ Complete |
| `accounts` | `001_dashboard_schema.sql` | ✅ Complete |
| `key_generations` | `001_dashboard_schema.sql` | ✅ Complete |
| `magic_link_tokens` | `001_dashboard_schema.sql` | ✅ Complete |
| `sessions` | `001_dashboard_schema.sql` | ✅ Complete |
| `current_api_keys` | `002_secure_api_key_storage.sql` | ✅ Complete |

### Server Libraries

| Component | Status | Location | Notes |
|-----------|--------|----------|-------|
| Database Client | ✅ Complete | `src/lib/server/db.ts` | Neon serverless, AES-256-GCM encryption |
| Auth (Lucia) | ✅ Complete | `src/lib/server/auth.ts` | Session management |
| Email (Resend) | ✅ Complete | `src/lib/server/email.ts` | Magic link generation/verification |
| Key Generation | ✅ Complete | `src/lib/server/keygen.ts` | `bz_dev_<32>` format, Argon2id |
| Dynamic Port | ✅ Complete | `src/lib/server/dynamic-port.ts` | Dev server URL detection |

### Routes

| Route | Status | Location | Notes |
|-------|--------|----------|-------|
| Landing Page (`/`) | ✅ Complete | `src/routes/(marketing)/` | Product site |
| Dashboard (`/dashboard`) | ✅ Complete | `src/routes/(app)/dashboard/` | Key display, usage stats |
| GitHub OAuth | ✅ Complete | `src/routes/auth/callback/github/` | OAuth callback handler |
| Email Sign In | ✅ Complete | `src/routes/auth/email/` | Magic link form |
| Email Verify | ✅ Complete | `src/routes/auth/email/verify/` | Token verification |
| Sign Out | ✅ Complete | `src/routes/auth/signout/` | POST endpoint |
| API Key Rotate | ✅ Complete | `src/routes/api/key/rotate/` | POST endpoint |

### Dashboard Features

| Feature | Status | Notes |
|---------|--------|-------|
| First Sign-In Key Generation | ✅ Complete | Auto-generates on new account |
| Secure Key Storage | ✅ Complete | AES-256-GCM encrypted, 1-hour expiry |
| Usage Statistics | ✅ Complete | Scans used/remaining, tier display |
| Key Rotation | ✅ Complete | Transfers balance, invalidates old key |
| Account Deletion | ⚠️ Partial | Framework in place, UI needs verification |

---

## Shared Types

| Component | Status | Location | Notes |
|-----------|--------|----------|-------|
| Rust Types | ✅ Complete | `types/src/lib.rs` | Wire protocol contract; no `bundle_token` field |
| Zod Schemas | ✅ Complete | `cloud/shared/schemas.ts` | Mirrors Rust types; includes `BundleVersionResponseSchema` |
| Sync Verification | ✅ Complete | Both files | Protocol in sync |

---

## WASM Rule Engine (`core/dev/mock-rules/`)

| Component | Status | Location | Notes |
|-----------|--------|----------|-------|
| Cargo Config | ✅ Complete | `Cargo.toml` | `cdylib` target, wasm32-unknown-unknown |
| `rule_count()` | ✅ Complete | `src/lib.rs` | Returns 13 (all rules implemented) |
| `malloc()` | ✅ Complete | `src/lib.rs` | Bump allocator at offset 65536 |
| `free()` | ✅ Complete | `src/lib.rs` | Simplified no-op for WASM |
| `evaluate_file()` | ✅ Complete | `src/lib.rs` | Full bincode (de)serialization |
| Memory Layout | ✅ Complete | `src/lib.rs` | 4-byte length prefix + data |
| Rule BZ-SEC-01 | ✅ Complete | `src/lib.rs` | Missing tool input schemas |
| Rule BZ-SEC-02 | ✅ Complete | `src/lib.rs` | Unsanitized string injections |
| Rule BZ-SEC-02B | ✅ Complete | `src/lib.rs` | Shell escalation detection |
| Rule BZ-FIN-01 | ✅ Complete | `src/lib.rs` | Missing recursion bounds |
| Rule BZ-FIN-02 | ✅ Complete | `src/lib.rs` | Unbounded chat history |
| Rule BZ-FIN-03 | ✅ Complete | `src/lib.rs` | High temperature extraction |
| Rule BZ-OPS-01 | ✅ Complete | `src/lib.rs` | Destructive without approval |
| Rule BZ-OPS-02 | ✅ Complete | `src/lib.rs` | Missing network timeouts |
| Rule BZ-HYG-01 | ✅ Complete | `src/lib.rs` | Hardcoded secrets |
| Rule BZ-HYG-02 | ✅ Complete | `src/lib.rs` | Env bleeding into prompts |
| Rule BZ-HYG-03 | ✅ Complete | `src/lib.rs` | AI credentials not from env |
| Rule BZ-SAST-01 | ✅ Complete | `src/lib.rs` | Insecure framework config |
| Rule BZ-SAST-02 | ✅ Complete | `src/lib.rs` | Wildcard CORS policy |
| Rule BZ-SAST-03 | ✅ Complete | `src/lib.rs` | SQL injection detection |
| Rule BZ-SAST-04 | ✅ Complete | `src/lib.rs` | Unpinned dependencies |

**Status:** ✅ **Fully Implemented.** All 13 compliance rules are complete in the WASM bundle. Native rules in `core/src/rules/patterns.rs` are now stubbed (deprecated).

---

## Pending Implementation

### 1. Stripe Webhooks (`cloud/payments/`)
- `payment_intent.succeeded` handler
- `checkout.session.completed` handler
- Wallet ledger credit insertion
- Top-up flow integration

### 2. Dashboard Enhancements
- `/pricing` page (exists, verify completeness)
- `/rules-info` page (exists, verify completeness)
- Billing section in dashboard (Stripe Customer Portal integration)

### 3. Distribution & Packaging
- [x] `install.sh` — Native CLI installer (curl | sh)
- [x] CI pipeline (`.github/workflows/ci.yml`)
- [x] Release workflow (`.github/workflows/release.yml`)
- [ ] GitHub Actions testing (requires repo setup)
- [ ] Release artifact publishing (requires GitHub Releases)
- [ ] `install.sh` testing on all platforms
- [ ] Windows PowerShell installer (`install.ps1`)
- [ ] Homebrew formula (future)
- ~~Docker distroless image~~ — Disabled (marked NOT READY in Dockerfile)

---

## Distribution & Installation

### Quick Install (Recommended)
```bash
curl -fsSL https://get.runtuora.com/install.sh | sh
```

This installs the Tuora CLI to `~/.local/bin/tuora` (user-level, no sudo required). Supports:
- **Linux**: x86_64, aarch64 (ARM64)
- **macOS**: Intel (x86_64), Apple Silicon (ARM64)
- **Windows**: PowerShell installer coming soon

### Manual Install
Download the binary for your platform from [GitHub Releases](https://github.com/tuora/tuora/releases) and place it in your PATH.

### From Source (Rust)
```bash
git clone https://github.com/tuora/tuora
cd breakzero
cargo build --release -p tuora
# Binary at: target/release/tuora
```

### First Run
```bash
tuora init           # Configure API key (stored in OS keyring)
tuora watch          # Scan and watch current directory
tuora watch ./path   # Scan and watch a specific path
```

## Testing Commands

```bash
# Core tests
cd core && cargo test

# Build and run locally
cd core && cargo run              # shows help
cd core && cargo run -- watch .   # watch current dir

# Cloud API tests
cd cloud/api && pnpm test

# Dashboard dev server
cd cloud/dashboard && pnpm dev
```

---

## Environment Variables Summary

### Core
| Variable | Required | Purpose |
|----------|----------|---------|
| `TUORA_API_KEY` | Yes* | API key for auth |
| `TUORA_LEDGER_URL` | No | Cloud API endpoint (default: `https://api.runtuora.com/v1`) |

*Or use OS keyring via `tuora init`. Installation is user-level (no sudo required).

### Cloud API
| Variable | Required | Purpose |
|----------|----------|---------|
| `DATABASE_URL` | Yes | Neon PostgreSQL connection |
| `MONGODB_URI` | Yes | MongoDB Atlas connection |
| `PORT` | No | Server port (default: 3000) |
| `BUNDLE_DIR` | No | WASM bundle storage path (default: `/var/tuora/bundles`) |
| `BUNDLE_VERSION` | No | Current bundle SemVer string (default: `0.1.0`) |
| `SIGNING_PRIVATE_KEY` | Yes (prod) | Ed25519 private key for signing WASM bundles |

### Dashboard
| Variable | Required | Purpose |
|----------|----------|---------|
| `DATABASE_URL` | Yes | Neon PostgreSQL connection |
| `LUCIA_SECRET` | Yes | Session signing key |
| `GITHUB_CLIENT_ID` | Yes* | GitHub OAuth app ID |
| `GITHUB_CLIENT_SECRET` | Yes* | GitHub OAuth secret |
| `RESEND_API_KEY` | Yes* | Email service API key |
| `RESEND_FROM_EMAIL` | Yes* | Sender email address |
| `API_KEY_ENCRYPTION_KEY` | No | AES-256-GCM key (auto-generated if missing) |

*Required for respective auth providers

---

## Related Documents

- `product-req.md` — Product requirements and feature definitions
- `tech-req.md` — Detailed technical architecture
- `dashboard-spec.md` — Dashboard UI/UX specifications
- `compliance-rules.md` — Security rule definitions
- `neon-setup.md` — Database setup instructions
