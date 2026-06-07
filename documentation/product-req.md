# Product Requirements Document (PRD): Tuora

**Document Version:** 2026.3.2

**Document Focus:** Standalone Pre-Deployment Scanning Core, Infrastructure Footprint, Pre-Paid Wallet Ledger, and Polyglot Ingestion Tier

**Exclusion Criteria:** This document intentionally excludes structural, financial, or security logic matching the SHIELDZERO_COMPLIANCE_RULES.md / TUORA_COMPLIANCE_RULES.md rule sets, focusing strictly on the systemic product platform frameworks.

## 1. Executive Summary & Product Scope

Tuora is an ultra-lightweight, zero-footprint developer static analysis utility (Linter/Scanner) designed to provide instant security, financial, and structural checks for vibe-coded applications before deployment. It targets the immediate anxiety shared by citizen developers and indie hackers deploying code generated at lightspeed via natural language AI code editors (e.g., Cursor, Windsurf): "I built this entire application in hours from natural language prompts, it compiles and runs, but I have absolutely no idea what hidden architectural flaws, budget traps, or injection vectors I just introduced."

The product scope of Tuora is strictly bounded to Pre-Deployment Static Application Security Testing (SAST) and Configuration Linting. It operates entirely locally on client compute resources via a stateless, self-terminating pipeline, verifying access eligibility via a pre-paid credit card token wallet ledger ($0.10 scaling down to $0.07 per scan), and indexing output data dynamically within a hybrid relational and document database stack.

> **Note:** Persistent, inline, runtime reverse-proxy firewalling and human-in-the-loop socket intercept loops are explicitly excluded from Tuora, remaining the unique domain of the ScrubZero enterprise suite.

## 2. Core Functional Primitives & Execution Lifecycle

Tuora executes exclusively as a stateless, non-daemonized, self-terminating CLI utility. It does not bind to local ports or maintain open execution loops.

**User Experience:** On launch, Tuora displays a clean ASCII banner, then shows animated progress indicators (spinning → ✓) for each pipeline stage before rendering the final analysis report.

The application lifecycle conforms to a strict, sequential six-stage pipeline:

```
         [ Command Fired ]
                │
                ▼
[ Stage 1: Cloud Auth Check ]
                │
                ▼
 [ Stage 2: WASM Rule Fetch ]
                │
                ▼
[ Stage 3: Local File Ingest ]
                │
                ▼
[ Stage 4: WASM Rule Evaluation ]
                │
                ▼
   [ Stage 5: ANSI Rendering ]
                │
                ▼
 [ Stage 6: Async Telemetry ]
                │
                ▼
    [ Exit Container ]
```

- **Phase 1: Cryptographic Authorization Handshake:** Halts file ingestion until it passes an out-of-band HTTPS validation call to verify account liquidity constraints.

- **Phase 2: Proprietary Rule Bundle Acquisition:** Fetches the threat signature WASM module from the cloud API immediately after authentication. The bundle undergoes signature verification and loads into a sandboxed wasmtime runtime. In debug builds, this stage sources from local filesystem (`dev/rules.wasm`) instead. **Note:** The WASM rule engine is complete with 13 rules. The CLI uses WASM rules as the primary backend; native Rust rules in `patterns.rs` are now stubbed (deprecated).

- **Phase 3: Local In-Memory Workspace Ingestion:** Extracts application manifests, workspace parameters, and functional configurations using zero-copy memory reads into local thread-safe RAM.

- **Phase 4: WASM-Based Rule Evaluation:** Serializes ingested files and passes them across the WebAssembly boundary to the sandboxed rule engine for threat detection. Results are deserialized back into native structures.

- **Phase 5: ANSI Report Production:** Displays an ASCII banner on startup, shows animated progress indicators during the 6-stage pipeline, streams a crisp summary table with grouped violations, and renders word-wrapped plain-English guidance directly to the developer's terminal display console.

- **Phase 6: Decoupled Telemetry Sinking:** Increments atomic buffer limits and fires an asynchronous background flush transaction to record unit deductions before executing a complete self-contained termination sequence (Exit Code 0).

## 3. Distribution, Footprint, & Deployment Requirements

To guarantee immediate bottom-up adoption across diverse developer compute scopes—ranging from base-model developer laptops with low storage partitions to isolated cloud testing workspaces (e.g., IDX, Gitpod, Replit) or continuous integration pipelines—the footprint must be minimized.

### 3A. Distroless Container Delivery Engine

- **Storage Footprint Restriction:** Total uncompressed image layer storage footprint must remain strictly under 20MB (target baseline: ~11MB to 14MB).

- **Base Layer Constraint:** The configuration completely bars operating system base targets (Ubuntu, Debian) or shell platforms (Alpine). The engine relies exclusively on a clean Google Distroless Static runtime profile (`gcr.io/distroless/static-debian12:nonroot`).

- **Packaging Inventory:** The container packs precisely three functional assets:
  - Statically compiled, stripped `tuora` binary executable (~12MB).
  - Core system root CA certification vectors (`/etc/ssl/certs/ca-certificates.crt`) required to establish the out-of-band HTTPS billing session.
  - Custom entrypoint routing execution helper script.

- **Volume Isolation:** Codebase access is achieved strictly through a read-only volume container mount flag (`-v $(pwd):/app`).

- **Automatic Eviction:** Invocation documentation mandates the use of the `--rm` parameter, instructing the host Docker daemon to wipe the container context instance out of system memory immediately upon execution termination, preserving complete data isolation.

### 3B. Native CLI Standalone Binary Distribution

The CLI distribution is the **primary and recommended** distribution method for developer workstations. It provides superior performance (startup ~100ms vs ~500-1000ms for Docker) and seamless IDE/pre-commit hook integration.

#### 3B.1. Installation Methods

**Quick Install (curl-based):**
```bash
curl -fsSL https://get.runtuora.com/install.sh | sh
```

**Package Managers:**
```bash
# macOS (Homebrew)
brew install tuora

# Linux (cargo)
cargo install tuora

# Windows (Scoop)
scoop install tuora
```

**Direct Download:**
Static binaries available for:
- macOS (ARM64/Intel)
- Linux (x86_64, ARM64)
- Windows (x64)

#### 3B.2. OS/Arch Fingerprinting

The installer script evaluates host system properties (e.g., Mac M1/M2/M3 ARM, Intel Linux, Windows x64) to fetch the exact pre-compiled static file asset from secure cloud bucket channels.

#### 3B.3. First-Run Initialization (`tuora init`)

To eliminate API key friction and improve security, Tuora implements an interactive first-run initialization flow:

**User Experience Flow:**
```
$ tuora init
Enter your Tuora API key: bz_dev_...
✓ API key validated and stored securely in OS keyring
✓ Ready to scan. Run `tuora watch` to begin.

$ tuora watch
# Scans and watches the current directory

$ tuora watch ./my-agent-app
# Scans and watches a specific path
```

**Re-initialization Flow (key already stored):**
```
$ tuora init
⚠ An API key is already stored in the OS keyring.
Do you want to reinitialize with a new API key? [y/N]:
```

**Implementation Details:**
- **OS Keyring Integration:** Stores API key in platform-native secure storage:
  - macOS: Keychain Access (`tuora` service, `api_key` account)
  - Linux: Secret Service API / kwallet / gnome-keyring (via keyring crate)
  - Windows: Credential Manager (`tuora` target name)
- **Validation on Save:** Validates the API key with a cloud ping before storage
- **Fallback Hierarchy:** 
  1. CLI argument (`--api-key`) - highest priority, for CI/CD
  2. Environment variable (`TUORA_API_KEY`)
  3. OS keyring storage (persistent, recommended for daily use)
- **Docker Compatibility:** `init` command detects containerized environments and errors with clear instructions to use environment variables instead

#### 3B.4. CLI Commands

| Command | Description |
|---------|-------------|
| `tuora` | Show available commands |
| `tuora init` | Interactive API key setup with OS keyring storage |
| `tuora watch` | Scan and watch the current directory |
| `tuora watch <path>` | Scan and watch a specific directory path |
| `tuora --version` | Show version |

#### 3B.5. CLI Options

| Option | Description |
|--------|-------------|
| `-a, --api-key <KEY>` | API key (overrides keyring/env) |
| `-f, --format <FORMAT>` | Output: `ansi` (default), `json`, `plain` |

## 4. Pre-Paid Credit Wallet System & Entitlement Matrix

Tuora eliminates post-paid billing uncertainty by shifting entirely to a pre-paid consumption framework driven by localized user balance primitives.

```
+───────────────────────────────────────────────────────────────────────────+
|                          CREDIT WALLET ENTITLEMENTS                       |
+───────────────────────────────────────────────────────────────────────────+
  [ Hobbyist Sandbox Pool ] ──────► 100 Free Scans (Lifetime/Account Limit)
                                                │
                                    (Exhausted / Upgraded)
                                                ▼
  [ Pre-Paid Top-Up Gate ] ───────► Enforces $2.00 USD Minimum Recharge Floor
                                                │
                                                ├──► Scans 1 - 999:    $0.10 / Scan
                                                └──► Scans 1,000+:     $0.07 / Scan
```

### 4A. Consumption Tier & Replenishment Bounds

- **The Hobbyist Free Pool:** New workspace credentials automatically receive a non-recurring trial allotment containing 100 free scans. Once the 100 checks are exhausted, the authentication gateway refuses compilation tokens until a credit card is validated and funded.

- **The Refunding Threshold Floor:** To protect the business model from micro-transaction processor percentage decay, the payment collection dashboard enforces a minimum transaction cap floor of USD $2.00 for any recharge or top-up operation.

- **Dynamic Cost De-escalation:** The ingestion ledger monitors cumulative historical workspace scan counts to shift pricing calculations automatically:
  - **Standard Volume Scale (Scans 1 to 999):** Each valid check sequence deducts exactly $0.10 from the user's prepaid asset ledger balance.
  - **High-Volume Scale (Scans 1,000 onwards):** The engine modifies step parameters, reducing the per-scan charge metric down to $0.07 to reward high-frequency development teams and CI/CD pipelines.

## 5. Technical Key Verification Handshake

To prevent client-side modifications from executing infinite local compilation evaluations for free, Tuora requires a cloud check handshake to unlock its parsing engines.

### 5A. Token Signature Taxonomy

- **Identifying String Markers:** Keys are formatted with structural prefixes: `bz_dev_[a-zA-Z0-9]{32}`. This structural uniformity allows public source repositories (like GitHub Secret Scanning patterns) to auto-detect and block compromised secrets before code lines are checked into public view.

- **One-Way Backend Protection:** Plain-text tokens are revealed on screen exactly once during provisioning. The central server stores only strong one-way cryptographic hashes (SHA-256 or Argon2id employing a unique 32-byte salt).

### 5B. The Handshake Verification Flow

- **The Telemetry POST Ping:** On initialization, Tuora holds code ingestion and shoots an HTTPS POST query containing the text string target to `https://api.runtuora.com/v1/auth`.

- **Server Ledger Rules Engine:** The gateway tests the token parameter hash to confirm three variables:
  1. The account key matches an active database hash signature.
  2. The lifetime usage ledger count is tracked to assign the step cost rate ($0.10 vs. $0.07).
  3. Remaining pre-paid wallet cash structures contain sufficient liquidity to absorb the unit cost.

- **Lockout Boundary Enforcement:** If account checking rules fail, the central engine generates an authorization rejection. Tuora breaks execution before processing files, logging a terminal error block to standard error (`Exit Code 1: Insufficient Balance. Current wallet balance does not cover execution unit parameters ($0.10 / $0.07). Minimum top-up threshold: $2.00.`).

- **Local Budget Token Window Caching:** To prevent concurrent continuous integration test runs or rapid prompt iterations from overwhelming central cloud load balancers, valid tokens cache a clearance lease inside container RAM for 300 seconds (5 minutes) or for a specific scan budget proxy constraint parameter (e.g., `"cached_allowed_units": 10`) before demanding a fresh out-of-band network ping.

## 6. High-Velocity Metering Pipeline & Hybrid Polyglot Data Model

### 6A. Non-Blocking Atomic Counter Management

- **Atomic Sinking Layers:** Local testing operations cannot lag over remote data writes. The Rust binary core logs tracking items straight into an in-memory Atomic Memory Ring Buffer using atomic indicators (`std::sync::atomic::AtomicU64`), dropping local thread-contention overhead to exactly 0ns.

- **Batch Network Sinking:** An async tracking task processes buffer limits out-of-band, compressing datasets via fast protocols (`zstd` or `lz4`) and flushing them over TLS to the cloud infrastructure every 60 seconds (or upon accumulating 1,000 checks).

### 6B. Hybrid Polyglot Storage Architecture

Tuora routes incoming operational and accounting datasets into separate database nodes, matching engine utility to transaction behavior:

```
              [ Tuora Ingestion Cloud Ingest Gateway ]
                                     │
       ┌─────────────────────────────┴─────────────────────────────┐
       ▼                                                           ▼
+─────────────────────────────────+                 +─────────────────────────────────+
│       PostgreSQL Engine         │                 │      MongoDB Atlas Cluster      │
│  [ Double-Entry Wallet Vault ]  │                 │   [ Polymorphic Scan Records ]  │
│  - Strict SQL Type Verification │                 │   - Flexible BSON Log Formats   │
│  - ACID High-Concurrency MVCC  │                 │   - Deep Graph Layout Topologies│
│  - Prevents Race Exploits       │                 │   - Schema-Migration Free Engine│
+─────────────────────────────────+                 +─────────────────────────────────+
```

- **The Financial Vault Layer (PostgreSQL):** Handles the prepaid balance accounting system using a strict relational table schema. It employs PostgreSQL's ACID transactional boundaries and Multi-Version Concurrency Control (MVCC) to secure cash modifications and eliminate double-spending risks during parallel pipeline check sweeps.

- **The Application Analytics Layer (MongoDB Atlas):** Ingests the complex structural logging data fields output by the tool engine (such as AST diagnostic trees, list maps detailing vulnerability indices, and framework properties). Because vibe-coded applications use varying orchestrator definitions (LangGraph, CrewAI, AutoGen), MongoDB's schema-flexible document design allows engineers to scale features to new AI frameworks instantly without executing structural database migrations.

### 6C. Open-Core Code Splitting Separation

- **The Open Base Core (Open Source):** The primary CLI framework, file ingestion pipeline, token lexer infrastructure, folder scanners, async memory ring buffers, and WASM execution runtime operate as open-source code (licensed under MIT or Apache 2.0). This transparency builds trust, letting developers verify that their application source files are analyzed strictly in local memory and never leaked to external data centers.

- **The Closed Rule Bundle (Proprietary SaaS):** The specialized threat signatures mapping to live agent exploits, vulnerability detection patterns, and compliance rule implementations are compiled into a signed WebAssembly (WASM) module. This module is fetched from `https://api.runtuora.com/v1/rules-bundle` immediately after successful authentication and wallet validation. The WASM bundle executes within a sandboxed runtime (wasmtime) with no filesystem or network access, ensuring threat detection logic remains proprietary while maintaining client-side execution privacy. The rule engine source remains Rust (`cloud/rules/rule-engine/`, compiled to `wasm32-unknown-unknown`).

- **Supporting SaaS Infrastructure:** The cloud backend (`cloud/`) is implemented in TypeScript (Node.js 22, Fastify 5) with the exception of the WASM rule engine which is Rust. It exposes three endpoints at `https://api.runtuora.com`: auth/wallet verification (`/v1/auth`), rule bundle delivery (`/v1/rules-bundle`), and telemetry ingestion (`/telemetry/batch`). Payment processing is handled by a dedicated Stripe webhook service (`cloud/payments/stripe-webhooks/`) — fully implemented with `payment_intent.succeeded` and `checkout.session.completed` handlers that credit the PostgreSQL wallet ledger. Double-entry credit balance wallets (PostgreSQL), multi-tenant scan logs (MongoDB Atlas), and enterprise expansion attachments reside safely behind these commercial cloud SaaS systems.
