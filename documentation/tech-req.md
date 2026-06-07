# Technical Requirements Document (TRD): Tuora

**Document Version:** 2026.6.4

**Engineering Domain:** Pre-Deployment Static Analysis (LintMode Only) for Vibe-Coded Frameworks

**Target Architecture Stack:** Statically Linked Rust Core (CLI), TypeScript/Node.js (Cloud API), Google Distroless Static, Hybrid Polyglot Data Tier (PostgreSQL + MongoDB Atlas Ingestion)

**Repository Layout:** Private monorepo with open-core CLI (`core/`), closed-source cloud backend (`cloud/`), and shared wire-protocol types (`types/`). Proprietary WASM rule engine (`cloud/rules/rule-engine/`) is Rust compiled to wasm32-unknown-unknown.

---

## 1. Architectural Scope & Execution Lifecycle

Tuora is designed strictly as a single-purpose, stateless, self-terminating command-line tool written in Rust. It does not act as an inline network gateway proxy or persistent firewall microservice (which are primitives belonging exclusively to ScrubZero).

```
                   [ Invoke `tuora` Execution ]
                                  │
                                  ▼
               [ Phase 1: Cryptographic Wallet Check ]
              Out-of-band TLS Ping to Cloud Handshake Gate
                                  │
                  ┌───────────────┴───────────────┐
                  ▼ (Wallet Funded)               ▼ (Depleted/Invalid)
        [ Fetch WASM Rule Bundle ]        [ Process Termination ]
         Download + Verify Signature             Exit Code 1
                  │                               │
                  ▼                               ▼
     [ Load into wasmtime Sandbox ]       [ Abort Workflow ]
         Initialize Rule Engine
                  │
                  ▼
       [ Phase 2: In-Memory Ingest ]
      Read Workspace Manifests & AST
                  │
                  ▼
       [ Phase 3: Evaluation Engine ]
      WASM-based Rule Evaluation
                  │
                  ▼
       [ Phase 4: Output Rendering ]
        Print Banner, Progress, Grouped Violations & Health Score
                  │
                  ▼
       [ Phase 5: Async Telemetry Flush ]
      Sync Batch Log via Atomic Ring Buffer
                  │
                  ▼
        [ Container Destruction ]
            (--rm Engine Exit)
```

### 1A. Lifecycle Phases

- **The Handshake Constraint:** Halts repository processing until an out-of-band HTTPS POST call validates that the presentation token (`TUORA_API_KEY`) is active and the pre-paid workspace wallet balance contains funded assets (≥ $0.10 or ≥ $0.07).

- **WASM Rule Bundle Acquisition:** Immediately following successful authentication, the CLI performs a lightweight `GET /v1/bundle-version` check. If a matching bundle exists in `~/.cache/tuora/`, it is decrypted and loaded from disk. Otherwise the CLI fetches the full bundle from `POST /v1/rules-bundle`. All network requests use the API key as a Bearer token. The bundle undergoes Ed25519 signature verification before being loaded into a sandboxed wasmtime runtime. On debug builds, this stage is bypassed in favor of local filesystem loading from `dev/rules.wasm`.

- **Local Repository Extraction:** Ingests local application properties (mounted read-only at `/app`) using zero-copy file pointers to copy structures strictly into thread-safe stack memory allocations.

- **The WASM Rule Evaluation Engine:** Cross-references application structures against the threat signature matrix by serializing ingested files and passing them across the WASM boundary to the sandboxed rule engine. Results are deserialized back into native Rust structures.

- **Console Output:** Displays an ASCII banner on startup, renders animated progress indicators (spinner → ✓) for each pipeline stage, and streams grouped violations with word-wrapped plain-English explanations (~88 chars/line) along with an operational AI health score to the stdout stream.

- **Non-Blocking Telemetry Sinking:** Increments atomic buffer fields out-of-band and exits safely (Exit Code 0), triggering automatic container cleanup.

---

## 2. Containerization & Size Optimization Specifications

To prevent installation friction inside tight local hard drives, specialized continuous integration environments (e.g., GitHub Actions, Vercel, Replit), or temporary dev pods, the system enforces a strict container constraint framework.

### 2A. Multi-Stage Distroless Image Directives

- **Storage Footprint Cap:** Total uncompressed image runtime weight must not exceed 20MB (target baseline distribution tier: ~11MB to 14MB).

- **Base Layer Constraint:** Explicitly blocks standard Unix operating system targets (Ubuntu/Debian) or shell runtimes (Alpine). The binary relies on an immutable Google Distroless Static base layer configuration (`gcr.io/distroless/static-debian12:nonroot`).

- **Static Compilation Toolchain:** Compiles code objects using `x86_64-unknown-linux-musl` or corresponding target environments to drop runtime standard-library dependencies (glibc), ensuring cross-environment stability.

- **Baked Image Asset Boundaries:** Shipped images containerize exactly three files:
  - The optimized static `tuora` execution core binary (~12MB).
  - Root authority SSL configuration anchors (`/etc/ssl/certs/ca-certificates.crt`) for out-of-band web handshakes.
  - Non-root system UID indicators (`USER 65532:65532`) to satisfy safe multi-tenant sandbox rules.

### 2B. Size Minimization Profiles (`Cargo.toml`)

The release target maps compilation variables to minimize output binary sizes:

```toml
[profile.release]
opt-level = "z"        # Commands the compiler to optimize machine instructions strictly for size
lto = true             # Triggers comprehensive Cross-Crate Link-Time Optimization
codegen-units = 1      # Prevents block parallelization to maximize code layout compression
panic = "abort"        # Eliminates panic stack unwinding and tracking string frameworks

[dependencies]
wasmtime = { version = "24.0", default-features = false, features = ["cranelift", "runtime"] }
wasmtime-environ = "24.0"
bincode = "1.3"        # Zero-copy serialization for WASM boundary
dirs = "5.0"           # Cache directory resolution for rule bundles
keyring = "3"          # OS keyring integration for API key storage
```

- **Production Stripping Execution:** The container pipeline strips the artifact (`strip --strip-all target/release/tuora`) to sweep away trace elements, testing maps, and debugging symbols before outputting the layer image.

- **WASM Runtime Footprint:** The wasmtime dependency adds ~2-3MB to the final binary, keeping the total under the 20MB container limit.

---

## 3. API Key Storage & Credential Management

Tuora implements a **secure-by-default** credential storage strategy that prioritizes both security and user experience across different deployment contexts.

### 3A. Storage Architecture

**Primary Storage: OS Keyring (Native Desktop)**

The CLI uses the platform-native credential store via the `keyring` crate:

```
Service: "tuora"
Account: "api_key"
Value:   <API_KEY> (plaintext, OS encrypts at rest)
```

| Platform | Backend | Storage Location |
|----------|---------|------------------|
| macOS | Keychain Services | `~/Library/Keychains/login.keychain-db` |
| Linux | Secret Service API | `~/.local/share/keyrings/` (default) |
| Windows | Windows Credential Manager | Credential Vault |

**Security Properties:**
- Key never touches disk in plaintext (OS-managed encryption)
- Protected by user's login session (biometric unlock on macOS/Windows)
- Isolated from other applications via OS sandboxing
- Automatic cleanup on user account removal

### 3B. Credential Resolution Hierarchy

Tuora resolves the API key using the following priority order:

```rust
1. CLI argument (--api-key <KEY>)
   └── Highest priority, for CI/CD pipelines and one-off scans
   
2. Environment variable (TUORA_API_KEY)
   └── Secondary, for shell scripts and Docker
   
3. OS Keyring storage
   └── Default for interactive developer use
   
4. First-run prompt
   └── If none found, guide user to `tuora init`
```

### 3C. Docker & Container Compatibility

Containers cannot access host OS keyrings. Tuora detects containerized environments and adapts:

```rust
fn is_running_in_docker() -> bool {
    std::path::Path::new("/.dockerenv").exists() ||
    std::fs::read_to_string("/proc/self/cgroup")
        .map(|c| c.contains("docker"))
        .unwrap_or(false)
}
```

**Docker Behavior:**
- Skip `init` command with clear error: "`tuora init` unavailable in Docker. Use `TUORA_API_KEY` env var."
- Require `TUORA_API_KEY` environment variable
- Validate key early, fail fast with actionable error message

### 3D. First-Run Initialization (`tuora init`)

**Command Flow:**

1. **Check Existing:** Call `get_existing_api_key()` — single keychain read (avoids double macOS Keychain prompt)
2. **If found:** Display source (OS keyring or `TUORA_API_KEY` env var) and ask "Do you want to reinitialize with a new API key? [y/N]"
3. **Prompt User:** Interactive prompt: "Enter your Tuora API key:" (masked input)
4. **Validate:** Ping ledger service to verify key validity
5. **Store:** Save to OS keyring on successful validation
6. **Confirm:** Print success message

**Implementation Sketch:**

```rust
// Single keychain read — avoids double macOS Keychain authorization prompt
pub fn get_existing_api_key() -> Option<String> {
    if let Ok(key) = std::env::var("TUORA_API_KEY") {
        if !key.is_empty() { return Some(key); }
    }
    if !is_running_in_docker() {
        if let Ok(entry) = keyring::Entry::new("tuora", "api_key") {
            if let Ok(key) = entry.get_password() {
                if !key.is_empty() { return Some(key); }
            }
        }
    }
    None
}

pub fn get_api_key(cli_key: Option<String>) -> Result<String> {
    // 1. CLI argument (highest priority)
    if let Some(key) = cli_key {
        if !key.is_empty() { return Ok(key); }
    }
    // 2 & 3. Env var then OS keyring — single read, one Keychain access
    if let Some(key) = get_existing_api_key() {
        return Ok(key);
    }
    bail!("No API key configured. Run `tuora init`.");
}
```

### 3E. Security Considerations

| Threat | Mitigation |
|--------|-----------|
| Key in shell history | Keyring storage avoids CLI args; env var only for CI |
| Key in `ps aux` output | Keyring retrieval happens before subprocess spawning |
| Memory dump exposure | Key zeroed from memory after use (Drop implementation) |
| Container layer leakage | Never write key to image layers; env only |
| Keyring enumeration | Standard OS protections; no custom crypto |
| Network interception | HTTPS only; TLS 1.3 for all API calls |

---

## 4. Local Workspace Ingestion & AST Extraction

Code verification executes completely locally inside the user's secure framework infrastructure. Source files are never parsed on or sent to cloud targets, guaranteeing absolute code data privacy.

### 4A. Zero-Copy Serialization Paths

- **Memory Primitives:** Utilizes memory reference mapping primitives (`&str` borrowed lifetimes) over file contexts loaded using the `serde_json` and `serde_yaml` crates to eliminate dynamic allocation cycles.

- **Manifest Mapping Matrix:** Automatically discovers and deserializes workspace shapes matching target vibe-coded orchestration topologies:

  **Python Frameworks:**
  - **CrewAI:** Priority-detected via `agents.yaml` or `tasks.yaml` manifest files. Fallback: `crewai` import substring in `.py` files.
  - **LangGraph:** Detected via `langgraph` import substring in `.py` files, or `"langgraph"` key in `package.json` dependencies.
  - **LangChain:** Detected via `langchain` import substring in `.py` files, or `"@langchain/` scoped package key in `package.json`.
  - **Microsoft AutoGen:** Detected via `autogen` import substring in `.py` files.

  **TypeScript / JavaScript Frameworks:**
  - **Vercel AI SDK:** Detected via `from "ai"` or `from 'ai'` exact import strings in `.ts`/`.js` files, or `"ai"` key in `package.json` `dependencies`.
  - **LangChain.js:** Detected via `@langchain/` scoped import strings in `.ts`/`.js` files, or `"@langchain/` key in `package.json` dependencies.
  - **LlamaIndex.TS:** Detected via `llamaindex` or `@llamaindex/` import strings in `.ts`/`.js` files, or `"llamaindex"` / `"@llamaindex/` key in `package.json` dependencies.
  - **OpenAI Agents SDK (JS):** Detected via `@openai/agents` import string in `.ts`/`.js` files, or `"@openai/agents"` key in `package.json` dependencies.
  - **Mastra:** Detected via `@mastra/core` import string in `.ts`/`.js` files, or `"@mastra/core"` key in `package.json` dependencies.
  - **OpenAI SDK (Standard):** Detected via `from "openai"` or `from 'openai'` import strings in `.ts`/`.js` files, or `"openai"` key in `package.json` dependencies (both Python and JS/TS).

  Detection runs in priority order: **(1) CrewAI YAML manifests → (2) `package.json` dependency keys → (3) source file import strings**. The `package.json` pass is more reliable than import tracing for projects that use barrel re-exports or dynamic imports, so it is evaluated before the import-string scan.

### 4B. Abstract Syntax Tree (AST) Token-Streaming

- **Lexer Core:** Ingests raw scripting strings (`.py`, `.ts`, `.js`) using an optimized regular expression and token-streaming lexer engine to isolate functional declarations in memory.

- **Parsing Boundaries:** Indexes parameter types, validation schemas, system mutations, and timeout definitions. It explicitly logs vulnerabilities if high-risk application interfaces (such as shell commands or raw database handlers) take variable inputs directly from an LLM planner without structured schema templates.

- **TS/JS Schema Validation Boundary:** For TypeScript/JavaScript tool registrations, the engine looks for Zod schema attachments (`parameters: z.object(`, `parameters: z.`) as the canonical validation signal for Vercel AI SDK. `DynamicTool` and `DynamicStructuredTool` (LangChain.js) are differentiated — the latter requires a `schema:` property; the former triggers BZ-SEC-01 unconditionally since it accepts arbitrary string input by design. For standard OpenAI SDK, the engine validates that `tools` array entries include a `parameters` object with JSON Schema definition.

---

## 5. Cloud Handshake Gate & Pre-Paid Credit Enforcement

To govern usage rights on a pre-paid infrastructure model, Tuora executes a low-latency cryptographic authentication handshake on engine launch.

### 5A. Key Synthesis & Validation Architecture

- **Naming Semantics:** Keys enforce uniform validation patterns: `bz_dev_[a-zA-Z0-9]{32}`. This explicit layout allows secret-scanning watchdogs (like GitHub Secret Scanning) to auto-detect and protect exposed keys in repository commits.

- **One-Way Cryptographic Hashing:** The database engine never retains plain-text key records. Incoming keys pass through a secure hashing algorithm (SHA-256 or Argon2id employing a unique 32-byte salt) before matching against database indices.

### 5B. The Handshake Lifecycle Sequence

- **Out-of-Band Auth Verification:** Upon firing the validation routine via standard terminal binds, the binary pauses local workspace ingestion and initiates a sub-10ms HTTPS POST call to `https://api.runtuora.com/v1/auth`:

  ```json
  {
    "token_identity": "bz_dev_7a9f2b3c...",
    "client_epoch": 1779212056
  }
  ```

- **Server Entitlement Evaluation:** The central service receives the token metadata block and tests balance constraints across the pre-paid ledger parameters:
  - **The Hobbyist Free Pool:** If the account's cumulative successful operation metric evaluates under the baseline Sandbox limit (< 100 scans), the unit cost configuration falls to $0.00.
  - **Standard Scale Checking (Scans 1 to 999):** Confirms that the pre-paid credit wallet balance possesses sufficient liquidity to handle a $0.10 charge deduction event. Note: Financial replenishment endpoints require a minimum payment capture floor of $2.00 upfront to limit processing fee overhead.
  - **High-Volume Scale Checking (Scans 1,000+):** Triggers automatic volumetric adjustments on the 1,000th operation trace, confirming that available wallet assets cover a discounted cost calculation of $0.07 per scan unit.

- **Lockout Enforcement:** If available credits drop below the necessary cost floor, execution terminates instantly. Tuora halts further system entry, outputs a clean description block to stdout, and throws an Exit Code 1 execution failure error.

- **Validation Caching Window:** To ensure back-to-back testing runs within local AI code utilities do not create high-frequency network spikes, key verification receipts are cached inside volatile container memory for 300 seconds (5 minutes) before necessitating a fresh network sync.

---

## 6. Non-Blocking High-Velocity Metering Pipeline

To safeguard local development loops from compilation and logging network delays, performance telemetry is managed strictly through an out-of-band logging queue.

### 6A. Atomic Counters & Ring Buffers

- **Zero Contention Overhead:** Transaction variables increment straight to a pre-allocated Atomic Memory Ring Buffer using atomic primitives (`std::sync::atomic::AtomicU64`), bypassing thread-locking overhead completely.

- **Async Network Batching:** An asynchronous thread isolates tracked counter states, compressing log metadata arrays using high-speed protocols (`zstd` or `lz4`) and flushing them over an active TLS pipeline to the cloud ingestion gate every 60 seconds (or upon accumulating 1,000 events).

### 6B. Network Denial Protections

- **In-Memory Volatile Buffering:** If the central cloud ingestion network goes offline, metric states buffer safely inside local volatile memory caches. The container manages exponential back-off reconnection sweeps without bottlenecking or freezing the developer's local terminal interface.

- **Local Token Bucket Limiter:** Incorporates a thread rate-limiting system inside the container driver. If a broken deployment routine creates infinite compilation iterations, the client container throttles its own background metrics reporting thread, safeguarding the central analytical databases from excessive data surges.

---

## 7. Hybrid Polyglot Data Plane Storage Schema

To deliver absolute financial precision for pre-paid account states alongside flexible schema scaling for unpredictable, polymorphic AI framework graph files, Tuora replaces single-database models with a Hybrid Polyglot Storage Architecture.

```
                    [ Tuora Ingestion Cloud ]
                                  │
        ┌─────────────────────────┴─────────────────────────┐
        ▼                                                   ▼
+─────────────────────────────────+     +─────────────────────────────────+
│       PostgreSQL Engine         │     │      MongoDB Atlas Cluster      │
│   [ Pre-Paid Credit Wallet ]    │     │   [ Polymorphic Scan Logs ]     │
│   - MVCC Financial Isolation    │     │   - Flexible BSON Documents     │
│   - Append-Only Transactions    │     │   - Deep Graph Topologies       │
│   - Immutable Row Constraints   │     │   - Multi-Framework Mapping     │
+─────────────────────────────────+     +─────────────────────────────────+
```

### 7A. Financial Vault Layer: PostgreSQL (MVCC / Relational)

Pre-paid credits are tracked using an append-only transaction ledger. It utilizes PostgreSQL's strict type safety and Multi-Version Concurrency Control (MVCC) to ensure atomic balance checks and protect accounts from high-concurrency race condition double-spending exploits during concurrent pipeline runs.

```sql
CREATE SCHEMA IF NOT EXISTS tuora_vault;

CREATE TYPE tuora_vault.tx_primitive AS ENUM ('top_up', 'scan_deduction', 'hobby_grant');
CREATE TYPE tuora_vault.tier_primitive AS ENUM ('hobby', 'standard', 'volume_discount');

CREATE TABLE tuora_vault.wallet_ledger (
    transaction_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id     UUID NOT NULL,
    api_key_hash     CHAR(64) NOT NULL, -- Fixed-width SHA-256 text representation
    transaction_type tuora_vault.tx_primitive NOT NULL,
    -- Decimal prevents floating-point rounding discrepancies during balance changes
    amount_usd       NUMERIC(10, 4) NOT NULL,
    current_tier     tuora_vault.tier_primitive NOT NULL,
    historic_scans   BIGINT NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Compound index to deliver ultra-fast, sub-millisecond wallet state validation handshakes
CREATE INDEX idx_wallet_handshake
ON tuora_vault.wallet_ledger (workspace_id, api_key_hash, created_at DESC);
```

### 7B. Application Analytics Layer: MongoDB Atlas (Document Store)

The complex properties generated during evaluation (vulnerability lists, abstract syntax tree nodes, nested parameter metadata arrays, and dynamic multi-agent connections) are stored inside a schema-flexible document tier. This allows engineers to deploy support for new AI frameworks (like additions to LangGraph or CrewAI variants) instantly without performing database column migrations or causing system execution downtime.

**Collection Targets & Document Mappings:** `tuora.scan_logs`

```json
{
  "_id": "ObjectId(\"65f1a2b3c4d5e6f7a8b9c0d1\")",
  "scan_id": "8f3b2a10-c4d5-4e6f-8a9b-c0d1e2f3a4b5",
  "workspace_id": "3a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d",
  "framework": "crewai",
  "meta_stats": {
    "rules_evaluated": 42,
    "anomalies_detected": 3,
    "code_base_files": 14,
    "scan_duration_ms": 112
  },
  "detected_vulnerabilities": [
    {
      "rule_id": "BZ-SEC-01",
      "severity": "HIGH",
      "tool_target": "execute_database_query",
      "message": "Tool accepts raw arguments without strict JSON parameter patterns.",
      "remediation": "Wrap fields in an explicit Pydantic schema class structure to isolate injection anomalies.",
      "plain_message": "Your AI tool has no rules about what data it will accept. This means anyone — or any malicious prompt — can send it unexpected, harmful inputs with no checks in place.",
      "plain_remediation": "Define exactly what your tool expects by wrapping its inputs in a Pydantic schema (Python) or a Zod schema (TypeScript). Think of it like a bouncer for your tool's front door."
    },
    {
      "rule_id": "BZ-FIN-01",
      "severity": "MEDIUM",
      "tool_target": "agent_planning_graph",
      "message": "Uncapped Agent Execution Lifecycle - rogue loops can spin infinite token bills.",
      "remediation": "Explicitly pass a rigid runtime constraint ceiling parameter inside the execution configuration.",
      "plain_message": "Your AI agent has no maximum step limit. If it gets confused, goes in circles, or is manipulated by a bad prompt, it will keep running forever — and every step costs you money in API calls.",
      "plain_remediation": "Set a maximum number of steps when you run your agent, e.g. `recursion_limit=10` or `max_loops=5`. This acts like a circuit breaker that stops runaway charges."
    }
  ],
  "ingested_framework_manifest": {
    "agents": [
      {
        "role": "Financial Analyst Bot",
        "goal": "Process outbound mutations over customer portfolios",
        "allow_delegation": true,
        "verbose_logging": false
      }
    ]
  },
  "timestamp": "ISODate(\"2026-05-20T22:21:56.000Z\")"
}
```

**Index Configuration:**

```js
db.scan_logs.createIndex({ "workspace_id": 1, "timestamp": -1 })
```

---

## 8. WebAssembly Rule Engine Architecture

To enforce the open-core licensing model while maintaining client-side execution privacy, Tuora implements a hybrid rule evaluation system. The open-source CLI core handles file ingestion and orchestration, while proprietary threat detection logic is delivered as a signed, sandboxed WebAssembly module fetched post-authentication.

### 8A. WASM Bundle Distribution Flow

```
[CLI Launch] ──► [Auth Handshake] ──► [GET /v1/bundle-version]
                                            │
                            ┌─────────────┴────────────────┐
                            ▼ (cache hit)               ▼ (cache miss)
              [Load ~/.cache/tuora/def-*.wasm]   [POST /v1/rules-bundle]
              [Decrypt + Verify Signature]        [Verify + Cache + Load]
                            │                               │
                            └─────────▼─────────┘
                                     │
                            ┌───────┴───────┐
                            │   wasmtime    │
                            │  (sandboxed)  │
                            └───────┬───────┘
                                     │
                            [Violation Results]
```

**Execution Sequence:**
1. **Authentication Gate:** Rules are only fetched after successful wallet validation (`/v1/auth` returns `200 OK` with valid balance)
2. **Version Check:** `GET /v1/bundle-version` (Bearer API key) returns current SemVer and tier — cheap, no binary transferred
3. **Cache Hit:** If `~/.cache/tuora/def-{version}.wasm` exists, it is decrypted (AES-256-GCM, key derived from API key) and the embedded Ed25519 signature is re-verified before loading
4. **Cache Miss:** Full bundle downloaded from `POST /v1/rules-bundle`, signature verified, AES-encrypted and written to disk, then loaded
5. **Platform-Agnostic Delivery:** Single WASM32 target serves all platforms (Linux x86_64, macOS ARM/x86, Windows)
6. **Sandboxed Execution:** wasmtime runtime with no WASI imports, fuel metering, and memory limits

### 8B. WASM Module Interface Contract

The rule bundle exports a strict C-compatible ABI for interoperability:

```rust
// WASM Module Exports (compiled from private tuora-signatures repo)
#[no_mangle]
pub extern "C" fn evaluate_file(input_ptr: *const u8, input_len: u32) -> *mut u8;

#[no_mangle]
pub extern "C" fn malloc(size: u32) -> u32;

#[no_mangle]
pub extern "C" fn free(ptr: u32, size: u32);

#[no_mangle]
pub extern "C" fn rule_count() -> u32;
```

**Data Serialization:** Bincode is used for zero-copy (de)serialization across the WASM boundary due to its speed and deterministic output.

### 8C. Development Mode: Local File Loading

To enable rapid iteration without network dependencies or authentication during development, the CLI implements a dev-mode file loading path activated via `#[cfg(debug_assertions)]`:

```
core/
└── dev/
    └── rules.wasm              # Auto-built from rule-engine (gitignored)

cloud/
└── rules/
    └── rule-engine/            # Single source of truth for all rules
        ├── Cargo.toml          # wasm32-unknown-unknown target
        └── src/lib.rs          # 15 rule implementations
```

**Dev-Mode Behavior:**
- **Build-Time Compilation:** `core/build.rs` automatically compiles `rule-engine` to WASM during `cargo build` (debug profile only) and places the stripped output at `core/dev/rules.wasm`
- **Automatic Detection:** On debug builds, the engine loads from `core/dev/rules.wasm` before attempting network fetch
- **Incremental:** Rebuild triggers only when `cloud/rules/rule-engine/src` or its `Cargo.toml` changes
- **Signature Bypass:** Signature verification is skipped in dev mode; the WASM loads directly into wasmtime
- **Single Crate:** Both dev and production use the same `cloud/rules/rule-engine/` crate — no separate mock implementation

**Environment Toggle:**
```bash
# Default dev behavior — load from filesystem
cargo run -- watch ./project

# Test actual network path locally
TUORA_LEDGER_URL=http://localhost:3000/v1 cargo run -- watch ./project
```

### 8D. Security Controls

| Layer | Implementation |
|-------|---------------|
| **Transport** | TLS 1.3 to `api.runtuora.com` |
| **Authentication** | API key as Bearer token on all endpoints; validated directly against the wallet ledger |
| **Code Integrity** | Ed25519 signature verification using public key embedded at compile time (`TUORA_SIGNING_PUBKEY_VALUE`); failed verification aborts loading |
| **Execution Sandbox** | wasmtime with `config.wasi(false)`, fuel metering (prevents infinite loops), 64MB memory cap |
| **No I/O** | WASM module has zero filesystem or network access; pure computation only |
| **Temporal Validity** | Bundles include `expires_at` timestamp; expired bundles trigger re-download |
| **Local Cache** | Bundles cached to `~/.cache/tuora/def-{version}.wasm` as `[sig (64B)][wasm]`, AES-256-GCM encrypted with key derived from API key; signature re-verified on every cache load |

### 8E. Bundle Naming & Versioning

Bundles are version-resolved server-side. The filename is `rule-engine.wasm` (same file for all tiers).

```
[API Request: /v1/rules-bundle]
         │
         └──► rule-engine.wasm   (all tiers)
```

**Bundle Versioning:** The current version string is served by `GET /v1/bundle-version` and embedded in the download response. The CLI caches by version — a version change on the server triggers a fresh download.

---

## 9. Cloud Backend Architecture (`cloud/`)

The Tuora SaaS backend is structured as a TypeScript monorepo under `cloud/`, with the exception of the proprietary WASM rule engine which remains Rust.

### 9A. Service Map

```
cloud/
├── api/                # Primary API gateway — Fastify (TypeScript)
├── shared/             # Zod schemas shared across all TS services
├── dashboard/          # SvelteKit web dashboard (account management)
└── payments/
    └── stripe-webhooks/  # Stripe event handler — Fastify (TypeScript)

### 9A1. WASM Rule Engine (`cloud/rules/rule-engine/`)

The proprietary WASM rule engine is a workspace member used for both dev and production:

```
cloud/
└── rules/
    └── rule-engine/     # WASM rule bundle — Rust (wasm32-unknown-unknown)
        ├── Cargo.toml
        └── src/lib.rs   # 15 rule implementations
```

### 9B. `api` — Primary API Gateway

**Runtime:** Node.js 22 LTS, TypeScript 5, Fastify 5

**Access point:** `https://api.runtuora.com`

This service consolidates all three endpoints the CLI communicates with, plus internal auth and telemetry ingestion logic. It replaces the previously planned separate `ledger-api`, `auth-service`, and `telemetry-sink` Rust services.

**Endpoints:**

| Method | Path | Responsibility |
|--------|------|----------------|
| `POST` | `/v1/auth` | Argon2id key lookup, wallet balance check, returns `AuthResponse` |
| `GET` | `/v1/bundle-version` | Lightweight version check; returns `{ version, tier }` without transferring bundle bytes |
| `POST` | `/v1/rules-bundle` | WASM bundle delivery (`rule-engine.wasm`) with Ed25519 signature |
| `POST` | `/telemetry/batch` | MongoDB scan log ingestion + PostgreSQL credit deduction |

**Dependencies:**
- `fastify` — HTTP framework with built-in JSON schema validation
- `postgres` (porsager) — PostgreSQL client for wallet ledger operations
- `mongodb` — MongoDB Atlas driver for scan log ingestion
- `argon2` — API key hashing (Argon2id with 32-byte salt)
- `zod` — Runtime validation using shared schemas from `cloud/shared/`
- `@fastify/bearer-auth` — Bearer token middleware

**Database responsibilities:**
- PostgreSQL: `tuora_vault.wallet_ledger` — balance reads, deduction writes (ACID)
- MongoDB Atlas: `tuora.scan_logs` — telemetry document inserts

### 9C. `cloud/shared/` — Shared Zod Schemas

Contains Zod schema definitions that mirror `types/src/lib.rs`. All TypeScript cloud services import from here. TypeScript types are inferred directly from Zod schemas (`z.infer<typeof Schema>`), ensuring a single source of truth for the wire protocol contract on the TS side.

**Files:**
- `schemas.ts` — `AuthRequestSchema`, `AuthResponseSchema`, `BundleVersionResponseSchema`, `RulesBundleRequestSchema`, `RulesBundleResponseSchema`, `TelemetryEventSchema`, `EvalInputSchema`, `EvalOutputSchema`

When Rust types in `types/src/lib.rs` change, `cloud/shared/schemas.ts` must be updated in the same commit.

### 9D. `stripe-webhooks` — Payment Handler

**Status:** ✅ Implemented

**Runtime:** Node.js 22 LTS, TypeScript 5, Fastify 5

**Port:** 3001 (separate from `api`)

Kept as a separate service from `api` because:
1. Stripe webhook verification requires raw (unparsed) request body before JSON deserialization
2. Payment events are async and fire independently of the scan auth lifecycle
3. Separate deployment isolates Stripe failures from scan availability

**Responsibilities:** 
- Receives Stripe `payment_intent.succeeded` and `checkout.session.completed` events
- Verifies webhook signature using `STRIPE_WEBHOOK_SECRET`
- Credits the PostgreSQL wallet ledger via direct `INSERT` into `tuora_vault.wallet_ledger`
- Enforces $2.00 minimum top-up floor
- Maps payments to workspace via `metadata.workspace_id` and `metadata.api_key_hash`

### 9E. `rule-engine` — Proprietary WASM Bundle (Rust)

**Status:** ✅ **Fully Implemented**

The WASM rule engine at `cloud/rules/rule-engine/` is complete with all 15 compliance rules implemented. It compiles to `wasm32-unknown-unknown` and is loaded by the CLI via wasmtime. The native Rust rules in `core/src/rules/patterns.rs` are now stubbed (deprecated) — the WASM bundle is the primary rule backend.

**Build target:** `cargo build --target wasm32-unknown-unknown --release -p rule-engine`

**Interface Functions:**
- `evaluate_file(input_ptr, input_len)` — Evaluates all rules against ingested files
- `malloc(size)` — Bump allocator starting at offset 65536
- `free(ptr, size)` — Simplified no-op for WASM
- `rule_count()` — Returns 15 (all rules implemented)

**Data Serialization:** Bincode for zero-copy (de)serialization with 4-byte length prefix.

**Signing:** Ed25519 private key held in CI/CD secrets vault. Signed bundles uploaded to artifact storage. Public key embedded in `core/assets/signing_key.pub`.

**Dev Mode:** On debug builds, the CLI loads from `core/dev/rules.wasm` with signature verification skipped. Production builds fetch from `/v1/rules-bundle` with full signature verification.
