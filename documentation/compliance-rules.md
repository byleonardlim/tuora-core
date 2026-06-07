# Tuora Core Engine: Parsing Checklist & Rule Registry

## 1. Security & Input Validation Tier

### Rule ID: BZ-SEC-01 (Missing Tool Input Schemas)

**OWASP Reference:** ASI02 (Tool Misuse)

**Target Vector:** Python code files (`.py`), TypeScript/JavaScript tool definitions (`.ts`, `.js`), framework manifests (`tasks.yaml`, graph definitions).

**Rust Parsing Logic (What the engine scans for):**

The engine detects unvalidated tool registrations across both Python and TypeScript/JavaScript ecosystems:

**Python patterns:**
- `@tool` decorator or class definitions inheriting from `BaseTool` or `Tool.from_function()` that lack `args_schema`, `pydantic_model`, or a Pydantic `BaseModel` subclass within 20 lines.

**TypeScript / JavaScript patterns:**
- **Vercel AI SDK:** `tool({` call blocks that lack a `parameters: z.object(` or `parameters: z.` Zod schema definition within the same block (within 15 lines).
- **LangChain.js:** `new DynamicTool({` or `new DynamicStructuredTool({` instantiations that lack a `schema:` property.
- **OpenAI Agents SDK (JS):** `tool(` calls that lack a `parameters:` key in the config object.
- **OpenAI SDK (Standard):** `tools:` array in chat completions that lack a `parameters` object with JSON schema definition.
- **Mastra:** `createTool({` calls that lack an `inputSchema:` property.

- **Trigger Condition:** If any tool registration path is identified but lacks an explicit validation schema or typed parameter definition object, raise an anomaly indicator flag.

**Actionable User Advice (Terminal Log Output):**

```
🛑 BZ-SEC-01 [HIGH] [tool_name]
  │  Your AI tool has no rules about what data it will accept. This means anyone — or any
  │  malicious prompt — can send it unexpected, harmful inputs with no checks in place.
  │
  │  Affected locations:
  │    • src/tools.py:15
  │    • src/tools.py:42
  │    • src/helpers.py:8
  │
  │  💡 Fix: Define exactly what your tool expects by wrapping its inputs in a Pydantic
  │          schema (Python) or a Zod schema (TypeScript). Think of it like a bouncer for
  │          your tool's front door.
```

---

### Rule ID: BZ-SEC-02 (Insecure Unsanitized String Injections)

**OWASP Reference:** ASI05 (Unexpected Code Execution) / A03:2021 Injection

**Target Vector:** All function bodies across `.py`, `.ts`, `.js` files — not limited to tool-decorated functions. Applies in both agentic and non-agentic codebases.

**Rust Parsing Logic (What the engine scans for):**
- Scan all function bodies for system mutation methods or execution block statements: `os.system()`, `subprocess.run()`, `subprocess.call()`, `subprocess.Popen()`, `eval()`, `exec()`, or raw database execution statements (`.execute()`).
- **Trigger Condition A (String Injection):** Trigger a CRITICAL error if string formatting or concatenation (e.g., Python f-strings like `f"rm -rf {user_input}"` or JS template literals like `` `cmd ${arg}` ``) inserts any variable directly into the statement without using parametrized execution arrays or query drivers.
- **Trigger Condition B (Shell Escalation):** Trigger a standalone CRITICAL error if `shell=True` is present in any `subprocess.*` call, regardless of whether string formatting is detected. This pattern unconditionally enables shell injection and has no safe usage with variable inputs.

**Actionable User Advice (Terminal Log Output):**

```
🛑 BZ-SEC-02 [CRITICAL] [function_name]
  │  Your code is pasting user input directly into a system command or database query. An
  │  attacker could type something malicious and your app would run it — like deleting your
  │  entire database or taking over the server.
  │
  │  Affected locations:
  │    • src/api.py:23
  │    • src/utils.py:45
  │
  │  💡 Fix: Never build commands or queries by gluing strings together. Pass values
  │          separately: instead of `f"rm {user_input}"`, use `subprocess.run(["rm", user_input])`.

🛑 BZ-SEC-02B [CRITICAL] [function_name]
  │  You're running a system command with `shell=True`, which hands full control of the
  │  terminal to whatever string gets passed in. If any part of that string comes from user
  │  input or an AI response, an attacker can run any command they want on your machine.
  │
  │  Affected locations:
  │    • src/legacy.py:12
  │
  │  💡 Fix: Remove `shell=True` and switch to a list format: change
  │          `subprocess.run("cmd arg", shell=True)` to `subprocess.run(["cmd", "arg"])`. It's
  │          a one-line fix.
```

---

## 2. Financial Guardrails & Token Optimization Tier

### Rule ID: BZ-FIN-01 (Missing Recursion Bounds / Loop Caps)

**OWASP Reference:** ASI08 (Cascading Failures & Denial-of-Wallet)

**Target Vector:** State graphs initialization files (.py, .ts), orchestration scripts, pipeline manifests.

**Rust Parsing Logic (What the engine scans for):**
- Locate orchestration graph invocation or deployment initialization call chains (e.g., tracking string sequences like `.invoke()`, `.stream()`, `.run()`, or framework builder states like `StateGraph().compile()`).
- Verify the existence of loop-termination keyword fields such as `recursion_limit`, `max_loops`, or `max_iter`.
- **Trigger Condition:** If the parameters are omitted, completely missing from the target dictionary object mapping, or set to an infinite value, fire the risk indicator.

**Actionable User Advice (Terminal Log Output):**

```
⚠️ BZ-FIN-01 [MEDIUM] [workflow_name]
  │  Your AI agent has no maximum step limit. If it gets confused, goes in circles, or is
  │  manipulated by a bad prompt, it will keep running forever — and every step costs you money
  │  in API calls.
  │
  │  Affected locations:
  │    • src/graph.py:34
  │    • src/agents.py:56
  │
  │  💡 Fix: Set a maximum number of steps when you run your agent, e.g. `recursion_limit=10`
  │          or `max_loops=5`. This acts like a circuit breaker that stops runaway charges.
```

---

### Rule ID: BZ-FIN-02 (Unmanaged Chat History Token Inflation)

**OWASP Reference:** Token Bleed & Asymmetric Wallet Exhaustion

**Target Vector:** Long-term conversational threads, loop message arrays, context states.

**Rust Parsing Logic (What the engine scans for):**
- Scan for arrays accumulating model text objects (e.g., patterns matching `.append()` sequences modifying structures containing strings like `messages`, `chat_history`, or `memory_store`).
- Cross-map the surrounding context to verify if the file runs a trim, slice, or filter loop (e.g., `messages[-10:]`, or memory management utility calls like `ConversationSummaryMemory()`).
- **Trigger Condition:** Trigger if conversational variables continuously grow without an explicit history truncation layout or summarization function attached to the iteration.

**Actionable User Advice (Terminal Log Output):**

```
⚠️ BZ-FIN-02 [LOW] [history_variable_name]
  │  Every message in your chat history gets resent to the AI on every turn. The longer the
  │  conversation grows, the more you pay — and it compounds fast. A 100-message chat can cost
  │  10x more per reply than a 10-message one.
  │
  │  Affected locations:
  │    • src/chat.py:78
  │
  │  💡 Fix: Keep only the last N messages, e.g. `messages = messages[-10:]`, or use a
  │          summarization memory so old history is compressed instead of resent in full.
```

---

### Rule ID: BZ-FIN-03 (High Temperature on Non-Deterministic Extraction Agents)

**OWASP Reference:** Structural Extraction Failure

**Target Vector:** Model constructor calls (`ChatOpenAI(..)`), configuration setup fields.

**Rust Parsing Logic (What the engine scans for):**
- Parse the properties passed during LLM initialization blocks. Extract the assigned values for the `temperature` attribute variable.
- Evaluate the associated agent context description, system prompts, or tool labels to check if they match structured tasks (e.g., look for keywords like "json", "extract", "parse", "schema", "mapping").
- **Trigger Condition:** Trigger a warning flag if an agent intended for structured data or system schema parsing sets its runtime temperature > 0.2 or leaves it un-configured (defaulting to high fluid metrics).

**Actionable User Advice (Terminal Log Output):**

```
⚠️ BZ-FIN-03 [LOW] [agent_name]
  │  Your AI agent is set to be "creative" (high temperature) but it's doing a precise job like
  │  extracting structured data or parsing JSON. A creative AI gives inconsistent, unpredictable
  │  outputs — your app will break in random ways.
  │
  │  Affected locations:
  │    • src/agents.py:23
  │
  │  💡 Fix: Set `temperature=0.0` or `temperature=0.1` for any agent that needs to extract
  │          data, fill structured fields, or return consistent formats. Save high temperature
  │          for creative writing tasks only.
```

---

## 3. Architectural Safety & Privileges Tier

### 3A. Agentic Runtime Rules (Active when agentic framework is detected)

### Rule ID: BZ-OPS-01 (Destructive Actions Without Human Approval)

**OWASP Reference:** ASI03 (Privilege Abuse) / ASI09 (Over-Reliance / Trust Exploitation)

**Target Vector:** Exposed tool function names, system tool declaration vectors.

**Rust Parsing Logic (What the engine scans for):**
- Compare tool function string handles against an internal vector array of high-risk mutation naming profiles: `*payout*`, `*transfer*`, `*delete_*`, `*drop_*`, `*publish_*`, `*overwrite_*`.
- Scan the functional logic tree block to see if it routes through verification wrappers, manual approval methods, or confirmation channel webhooks.
- **Trigger Condition:** If a critical high-risk capability executes changes autonomously without an explicit boolean user-gate validation or check bridge parameter, log a safety exception.

**Actionable User Advice (Terminal Log Output):**

```
🛑 BZ-OPS-01 [HIGH] [function_name]
  │  Your AI agent can delete data, transfer money, or publish content completely on its own —
  │  no confirmation step required. A bad prompt or a hacked message could trick it into doing
  │  something irreversible before you even know about it.
  │
  │  Affected locations:
  │    • src/tools/payment.py:45
  │    • src/tools/content.py:12
  │
  │  💡 Fix: Add a human approval step before any dangerous action runs: pause and ask "Are
  │          you sure?" before the agent calls anything that deletes, transfers, or overwrites
  │          data. Never let the AI do these things without a human confirming first.
```

---

### Rule ID: BZ-OPS-02 (Missing Outbound Client Network Timeouts)

**OWASP Reference:** Core Platform Denial of Service

**Target Vector:** Network client declarations wrapped inside tool execution algorithms.

**Rust Parsing Logic (What the engine scans for):**
- Identify standard HTTP/RPC request libraries inside tool processing modules: `requests.get()`, `httpx.AsyncClient()`, `fetch()`, `axios()`.
- **Trigger Condition:** Check the calling arguments dictionary. If the connection routine lacks a bounded `timeout=...` definition expression parameter, fire the indicator.

**Actionable User Advice (Terminal Log Output):**

```
⚠️ BZ-OPS-02 [MEDIUM] [http_client_name]
  │  Your code makes requests to external websites or APIs but never sets a time limit. If
  │  that service is slow or goes down, your entire app freezes waiting forever — hanging every
  │  request behind it.
  │
  │  Affected locations:
  │    • src/api/client.py:34
  │    • src/services/external.py:56
  │
  │  💡 Fix: Always set a timeout when calling external services, e.g. `requests.get(url,
  │          timeout=10)` or `httpx.AsyncClient(timeout=10.0)`. Ten seconds is a sensible default.
```

---

### 3B. Traditional SAST Rules (Active when no agentic framework is detected)

The following four rules activate as the primary rule set when the engine determines the scanned workspace contains no agentic framework imports (CrewAI, LangGraph, LangChain, AutoGen, Vercel AI SDK, LlamaIndex.TS, OpenAI Agents SDK JS, Mastra, OpenAI SDK). They also run in parallel alongside the agentic rules when a framework is detected, since vibe-coded AI apps still ship traditional web backends.

---

### Rule ID: BZ-SAST-01 (Insecure Framework Configuration)

**OWASP Reference:** A05:2021 Security Misconfiguration

**Target Vector:** `settings.py`, `app.py`, `server.js`, `main.py`, `index.ts`, `index.js`, `.env*` files.

**Rust Parsing Logic (What the engine scans for):**
- Scan for `DEBUG = True`, `DEBUG=True`, `FLASK_DEBUG=1`, or `NODE_ENV=development` in any file that is not inside a directory path containing `test`, `dev`, or `local` in its name.
- Scan for `host="0.0.0.0"` or `host='0.0.0.0'` bindings. Cross-check the workspace root for the presence of a reverse-proxy configuration file (`nginx.conf`, `Caddyfile`, `traefik.yml`). If none are found, the binding is flagged as exposed.
- **Trigger Condition:** Fire the indicator on any of the above patterns in a file that does not contain explicit documentation comments marking it as a local development configuration.

**Actionable User Advice (Terminal Log Output):**

```
🛑 BZ-SAST-01 [HIGH] [config_variable]
  │  Your app is running in debug mode, which is designed for development only. In debug mode,
  │  when something breaks, your app shows the full error details — including file paths,
  │  environment variables, and internal code — to anyone who triggers that error on the internet.
  │
  │  Affected locations:
  │    • src/config.py:12
  │    • .env:3
  │
  │  💡 Fix: Before going live, set `DEBUG=False` (Python/Django/Flask) or `NODE_ENV=production`
  │          (Node.js). This hides internal details from the public while you keep full logs
  │          privately on your server.
```

---

### Rule ID: BZ-SAST-02 (Missing or Wildcard CORS Policy)

**OWASP Reference:** A01:2021 Broken Access Control

**Target Vector:** Express, FastAPI, Flask, and Django route setup files (`.py`, `.ts`, `.js`).

**Rust Parsing Logic (What the engine scans for):**
- Scan for `Access-Control-Allow-Origin: *` in string literals.
- Scan for framework-specific CORS wildcard patterns:
  - Python: `origins=["*"]`, `allow_origins=["*"]` in `CORSMiddleware` or `flask_cors` calls.
  - JavaScript/TypeScript: `cors({ origin: "*" })`, `cors({ origin: true })`, `origin: /.*/ `.
- **Trigger Condition:** Fire if a wildcard origin is found without an explicit `allow_credentials: false` annotation on the same call. Credentialed wildcard CORS is a CRITICAL severity; non-credentialed wildcard is MEDIUM.

**Actionable User Advice (Terminal Log Output):**

```
⚠️ BZ-SAST-02 [MEDIUM] [cors_config]
  │  Your API is set to accept requests from literally any website on the internet (`*` means
  │  "everyone"). This means a malicious site could silently read your API responses when a
  │  logged-in user visits it.
  │
  │  Affected locations:
  │    • src/main.py:45
  │
  │  💡 Fix: Replace the wildcard with your actual domain: e.g. `allow_origins=["https://
  │          yourdomain.com"]`. Only list the exact websites that should be allowed to talk to
  │          your API.

🛑 BZ-SAST-02B [CRITICAL] [cors_config]
  │  Your API is set to accept requests from any website AND allows cookies to be sent along.
  │  This combination lets a malicious site silently act as a logged-in user — a full session
  │  hijack vector.
  │
  │  Affected locations:
  │    • src/api.py:67
  │
  │  💡 Fix: Wildcard origin is forbidden when `allow_credentials=True`. You must specify
  │          exact, trusted origins instead of `*`.
```

---

### Rule ID: BZ-SAST-03 (SQL Injection via Raw Query Concatenation)

**OWASP Reference:** A03:2021 Injection

**Target Vector:** All `.py`, `.ts`, `.js` files containing database interaction patterns.

**Rust Parsing Logic (What the engine scans for):**
- Identify raw query execution calls: `cursor.execute()`, `db.query()`, `connection.execute()`, `knex.raw()`, `sequelize.query()`, `engine.execute()`, `session.execute()`.
- This rule is distinct from BZ-SEC-02 which targets shell/eval execution. BZ-SAST-03 is SQL-specific.
- **Trigger Condition:** Fire a CRITICAL error if the argument to the query call is a string formed via concatenation (`+`), f-string interpolation (`f"SELECT ... {var}"`), or JS template literal (`` `SELECT ... ${var}` ``). Do NOT fire if the argument uses only parameterized placeholders (`?`, `$1`, `%s`, `:name`) with a separate params tuple or array.

**Actionable User Advice (Terminal Log Output):**

```
🛑 BZ-SAST-03 [CRITICAL] [query_function]
  │  You're building a database query by gluing user input directly into the SQL string. This
  │  is one of the oldest and most dangerous bugs in web development — a user can type SQL code
  │  into a form field and your database will run it, potentially dumping or wiping all your data.
  │
  │  Affected locations:
  │    • src/db/queries.py:23
  │    • src/models/user.py:45
  │
  │  💡 Fix: Pass user values separately from the query template. Instead of `f"SELECT * FROM
  │          users WHERE id = {user_id}"`, use `cursor.execute("SELECT * FROM users WHERE id
  │          = %s", (user_id,))`. The database handles the separation safely.
```

---

### Rule ID: BZ-SAST-04 (Unpinned Dependency Versions)

**OWASP Reference:** A06:2021 Vulnerable and Outdated Components

**Target Vector:** `package.json` (production `dependencies` block only, not `devDependencies`), `requirements.txt`, `pyproject.toml`.

**Rust Parsing Logic (What the engine scans for):**
- **`package.json`:** Parse the `dependencies` key. Flag any entry whose version string is `"*"`, `"latest"`, or uses a bare caret range resolving to a full major version (e.g., `"^1"` with no minor/patch pin). Do not flag `devDependencies`.
- **`requirements.txt`:** Flag any package line that does not contain `==`. Lines using `>=`, `~=`, or no version specifier at all are flagged.
- **`pyproject.toml`:** Under `[tool.poetry.dependencies]` or `[project.dependencies]`, flag entries using `>=` without a corresponding `<` upper bound, or entries set to `"*"`.
- **Trigger Condition:** Any production dependency that resolves to a non-deterministic version range.

**Actionable User Advice (Terminal Log Output):**

```
⚠️ BZ-SAST-04 [LOW] [package_name]
  │  One of your packages doesn't have a fixed version number, so every fresh install can pull
  │  in a different (potentially newer, potentially broken or hacked) version. Package hijacking
  │  attacks specifically target this — a malicious update can silently end up in your app.
  │
  │  Affected locations:
  │    • package.json:12 (current: "^4.0.0")
  │    • requirements.txt:5 (current: >=2.0.0)
  │
  │  💡 Fix: Lock to an exact version in your dependency file, e.g. `"express": "4.18.2"` instead
  │          of `"^4"`, and commit your lockfile (`package-lock.json` or `poetry.lock`) so every
  │          install is identical.
```

---

## 4. Secret Hygiene & Isolation Tier

### Rule ID: BZ-HYG-01 (Hardcoded Secret Tokens)

**OWASP Reference:** Compromised Variable Management / A02:2021 Cryptographic Failures

**Target Vector:** Universal codebase scan across all mounted directory files, explicitly including `.env`, `.env.local`, `.env.production`, `.env.staging`, `.env.development` in addition to `.py`, `.ts`, `.js`, `.yaml`, `.yml`, `.json`. `.env*` files must be ingested even though they are commonly `.gitignore`d locally, as they are a primary vector for accidental secret commits in vibe-coded projects.

**Rust Parsing Logic (What the engine scans for):**
- Evaluate all literal text string assignments inside scanned file segments against a strict collection of high-precision cryptographic regular expressions.
- **Regex Targets:**
  - `sk-[a-zA-Z0-9]{48}` — OpenAI API Key
  - `sk-proj-[a-zA-Z0-9]{48}` — OpenAI Project Key
  - `sk-ant-[a-zA-Z0-9\-]{80,}` — Anthropic API Key
  - `sk_live_[a-zA-Z0-9]{24,}` — Stripe Live Secret Key
  - `sk_test_[a-zA-Z0-9]{24,}` — Stripe Test Secret Key
  - `ghp_[a-zA-Z0-9]{36}` — GitHub Personal Access Token
  - `gho_[a-zA-Z0-9]{36}` — GitHub OAuth Token
  - `AKIA[0-9A-Z]{16}` — AWS Access Key ID
  - `api[_-]?key['"\s]*[:=]['"\s]*[a-zA-Z0-9]{32,}` — Generic API Key Pattern
  - `secret[_-]?key['"\s]*[:=]['"\s]*[a-zA-Z0-9]{32,}` — Generic Secret Key Pattern
  - `DATABASE_URL['"\s]*[:=]['"\s]*[a-zA-Z0-9+:\/@.\-]+` — Database connection string with embedded credentials
  - `POSTGRES_PASSWORD['"\s]*[:=]['"\s]*\S+` — Postgres password assignment

**Actionable User Advice (Terminal Log Output):**

```
🛑 BZ-HYG-01 [CRITICAL] [secret_type]
  │  A real API key, password, or secret token is written directly in your code file. If this
  │  code ever touches GitHub — even briefly, even in a private repo — bots scan for it within
  │  seconds and will start using your credentials to rack up charges or steal data.
  │
  │  Affected locations:
  │    • src/config.py:8 (OpenAI API key pattern)
  │    • .env.local:3 (AWS Access Key)
  │
  │  💡 Fix: Revoke this key immediately at the provider's dashboard, then move it to a `.env`
  │          file and load it with `os.environ["MY_KEY"]` or `process.env.MY_KEY`. Never put real
  │          secrets in code files.
```

---

### Rule ID: BZ-HYG-02 (System Prompt Environment Bleeding)

**OWASP Reference:** ASI01 (Agent Goal Hijack) / Context Leakage

**Target Vector:** Prompt construction strings, template rendering files.

**Rust Parsing Logic (What the engine scans for):**
- Trace the data components feeding system prompt strings or prompt-template objects.
- **Trigger Condition:** Flag cases where internal system data objects or configuration dictionaries (e.g., formatting variables loading properties like `process.env` or server configuration contexts) are interpolated directly into the system message template block.

**Actionable User Advice (Terminal Log Output):**

```
⚠️ BZ-HYG-02 [MEDIUM] [variable_name]
  │  Your server's private configuration values (like database URLs or internal settings) are
  │  being mixed into the text you send to the AI. A clever user could craft a message that
  │  tricks the AI into repeating those secrets back to them.
  │
  │  Affected locations:
  │    • src/prompts/system.py:12
  │
  │  💡 Fix: Keep your AI prompt text completely separate from your app's configuration. Build
  │          prompt strings using only the specific variables you intend the AI to see — never
  │          inject a whole config object or environment into a prompt.
```

---

### Rule ID: BZ-HYG-03 (AI SDK Credentials Not Sourced from Environment Variables)

**OWASP Reference:** ASI04 (Agentic Supply Chain Vulnerabilities) / A02:2021 Cryptographic Failures

**Target Vector:** All `.py`, `.ts`, `.js` files that instantiate an AI SDK client (`OpenAI()`, `Anthropic()`, `AzureOpenAI()`, `new OpenAI()`, `new Anthropic()`, etc.).

**Rust Parsing Logic (What the engine scans for):**
- Locate AI SDK client constructor calls across both Python and TypeScript/JavaScript ecosystems.
- Check whether an explicit `api_key` (Python) or `apiKey` (JS/TS) argument is supplied within the 10-line constructor block.
- If an explicit key argument **is present**, verify the value originates from an environment variable by checking the same block for any of: `os.environ`, `os.getenv`, `process.env`, `dotenv`, `getenv(`, `from_env`, `environ[`, `environ.get(`.
- **Trigger Condition:** Fire if an explicit key argument is found AND none of the above env-var sourcing patterns are present. If no explicit key argument is found at all, skip — the SDK is using its own implicit env-var lookup (the recommended pattern).

**Actionable User Advice (Terminal Log Output):**

```
🛑 BZ-HYG-03 [HIGH] [OpenAI]
  │  Your AI client is being given an API key that doesn't appear to come from an
  │  environment variable. This means the key might be hardcoded in source code, passed
  │  from a config file, or read from another insecure location — any of which puts it
  │  at risk of exposure.
  │
  │  Affected locations:
  │    • src/agent.py:12
  │    • src/client.ts:8
  │
  │  💡 Fix: The safest pattern is to not pass api_key at all: set the OPENAI_API_KEY (or
  │          equivalent) environment variable and let the SDK pick it up automatically. If
  │          you must pass it explicitly, always use os.environ["OPENAI_API_KEY"] (Python)
  │          or process.env.OPENAI_API_KEY (Node.js) — never a raw string or config object
  │          property.
```

---

## 5. Summary Scoring Formula (How Tuora calculates the Health Check Score)

When your Rust binary finishes evaluating the checklist, it maps the anomalies found into a single, unified mathematical health index score layout:

$$
\text{Health Score} = 100 - \sum (\text{Anomalies Triggered} \times \text{Severity Weight})
$$

Where your engine assigns these static severity deduction variables:

- **CRITICAL** Deducts: 25 points
- **HIGH** Deducts: 15 points
- **MEDIUM** Deducts: 8 points
- **LOW** Deducts: 3 points

(Floor constraint: The minimum display score cannot fall below 0)

---

## 6. OWASP Agentic Top 10 (2026) Framework

The OWASP Agentic Top 10 for 2026 is the definitive framework for securing autonomous AI systems, released in December 2025. It identifies the highest-impact risks posed by agents that can plan, decide, and act across tools and workflows.

Below is the official 2026 framework, categorized by the threats most relevant to your Tuora static analysis and health-check engine.

| ID | Name | Description |
|----|------|-------------|
| ASI01 | Agent Goal Hijack | Attackers manipulate an agent's goals or decision paths via direct or indirect instruction injection. |
| ASI02 | Tool Misuse & Exploitation | Agents use legitimate tools in unsafe ways, often due to poor schema validation or recursive call loops. |
| ASI03 | Identity & Privilege Abuse | Agents use excessive privileges or reuse old credentials to access data/systems they should not. |
| ASI04 | Agentic Supply Chain Vulnerabilities | Threats from third-party tools, prompt templates, or registries (e.g., poisoned plugins). |
| ASI05 | Unexpected Code Execution | The agent generates/executes code (e.g., shell commands) that is malicious or leads to container escapes. |
| ASI06 | Memory & Context Poisoning | Malicious data is "planted" in the agent's RAG/memory stores to bias future decisions. |
| ASI07 | Insecure Inter-Agent Communication | Spoofing or intercepting messages between agents lacking proper authentication. |
| ASI08 | Cascading Failures | A single agent fault propagates and amplifies across the agent network, causing system-wide impact. |
| ASI09 | Human-Agent Trust Exploitation | Exploiting the human user's tendency to trust the AI's "expertise" to authorize unsafe actions. |
| ASI10 | Rogue Agents | A compromised or "drifting" agent that deviates from its intended scope to pursue deceptive goals. |

---

## 7. How this Integrates into Tuora

You are using these 10 categories as the foundation for your Tuora health check. To ensure your scanner remains context-aware and actionable:

### Context-Aware Scoring

Tuora scans your codebase for the presence of agentic frameworks across both Python and TypeScript/JavaScript ecosystems.

**Detected Python frameworks:** CrewAI, LangChain, LangGraph, AutoGen, OpenAI SDK (`openai`)

**Detected TypeScript/JavaScript frameworks:** Vercel AI SDK (`ai`), LangChain.js (`@langchain/`), LlamaIndex.TS (`llamaindex`, `@llamaindex/`), OpenAI Agents SDK JS (`@openai/agents`), Mastra (`@mastra/core`), OpenAI SDK (`openai`)

Detection runs in priority order: **(1) CrewAI YAML manifests (`agents.yaml`, `tasks.yaml`) → (2) `package.json` dependency key lookup → (3) source file import string scan** across all ingested `.ts`, `.js`, `.py`, and `.json` files.

**If Agentic Frameworks are detected — Full Rule Set (13 rules active):**
- All agentic rules: BZ-SEC-01, BZ-SEC-02, BZ-FIN-01, BZ-FIN-02, BZ-FIN-03, BZ-OPS-01, BZ-OPS-02, BZ-HYG-01, BZ-HYG-02, BZ-HYG-03
- All Traditional SAST rules run in parallel: BZ-SAST-01, BZ-SAST-02, BZ-SAST-03, BZ-SAST-04
- Denominator for normalized scoring = 13

**If no Agentic Frameworks are detected — Traditional SAST Rule Set (8 rules active):**
- Active rules: BZ-SEC-02 (with BZ-SEC-02B variant), BZ-HYG-01, BZ-HYG-03, BZ-OPS-02, BZ-SAST-01, BZ-SAST-02, BZ-SAST-03, BZ-SAST-04
- Inactive rules (marked N/A, excluded from health score denominator): BZ-SEC-01, BZ-FIN-01, BZ-FIN-02, BZ-FIN-03, BZ-OPS-01, BZ-HYG-02
- Denominator for normalized scoring = 8

### Health Check Scoring Formula

The health score uses a deduction model with a floor of 0. The normalized formula ensures the score is fair relative to the applicable rule set for the detected context:

$$
\text{Health Score} = \max\left(0,\ 100 - \sum_{r\ \in\ \text{Active Rules}} (\text{Violations}_r \times \text{Weight}_r)\right)
$$

Where severity weights are: CRITICAL = 25, HIGH = 15, MEDIUM = 8, LOW = 3.

### Terminal Output

The engine explicitly communicates which rule mode is active and why:

> **Agentic mode:** "CrewAI framework detected — running full 13-rule suite (OWASP Agentic Top 10 + Traditional SAST)."

> **Traditional mode:** "No agentic frameworks detected — running Traditional SAST rule set (8 rules). AI-specific checks BZ-SEC-01, BZ-FIN-01, BZ-FIN-02, BZ-FIN-03, BZ-OPS-01, BZ-HYG-02 marked N/A."
