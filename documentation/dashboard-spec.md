# Tuora Web Dashboard Specification

**Status:** Draft  
**Last Updated:** 2026-06-02  
**Scope:** Account provisioning, API key management, and self-service portal

---

## 1. Overview

The Tuora Dashboard is a web-based portal for account management, API key provisioning, and scanner configuration. It eliminates the need for manual CLI-based key provisioning while maintaining a password-less authentication model.

**Primary Domain:** `runtuora.com`

---

## 2. Authentication Architecture

### 2.1 Design Principles

- **No passwords stored** — Authentication via trusted OAuth providers or email magic links only
- **Zero-friction first run** — First successful auth triggers automatic API key generation
- **Key shown once** — API key is revealed exactly once; server stores only Argon2id hash

### 2.2 Providers

| Provider | Implementation | Identifier Stored |
|----------|---------------|-------------------|
| **GitHub** | SvelteKit Auth (Lucia) + GitHub OAuth | GitHub user ID (`provider_account_id`) |
| **Email Magic Link** | Lucia + custom magic link handler + Resend | Email address (`provider_account_id`) |

### 2.3 Email Configuration (Resend)

```env
RESEND_API_KEY=re_xxxxxxxxxxxxxxxx
RESEND_FROM_EMAIL=noreply@runtuora.com
```

- Free tier: 100 emails/day (sufficient for testing phase)
- Magic link expires: 15 minutes
- Sender domain: `runtuora.com` (requires DNS verification)

---

## 3. Database Schema Additions

### 3.1 Accounts Table

Links external authentication providers to internal workspaces.

```sql
CREATE TABLE tuora_vault.accounts (
  account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES tuora_vault.workspaces(workspace_id),
  provider TEXT NOT NULL, -- 'github', 'email'
  provider_account_id TEXT NOT NULL, -- GitHub ID or email address
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(provider, provider_account_id)
);

-- Index for fast provider lookup during sign-in
CREATE INDEX idx_accounts_provider_lookup 
ON tuora_vault.accounts (provider, provider_account_id);
```

### 3.2 Workspaces Table

Isolates workspace metadata from the append-only ledger.

```sql
CREATE TABLE tuora_vault.workspaces (
  workspace_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT, -- nullable, populated from email provider or GitHub primary email
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 3.3 Magic Link Tokens Table

Single-use token store for email magic link replay protection. Tokens are stored as SHA-256 hashes — plaintext is never persisted.

```sql
CREATE TABLE tuora_vault.magic_link_tokens (
  token_hash  CHAR(64)    PRIMARY KEY,               -- SHA-256 of the raw token
  email       TEXT        NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '15 minutes')
);

-- TTL index: tokens expire after 15 minutes
CREATE INDEX idx_magic_link_tokens_expires_at
ON tuora_vault.magic_link_tokens (expires_at);
```

**Lifecycle:**
1. `generateMagicLink` inserts `(SHA-256(token), email, expires_at)` immediately after generating the token.
2. `verifyMagicLink` passes HMAC + expiry checks first (cheap, no DB), then deletes the row by hash.
3. If `DELETE` returns 0 rows the token has already been consumed — reject.
4. A periodic cleanup job (or `DELETE WHERE expires_at < NOW()`) purges stale rows.

### 3.4 Key Generations Table

Audit trail for API key lifecycle (no plaintext keys stored).

```sql
CREATE TABLE tuora_vault.key_generations (
  generation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES tuora_vault.workspaces(workspace_id),
  api_key_hash CHAR(64) NOT NULL, -- Argon2id hash
  generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for workspace key history
CREATE INDEX idx_key_generations_workspace 
ON tuora_vault.key_generations (workspace_id, generated_at DESC);
```

---

## 4. API Key Generation Flow

### 4.1 First Sign-In Sequence

```
[User clicks GitHub/Email sign-in]
           ↓
[Lucia auth callback validates token]
           ↓
[Check accounts table for provider + provider_account_id]
           ↓
    ┌──────┴──────────┐
    ↓                 ↓
[Existing]        [New Account]
    ↓                 ↓
Redirect to    [Insert workspaces row]
dashboard      [Insert accounts row]
               [Generate bz_dev_<random32>]
               [Argon2id hash with 32-byte salt]
               [Insert to key_generations]
               [Insert to wallet_ledger:]
                 - transaction_type: 'hobby_grant'
                 - amount_usd: 10.00 (100 scans at $0.10)
               [Redirect to /dashboard?showKey=true]
```

### 4.2 Key Format

- **Pattern:** `bz_dev_[a-zA-Z0-9]{32}`
- **Example:** `bz_dev_a3f9b2c1d8e7f6a5b4c3d2e1f0a9b8c7`
- **Rationale:** Structural prefix allows GitHub Secret Scanning and other tools to auto-detect leaked keys

### 4.3 Display Rules

- Key shown **only** on first visit to `/dashboard` with `?showKey=true`
- Modal overlay blocks interaction until user confirms: "I have copied this key to a secure location"
- Server marks key as "delivered" (not stored, just a boolean flag on the session)
- Subsequent dashboard visits show only hash suffix (`...a3f9b2c1`) as confirmation

---

## 5. Page Specifications

### 5.1 Landing Page (`/`)

**Purpose:** Convert visitors to users

**Content:**
- Hero: "Stop deploying AI agents blind"
- Feature bullets: 13-rule WASM engine, zero network access to your code
- Primary CTA: "Get Started Free" → `/auth/signin`
- Secondary link: `/pricing`

### 5.2 Pricing Page (`/pricing`)

**Purpose:** Tier comparison and value proposition

#### Hobby Tier (Free)

| Feature | Limit |
|---------|-------|
| Price | $0 |
| Scans included | 100 |
| API keys | 1 active |
| Support | Email |
| Best for | Indie devs, testing, small projects |

#### CI/CD Tier (Coming Soon)

| Feature | Limit |
|---------|-------|
| Price | TBD |
| Scans | Unlimited |
| API keys | Multiple (team sharing) |
| Rules | Priority access to new signatures |
| Best for | Teams, production pipelines |

#### Threat Signature Info Block

```
Current Rule Bundle: v{version}
Size: ~2.1 MB WASM module
Last Updated: {date}
Rules: 14 active (OWASP Agentic Top 10 + Traditional SAST)
Download estimate: ~0.5s on fast 4G, ~2s on 3G
```

### 5.3 Dashboard Home (`/dashboard`)

**Purpose:** Key management and scanner setup

#### First Visit (showKey=true)

Modal overlay with:
- API key in copy-friendly `<code>` block with one-click copy
- Three-step setup guide:
  1. Install: `curl -fsSL https://get.runtuora.com/install.sh | sh`
  2. Configure: `tuora init` then paste your key
  3. Scan: `tuora watch` in your project directory
- Checkbox: "I have saved this key securely" (required to dismiss)
- Warning: "We never show this key again. If you lose it, you must rotate."

#### Standard View

- Usage stats: `{scans_used} / 100 scans used` with progress bar
- Estimated remaining: `{remaining_scans} scans remaining (~${remaining_value} value)`
- Quick actions:
  - "View Scanner Setup" (expands install instructions)
  - "Rotate API Key" (generates new, invalidates old, shows once)
  - "Delete Account" ( GDPR/CCPA compliance)

### 5.4 Rules Info Page (`/rules-info`)

**Purpose:** Technical transparency and trust-building

**Content:**
- Current bundle version with changelog link
- Download size: `~2.1 MB` with network time estimator
- Rule breakdown by category:
  - Security (BZ-SEC-*): 1 rule (with BZ-SEC-02B shell escalation variant)
  - Financial (BZ-FIN-*): 3 rules
  - Operational (BZ-OPS-*): 2 rules
  - Hygiene (BZ-HYG-*): 3 rules
  - Traditional SAST (BZ-SAST-*): 4 rules
  - **Total: 13 rules**
- Link to `/documentation/compliance-rules.md` for full definitions
- "How rules work" explainer: WASM sandbox, local execution, no code leaves your machine

### 5.5 Billing (inline on `/dashboard`)

**Purpose:** Future Stripe integration placeholder, rendered as a section below the API key and usage cards

**Current State:**
- CI/CD upgrade card (Coming Soon badge, feature list, disabled Join Waitlist button)
- Payment history empty state

**Future State:**
- Stripe Customer Portal integration
- Top-up interface ($2.00 minimum)
- Invoice history

---

## 6. Tech Stack

```json
{
  "framework": "SvelteKit 2.x",
  "auth": "Lucia (SvelteKit auth)",
  "database": "@neondatabase/serverless",
  "email": "Resend",
  "hashing": "argon2",
  "styling": "Tailwind CSS",
  "components": "shadcn-svelte (port) or Skeleton UI"
}
```

---

## 7. Environment Variables

```env
# Database
DATABASE_URL=postgres://user:pass@host.neon.tech/tuora?sslmode=require

# SvelteKit / Lucia
PUBLIC_APP_URL=https://runtuora.com
LUCIA_SECRET=openssl_rand_base64_32

# OAuth (GitHub)
GITHUB_CLIENT_ID=Ov23lixxxxxxxxxxxx
GITHUB_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Email (Resend)
RESEND_API_KEY=re_xxxxxxxxxxxxxxxx
RESEND_FROM_EMAIL=noreply@runtuora.com

# Tuora API (for internal calls)
TUORA_API_URL=https://api.runtuora.com
```

---

## 8. File Structure

```
cloud/dashboard/
├── .env                     # Gitignored, populated from .env.example
├── .env.example             # Template for new developers
├── svelte.config.js         # SvelteKit adapter (Vercel)
├── vite.config.ts
├── package.json
├── src/
│   ├── app.d.ts             # Type declarations
│   ├── app.html             # HTML template
│   ├── routes/
│   │   ├── +layout.svelte           # Root layout (CSS import + slot only)
│   │   ├── +layout.server.ts        # Passes locals.user to all route groups
│   │   │
│   │   ├── (marketing)/             # Public product site — no auth required
│   │   │   ├── +layout.svelte       # Marketing nav (logo, Pricing, Get Started)
│   │   │   │                        # + curtain-reveal footer
│   │   │   └── +page.svelte         # Landing page at /
│   │   │
│   │   ├── (app)/                   # Post-login app shell
│   │   │   ├── +layout.svelte       # App nav (Dashboard link, email, Sign out)
│   │   │   └── dashboard/
│   │   │       ├── +page.server.ts  # Load: key stats, check showKey; redirects if unauthed
│   │   │       └── +page.svelte     # Key display, usage, and billing at /dashboard
│   │   │
│   │   ├── auth/                    # Auth flows (no group layout)
│   │   │   ├── signin/
│   │   │   │   ├── +page.server.ts  # Magic link form POST
│   │   │   │   └── +page.svelte     # Provider selection
│   │   │   ├── callback/
│   │   │   │   └── github/
│   │   │   │       └── +server.ts   # GitHub OAuth callback
│   │   │   ├── email/
│   │   │   │   ├── +page.server.ts  # Magic link form POST
│   │   │   │   └── verify/
│   │   │   │       └── +page.server.ts  # Verify token + sign in
│   │   │   └── signout/
│   │   │       └── +server.ts       # POST: sign out
│   │   │
│   │   └── api/                     # Internal API endpoints (no layout)
│   │       └── key/
│   │           ├── generate/
│   │           │   └── +server.ts   # POST: generate new key
│   │           └── rotate/
│   │               └── +server.ts   # POST: rotate key
│   └── lib/
│       ├── server/
│       │   ├── auth.ts              # Lucia configuration
│       │   ├── db.ts                # Neon client + helpers
│       │   ├── keygen.ts            # bz_dev_ + Argon2id logic
│       │   ├── email.ts             # Resend magic link sender
│       │   └── lucia.ts             # Lucia adapter (Neon)
│       └── components/
│           ├── ApiKeyModal.svelte   # "Copy this key NOW" modal
│           ├── SetupGuide.svelte    # Scanner install steps
│           ├── UsageStats.svelte    # Progress bar component
│           └── PricingCard.svelte   # Tier display component
└── static/                  # Static assets
└── migrations/              # SQL migrations (Neon)
```

> **Route groups** (`(marketing)`, `(app)`) are a SvelteKit convention — the parenthesized folder name does **not** appear in the URL. They exist solely to scope layouts: the product site and the post-login app shell each get an independent nav and shell without affecting any `/` or `/dashboard` paths.

---

## 9. Security Considerations

| Threat | Mitigation |
|--------|------------|
| Key brute force | 32-byte random key space (infeasible) |
| Argon2id cost | Memory: 64MB, iterations: 3, parallelism: 4 |
| Magic link interception | 15-min expiry, HTTPS only |
| Magic link replay | Token hash stored in `magic_link_tokens`; row deleted atomically on first use — second use returns 0 rows and is rejected |
| `LUCIA_SECRET` misconfiguration | `generateSignature` throws `Error('LUCIA_SECRET is not set')` on startup rather than silently falling back to a known string |
| OAuth CSRF | State parameter validation (Lucia handles) |
| Email enumeration | Generic "check your email" message regardless of existence |
| Session hijacking | Secure, HttpOnly, SameSite=strict cookies |
| Database leak | Only Argon2id hashes stored, no plaintext keys |

---

## 10. Open Questions (Resolve Before Build)

1. **GitHub OAuth app** — Create under personal account or organization?
2. **Resend domain** — `runtuora.com` DNS verification status?
3. **Session strategy** — Lucia session cookies (database-backed, revocable by default)
4. **Key rotation limit** — Rate limit rotations to prevent abuse?

---

## 11. Implementation Phases

### Phase 1: Foundation
- [x] SvelteKit 2.x + Tailwind + skeleton scaffold
- [x] Neon connection + workspace/accounts/key_generations schema
- [x] Lucia auth setup with GitHub OAuth

### Phase 2: Key Generation
- [x] First sign-in flow with automatic key generation
- [x] Argon2id hashing with proper salt
- [x] Hobby grant seeding ($10.00) in wallet_ledger

### Phase 3: Dashboard
- [x] `/dashboard` with showKey modal (query param driven)
- [x] `/pricing` page
- [x] `/rules-info` page

### Phase 4: Polish
- [x] Email magic link provider (Resend)
- [x] Key rotation feature
- [ ] Account deletion (framework in place, UI pending)

---

## Related Documents

- `/documentation/product-req.md` §3B.3 (First-Run Initialization)
- `/documentation/tech-req.md` §3 (API Key Storage)
- `/documentation/tech-req.md` §5B (Handshake Verification Flow)
- `/documentation/neon-setup.md` (Database schema baseline)
