# Neon PostgreSQL Setup

Tuora uses [Neon](https://neon.tech) for managed PostgreSQL.

## Quick Start

### 1. Create Neon Project

```bash
# Via Neon Console (console.neon.tech)
# - Create project: "tuora"
# - Region: Choose closest to your API deployment
# - Database name: "tuora"
```

### 2. Get Connection String

From Neon Dashboard → Connection String → Copy `postgres://...`

Format:
```
postgres://<user>:<password>@<host>.neon.tech/tuora?sslmode=require
```

### 3. Configure Environment

```bash
cp .env.example .env
# Edit .env and set DATABASE_URL to your Neon connection string
```

### 4. Run Migrations

```bash
# Connect to Neon via psql or Neon SQL Editor
psql "postgres://<user>:<password>@<host>.neon.tech/tuora?sslmode=require" -f migrations/001_initial_schema.sql
```

Or via Neon Console SQL Editor, paste contents of `migrations/001_initial_schema.sql`.

### 5. Verify Connection

```bash
cd cloud/tuora-api
pnpm install
pnpm dev
# Should start without DB connection errors
```

## Schema Overview

| Schema | Table | Purpose |
|--------|-------|---------|
| `tuora_vault` | `wallet_ledger` | Tracks wallet balance, scan deductions, tiers |

### Key Design Decisions

- **Append-only ledger**: No updates, only inserts — immutable audit trail
- **Argon2id hashed keys**: API keys are never stored plaintext
- **Tier at transaction time**: Historical tier tracking for billing transparency

### Schema Reference

```sql
CREATE SCHEMA IF NOT EXISTS tuora_vault;

CREATE TYPE tuora_vault.tier_primitive AS ENUM (
  'hobby',
  'standard',
  'volume_discount'
);

CREATE TYPE tuora_vault.tx_primitive AS ENUM (
  'top_up',
  'hobby_grant',
  'scan_deduction'
);

CREATE TABLE tuora_vault.wallet_ledger (
  transaction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id   UUID NOT NULL,
  api_key_hash   CHAR(64) NOT NULL,
  transaction_type tuora_vault.tx_primitive NOT NULL,
  amount_usd     DECIMAL(10, 4) NOT NULL DEFAULT 0,
  current_tier   tuora_vault.tier_primitive NOT NULL DEFAULT 'hobby',
  historic_scans BIGINT NOT NULL DEFAULT 0,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### Column Notes

| Column | Type | Notes |
|--------|------|-------|
| `transaction_id` | `UUID` | PK — `gen_random_uuid()` (no extension required on Neon PG 14+) |
| `api_key_hash` | `CHAR(64)` | Fixed-width Argon2id hash — never store plaintext |
| `historic_scans` | `BIGINT` | Cumulative scan count; `BIGINT` for high-volume accounts |
| `transaction_type` | `tx_primitive` | Enum: `top_up`, `hobby_grant`, `scan_deduction` |

## Neon-Specific Features Used

| Feature | How We Use It |
|---------|---------------|
| **Serverless compute** | Auto-scales to zero during low traffic |
| **SSL required** | Enforced in `postgres.ts` connection |
| **Connection pooling** | `prepare: false` in client config for pooler compatibility |
| **Branches** | Create branches for staging/testing schema changes |

## Connection Pooling

Neon uses PgBouncer for connection pooling. The `postgres` client is configured with:

```typescript
prepare: false,  // Required for Neon pooler (PgBouncer transaction mode)
max: 5,          // Conservative pool size for Neon pooler slot limits
```

`prepare: false` disables prepared statements, which are incompatible with PgBouncer's transaction mode.

## Indexes

| Index | Columns | Purpose |
|-------|---------|---------|
| `idx_wallet_ledger_api_key_hash` | `api_key_hash` | Key lookup |
| `idx_wallet_ledger_workspace_id` | `workspace_id` | Workspace queries |
| `idx_wallet_ledger_created_at` | `created_at DESC` | Time-range scans |
| `idx_wallet_ledger_api_key_hash_created_at` | `(api_key_hash, created_at DESC)` | Key + time composite |
| `idx_wallet_handshake` | `(workspace_id, api_key_hash, created_at DESC)` | Sub-millisecond `/v1/auth` handshake |

## Local Development

For local dev without Neon:

```bash
# Docker PostgreSQL
docker run -d --name tuora-db \
  -e POSTGRES_USER=user \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=tuora \
  -p 5432:5432 postgres:15

# .env
DATABASE_URL=postgres://user:password@localhost:5432/tuora
```

The code auto-detects `neon.tech` in the URL and enables SSL only when needed.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `SSL required` error | Ensure `sslmode=require` in connection string |
| Connection timeouts | Check `connect_timeout: 10` in `postgres.ts` |
| Prepared statement errors | `prepare: false` is already set for Neon |
| Pool exhaustion | `max: 5` is set; scale horizontally rather than increasing pool size |
