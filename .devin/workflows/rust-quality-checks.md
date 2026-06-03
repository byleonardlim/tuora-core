---
description: Rust quality checks — run after major code changes or code generation
---

# Rust Quality Checks

Run these checks after every **major** code change or code generation pass in any Rust crate
(workspace root, `core/`, or `types/`).

## Trigger Criteria

| Change Scope | Required Checks |
|---|---|
| **Major** — new modules, new public APIs, logic changes, generated code, dependency updates | `fmt` → `clippy` → `test` (all three, in order) |
| **Minor** — whitespace, comment edits, doc-only changes | `fmt` only |
| **Trivial** — no Rust source touched (e.g. markdown, YAML only) | Skip |

---

## Step 1 — Format (always run first)

Checks and auto-corrects formatting across the entire workspace.

```
cargo fmt --all
```

If you only want to *check* without mutating (e.g. in CI review):

```
cargo fmt --all -- --check
```

---

## Step 2 — Lint with Clippy (major changes only)

Runs Clippy with the workspace's default lint configuration. Treat warnings as errors to enforce a clean baseline.

```
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Fix any lint issues before proceeding. Never suppress a Clippy warning without explicit justification in a code comment.

---

## Step 3 — Run Tests (major changes only)

Run the full workspace test suite.

```
cargo test --workspace
```

For faster feedback during incremental work, target a specific crate:

```
cargo test -p core
cargo test -p types
```

---

## Notes

- Always run `fmt` **before** `clippy` — unformatted code can trigger spurious lint warnings.
- If `clippy` reports issues, fix them **before** running tests to avoid chasing false failures.
- In CI (`.github/workflows/ci.yml`), all three checks must pass on every PR.
