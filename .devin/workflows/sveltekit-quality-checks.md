---
description: SvelteKit quality checks — run after major code changes or code generation
---

# SvelteKit Quality Checks

Run these checks after every **major** code change or code generation pass in the dashboard application (`cloud/dashboard/`).

## Trigger Criteria

| Change Scope | Required Checks |
|---|---|
| **Major** — new components, new routes, API changes, logic changes, dependency updates | `check` → `build` (all, in order) |
| **Minor** — styling tweaks, component prop changes, copy edits | `check` only |
| **Trivial** — no source touched (e.g. markdown, YAML only) | Skip |

---

## Step 1 — Type Check (always run first)

Validates Svelte components and TypeScript files for type errors.

```
cd cloud/dashboard && pnpm check
```

This runs `svelte-kit sync && svelte-check --tsconfig ./tsconfig.json`.

Fix any type errors before proceeding.

---

## Step 2 — Build Verification (major changes only)

Ensures the application builds successfully for production.

```
cd cloud/dashboard && pnpm build
```

This runs `vite build` and validates the entire application compiles without errors.

---

## Optional Enhancements

### Add Prettier for Formatting

To enforce consistent code formatting, add Prettier:

```
cd cloud/dashboard && pnpm add -D prettier prettier-plugin-svelte
```

Create `cloud/dashboard/.prettierrc`:

```json
{
  "useTabs": false,
  "singleQuote": true,
  "trailingComma": "es5",
  "printWidth": 100,
  "plugins": ["prettier-plugin-svelte"],
  "overrides": [{ "files": "*.svelte", "options": { "parser": "svelte" } }]
}
```

Add to `package.json` scripts:

```json
"format": "prettier --write .",
"format:check": "prettier --check ."
```

### Add ESLint for Linting

To catch code quality issues, add ESLint:

```
cd cloud/dashboard && pnpm add -D eslint eslint-plugin-svelte globals
```

Create `cloud/dashboard/eslint.config.js` and add a `lint` script to `package.json`.

---

## Notes

- Always run `check` **before** `build` — type errors will fail the build anyway, so catch them early.
- The dashboard uses **pnpm** — never use npm or yarn in this workspace.
- In CI (`.github/workflows/ci.yml`), both checks must pass on every PR affecting `cloud/dashboard/`.
