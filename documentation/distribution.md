# Tuora Distribution Guide

**Status:** Active — Native CLI distribution via `install.sh`  
**Last Updated:** June 4, 2026

---

## Overview

Tuora is distributed as a **statically-linked native CLI binary** for maximum performance and minimal friction. This document describes the distribution architecture, installation methods, and release process.

**Philosophy:**
- No Docker required (disabled pending CI completion)
- Single binary (~12-14MB)
- Cross-platform: Linux (x86_64 + ARM64), macOS (Intel + Apple Silicon)
- Self-updating capable (future)

---

## Installation Methods

### Method 1: Quick Install (Recommended)

```bash
curl -fsSL https://get.runtuora.com/install.sh | sh
```

**What happens:**
1. Script detects your platform (OS + architecture)
2. Downloads the appropriate binary from GitHub Releases
3. Verifies the binary is a valid executable
4. Installs to `~/.local/bin/tuora` (no `sudo` required, or override with `$INSTALL_DIR`)
5. Adds to PATH if not already present

**Supported Platforms:**
| OS | Architecture | Binary Name |
|----|--------------|-------------|
| Linux | x86_64 | `tuora-linux-x86_64` |
| Linux | ARM64 | `tuora-linux-arm64` |
| macOS | Intel | `tuora-macos-x86_64` |
| macOS | Apple Silicon | `tuora-macos-arm64` |

### Method 2: Manual Download

1. Visit [GitHub Releases](https://github.com/byleonardlim/tuora-core/releases)
2. Download the binary for your platform
3. Move to a directory in your PATH:
   ```bash
   chmod +x tuora-*
   sudo mv tuora-* /usr/local/bin/tuora
   ```

### Method 3: Build from Source

**Requirements:**
- Rust 1.78+ with `cargo`
- For musl targets: `musl-tools` (Linux) or `musl-cross` (macOS)

```bash
# Clone repository
git clone https://github.com/byleonardlim/tuora-core
cd tuora-core

# Build release binary
cargo build --release -p tuora

# Binary location: target/release/tuora
```

**Static linking (Linux):**
```bash
# Install musl target
rustup target add x86_64-unknown-linux-musl

# Build static binary
cargo build --release --target x86_64-unknown-linux-musl -p tuora
strip target/x86_64-unknown-linux-musl/release/tuora
```

---

## Installation Details

### Default Installation Path (User-Level)

| Platform | Default Path | Override |
|----------|--------------|----------|
| Linux/macOS | `~/.local/bin/tuora` | `INSTALL_DIR=$HOME/bin sh install.sh` |

**Security Note:** Tuora installs to user directories only. No `sudo` or admin privileges required.

### Directory Creation

The installer automatically creates the install directory if needed:
```bash
# Creates ~/.local/bin if it doesn't exist
mkdir -p "$HOME/.local/bin"
mv tuora "$HOME/.local/bin/tuora"
```

### PATH Setup (One-Time)

Most modern Linux distributions and macOS have `~/.local/bin` in PATH by default. If not, add it:

```bash
# Add to shell profile
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc  # or ~/.zshrc
source ~/.bashrc  # reload shell
```

### Post-Installation

After installation, the user runs:
```bash
$ tuora init
Enter your Tuora API key: bz_dev_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
✓ API key validated and stored securely in OS keyring
✓ Ready to scan. Run `tuora watch` to begin.

$ tuora watch
# Scans and watches the current directory

$ tuora watch ./my-agent-app
# Scans and watches a specific path
```

---

## Release Process

### 1. Cross-Compilation Pipeline (GitHub Actions)

**File:** `.github/workflows/release.yml`

The pipeline has four jobs:

| Job | Trigger | Purpose |
|-----|---------|---------|
| `bump-version` | `workflow_dispatch` (non-build-only) | Increments `core/Cargo.toml`, commits, creates and pushes tag |
| `test` | tag push or `build_only=true` | Runs `cargo test`, `clippy`, `fmt` |
| `build` | after `test` | Cross-compiles for all 4 targets, strips, renames, and uploads artifacts with checksums |
| `release` | after `build` | Downloads artifacts, assembles `SHA256SUMS`, creates GitHub Release |
| `test-install` | after `release` | Runs `core/install.sh` on ubuntu and macos runners to verify the install end-to-end |

**Triggering a release via `workflow_dispatch`:**

| Input | Values | Description |
|-------|--------|-------------|
| `bump` | `patch` / `minor` / `major` / `none` | How to increment the version |
| `build_only` | `true` / `false` | Skip bump, rebuild and re-release the current tag |

**Tag-push trigger:** pushing any tag matching `v[0-9]+.[0-9]+.[0-9]+*` runs `test → build → release → test-install` directly (no bump step).

**Cross-compilation notes:**
- Linux ARM64 uses [`cross`](https://github.com/cross-rs/cross) with `CROSS_CONTAINER_OPTS` to forward `TUORA_SIGNING_PUBKEY` into the container
- Linux musl targets require `musl-tools`; ARM64 additionally requires `binutils-aarch64-linux-gnu` for `aarch64-linux-gnu-strip`
- macOS targets build natively on `macos-latest`
- Windows target is **not supported** (removed)

**PAT requirement:** The `bump-version` job uses `secrets.RELEASE_TOKEN` (a PAT) instead of `GITHUB_TOKEN` so that the tag push triggers downstream workflow runs.

### 2. Artifact Naming Convention

| Target | Artifact Name | Compression |
|--------|----------------|-------------|
| `x86_64-unknown-linux-musl` | `tuora-linux-x86_64` | None |
| `aarch64-unknown-linux-musl` | `tuora-linux-arm64` | None (built via `cross`) |
| `x86_64-apple-darwin` | `tuora-macos-x86_64` | None |
| `aarch64-apple-darwin` | `tuora-macos-arm64` | None |

### 3. Versioning

- **Semantic Versioning:** `MAJOR.MINOR.PATCH` (e.g., `0.1.0`)
- **Latest Tag:** Always points to most recent stable release
- **Pre-releases:** Tagged with `-rc.1`, `-beta.1` suffixes (not picked up by `install.sh`)

### 4. Release Checklist

Before publishing a release:

- [ ] All tests pass (`cargo test`)
- [ ] Version bumped in `core/Cargo.toml`
- [ ] CHANGELOG.md updated
- [ ] Git tag created: `git tag -a v0.1.0 -m "Release v0.1.0"`
- [ ] CI pipeline completes for all platforms
- [ ] Binaries attached to GitHub Release
- [ ] `install.sh` tested on clean VMs
- [ ] Documentation updated

---

## Installer Script (`install.sh`)

### Location
- **Source:** `core/install.sh`
- **Hosted:** `https://get.runtuora.com/install.sh` (Cloudflare R2 or GitHub Pages)

### Features
- Platform auto-detection (`uname -s`, `uname -m`)
- curl/wget fallback support
- Binary verification (executable check)
- User-level installation to `~/.local/bin` (no sudo required)
- Automatic PATH detection with setup instructions
- Dynamic latest-release resolution via GitHub Releases API (no `/latest` redirect dependency)
- Version pinning support (`VERSION=v0.1.3 sh install.sh`)
- Idempotent (can re-run to update)

### Customization

```bash
# Install to custom directory
export INSTALL_DIR="$HOME/bin"
curl -fsSL https://get.runtuora.com/install.sh | sh

# Install specific version
export VERSION="0.1.0"
curl -fsSL https://get.runtuora.com/install.sh | sh

# Silent install (CI/CD) - will update PATH instructions
export INSTALL_DIR="$HOME/.local/bin"
curl -fsSL https://get.runtuora.com/install.sh | sh
```

---

## Binary Size Optimization

Current target: **< 15MB per binary**

**Achieved via:**
```toml
# Cargo.toml [profile.release]
opt-level = "z"        # Optimize for size
lto = true             # Link-time optimization
codegen-units = 1      # Single codegen unit
panic = "abort"        # No unwinding
```

**Additional stripping:**
```bash
strip --strip-all target/release/tuora
```

**Dependencies contributing to size:**
- `wasmtime` (~2-3MB)
- `tokio` + async runtime (~1MB)
- `reqwest` + TLS (~1MB)
- `regex` + patterns (~0.5MB)

---

## Windows Distribution

### PowerShell Installer (Coming Soon)

**File:** `install.ps1`

```powershell
# Usage
irm https://get.runtuora.com/install.ps1 | iex

# Or with parameters
$env:INSTALL_DIR = "C:\Tools"
irm https://get.runtuora.com/install.ps1 | iex
```

### MSI Installer (Future)

For enterprise deployment:
- Windows Installer package (.msi)
- Registry integration
- Start menu shortcut
- PATH modification

---

## Package Managers (Future)

| Platform | Command | Status |
|----------|---------|--------|
| Homebrew | `brew install tuora` | Planned |
| Cargo | `cargo install tuora` | Planned (crates.io) |
| Scoop (Windows) | `scoop install tuora` | Planned |
| AUR (Arch) | `yay -S tuora` | Community |
| Nix | `nix-env -iA nixpkgs.tuora` | Community |

---

## Security

### Binary Verification

**Checksums:** Each release includes a `SHA256SUMS` file aggregated from per-binary `.sha256` artifacts:
```
a1b2c3d4...  tuora-linux-x86_64
e5f6g7h8...  tuora-linux-arm64
...
```

**Signature:** GPG-signed checksums (planned)

### Supply Chain

- All binaries built via GitHub Actions (reproducible)
- No local compilation required for users
- Minimal attack surface (static binary, no dynamic libs)

---

## Troubleshooting

### Installation Issues

**"command not found" after install:**
```bash
# ~/.local/bin not in PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**"Permission denied" on macOS (quarantine):**
```bash
# macOS quarantine attribute (rare for user-level installs)
xattr -d com.apple.quarantine "$HOME/.local/bin/tuora"
```

**"Not in PATH":**
```bash
# Add to shell profile
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc
```

**Windows Defender false positive:**
- Submit binary to Microsoft for whitelist
- Or use Windows Subsystem for Linux (WSL)

### Update Issues

**Check installed version:**
```bash
tuora --version
```

**Force reinstall:**
```bash
curl -fsSL https://get.runtuora.com/install.sh | sh
```

---

## Related Documents

- `implementation-status.md` — Current build status
- `product-req.md` §3B — CLI installation requirements
- `tech-req.md` §2 — Containerization specifications (disabled)

---

## Infrastructure Requirements

| Resource | Purpose | Provider |
|----------|---------|----------|
| `get.runtuora.com` | Installer hosting | Cloudflare R2 / GitHub Pages |
| `github.com/tuora/tuora/releases` | Binary hosting | GitHub Releases |
| DNS | CNAME for get subdomain | Cloudflare |

---

**Note:** Docker distribution is currently disabled. The Dockerfile exists but has a package name mismatch (`breakzero` vs `tuora`) and requires CI pipeline completion. Native CLI is the supported distribution method.
