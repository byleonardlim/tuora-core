# Tuora

**Zero-footprint static analysis for vibe-coded applications**

Tuora is a lightweight, stateless CLI security scanner designed for AI-generated code (CrewAI, LangGraph, AutoGen). It runs locally on your machine, scanning for security vulnerabilities, financial guardrails, and architectural anti-patterns before deployment.

## Installation

### macOS / Linux (Recommended)

Install with a single command:

```bash
curl -fsSL https://get.runtuora.com/install.sh | sh
```

This installs `tuora` to `~/.local/bin/tuora`. If this directory is not in your PATH, the installer will prompt you to add it.

### Docker

For CI/CD pipelines or containerized environments:

```bash
docker pull tuora/tuora:latest
```

## Commands

| Command | Description |
|---------|-------------|
| `tuora` | Show available commands |
| `tuora init` | First-time setup — store API key in OS keyring |
| `tuora watch` | Scan and watch the current directory |
| `tuora watch <path>` | Scan and watch a specific directory |

## Running Tuora

### First-time Setup

```bash
tuora init
```

Prompts for your API key and stores it securely in the OS keyring. If a key is already stored, you will be asked whether to reinitialize.

### Watch Mode

Scan your project and re-evaluate on every file save:

```bash
# Watch current directory
tuora watch

# Watch a specific path
tuora watch ./my-agent-app

# Watch with JSON output
tuora watch ./my-agent-app --format json
```

### Docker Usage

```bash
docker run --rm -v $(pwd):/app \
  -e TUORA_API_KEY=$TUORA_API_KEY \
  tuora/tuora:latest \
  watch /app
```

## Options

| Flag | Environment Variable | Default | Description |
|------|----------------------|---------|-------------|
| `--api-key` | `TUORA_API_KEY` | - | Tuora API key |
| `--format` | - | `ansi` | Output format: `ansi`, `json`, `plain` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean scan or only medium/low issues |
| 1 | High severity issues found |
| 2 | Critical severity issues found |

## CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  env:
    TUORA_API_KEY: ${{ secrets.TUORA_API_KEY }}
  run: |
    tuora watch . --format json
```

## Development

Build from source:

```bash
# Clone the repository
git clone https://github.com/tuora/tuora.git
cd tuora

# Build release binary
cargo build --release

# Run locally
cargo run -- watch ./test-workspace
```

## Troubleshooting

### "Invalid Ed25519 signature" or "Signing public key not embedded"

These errors indicate a signing key mismatch between the CLI client and the cloud API. See the complete [Key Management Guide](documentation/key-management.md) for:
- Key generation and extraction commands
- CI/CD secret configuration
- Build-time embedding requirements
- Key rotation procedures

## License

MIT - Open Core (scanner engine open source, threat signatures SaaS)
