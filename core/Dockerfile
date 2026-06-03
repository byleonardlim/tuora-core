# Tuora: Distroless Static Container Build
# STATUS: NOT READY - cross-compilation pipeline not complete
# For current distribution, use the native CLI installer: curl -fsSL https://get.runtuora.com/install.sh | sh
#
# Target: ~11-14MB uncompressed image
#
# Build context must be the workspace root, not core/:
#   docker build -f core/Dockerfile -t tuora .

# Stage 1: Build environment
FROM rust:1.78-alpine AS builder

# Install musl toolchain for static linking
RUN apk add --no-cache musl-dev openssl-dev pkgconfig

# Create workspace directory
WORKDIR /app

# ── Dependency caching layer ──────────────────────────────────────────────────
# Copy workspace root manifest + lock file
COPY Cargo.toml Cargo.lock ./

# Copy crate manifests (no source yet — for layer caching)
COPY core/Cargo.toml ./core/Cargo.toml
COPY types/Cargo.toml ./types/Cargo.toml

# Stub out minimal source files so cargo can resolve the workspace graph
RUN mkdir -p core/src types/src && \
    echo "fn main() {}" > core/src/main.rs && \
    echo "" > types/src/lib.rs

# Pre-build dependencies (cached layer — invalidated only on Cargo.toml changes)
RUN cargo build --release --target x86_64-unknown-linux-musl 2>/dev/null || true

# ── Real source build ─────────────────────────────────────────────────────────
COPY core/src ./core/src
COPY types/src ./types/src
COPY core/assets ./core/assets

# Touch entry points to force rebuild
RUN touch core/src/main.rs types/src/lib.rs

# Build static binary with size optimizations
RUN cargo build --release --target x86_64-unknown-linux-musl -p tuora && \
    strip --strip-all target/x86_64-unknown-linux-musl/release/tuora

# Stage 2: Runtime - Google Distroless Static
FROM gcr.io/distroless/static-debian12:nonroot

# Copy static binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/tuora /tuora

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Set non-root user
USER 65532:65532

# Working directory for volume mount
WORKDIR /app

# Entrypoint
ENTRYPOINT ["/tuora"]
