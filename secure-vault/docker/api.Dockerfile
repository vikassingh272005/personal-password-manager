# Multi-stage production image for the SecureVault API.
#
# The binary applies SQLx migrations at startup (sqlx::migrate! is baked in),
# so the runtime layer needs nothing but the binary itself — no cargo, no node.
# The process runs as an unprivileged user and only answers /health, /ready
# and /api/v1/*.

FROM rust:1.83-bookworm AS build
WORKDIR /build

# Cache dependency compilation: manifests first, then sources.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN mkdir -p apps/web && cargo build --release -p secure-vault-api

# ---- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin securevault

COPY --from=build /build/target/release/secure-vault /usr/local/bin/secure-vault

# Unprivileged runtime; the API binds PORT (default 3001).
USER securevault
EXPOSE 3001

ENV APP_ENV=production \
    PORT=3001 \
    RUST_LOG=info

# /ready proves the process is up AND the database is reachable.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -qO- "http://127.0.0.1:${PORT}/ready" >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/secure-vault"]
