# syntax=docker/dockerfile:1.7

ARG NODE_VERSION=24
ARG RUST_VERSION=1.95

FROM node:${NODE_VERSION}-bookworm-slim AS frontend
WORKDIR /src/web/admin-console

COPY web/admin-console/package.json web/admin-console/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm,sharing=locked \
    npm ci --no-audit --no-fund

COPY web/admin-console/ ./
RUN npm run build

FROM rust:${RUST_VERSION}-bookworm AS builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        libclang-dev \
        nasm \
        ninja-build \
        perl \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY crates ./crates
COPY contracts ./contracts
COPY --from=frontend /src/web/admin-console/dist ./web/admin-console/dist

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked -p super-gatewayd \
    && install -D -m 0755 target/release/super-gatewayd /out/super-gatewayd

FROM debian:bookworm-slim AS runtime

ARG OCI_SOURCE=https://github.com/xixiknow/super-gateway
LABEL org.opencontainers.image.source="${OCI_SOURCE}" \
      org.opencontainers.image.title="Super Gateway" \
      org.opencontainers.image.description="Claude Code enterprise gateway with an embedded administration console"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        curl \
        libstdc++6 \
        passwd \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 gateway \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/super-gateway --no-create-home --shell /usr/sbin/nologin gateway \
    && install -d -o gateway -g gateway -m 0700 \
        /var/lib/super-gateway \
        /var/lib/super-gateway/bundles \
        /var/lib/super-gateway/response-tmp \
        /var/lib/super-gateway/content-audit \
    && install -d -o root -g gateway -m 0750 /etc/super-gateway

COPY --from=builder --chown=10001:10001 /out/super-gatewayd /usr/local/bin/super-gatewayd
COPY --chmod=0755 deploy/container/entrypoint.sh /usr/local/bin/super-gateway-entrypoint

ENV RUST_BACKTRACE=0
WORKDIR /var/lib/super-gateway
USER 10001:10001

EXPOSE 8080 8081
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:8080/healthz"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/super-gateway-entrypoint"]
CMD ["serve"]
