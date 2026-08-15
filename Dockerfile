# syntax=docker/dockerfile:1
# ============================================================================
# MCPG Operator — Kubernetes operator for MCPG
# ----------------------------------------------------------------------------
# Self-contained image built from this crate's source alone, on public base
# images. A Rust builder compiles the operator and the `crdgen` companion from
# crates.io dependencies; a slim Debian runtime carries both and runs them as a
# non-root user.
#
#   docker build -t mcpg-operator:local .
#   docker run --rm mcpg-operator:local crdgen > crds.yaml
#
# In-cluster, both ports matter: :9443 terminates the admission webhook and
# :8443 serves metrics plus the liveness/readiness endpoints the Deployment's
# probes target. A pod whose probes hit a closed :8443 never goes Ready, and
# anything that waits on the operator before applying custom resources then
# blocks to timeout — so publish both.
# ============================================================================

FROM rust:1-bookworm AS build

# rustls' aws-lc-rs provider builds C sources at compile time and needs
# cmake + clang/bindgen; protoc is for the fleet-plane gRPC contract.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        cmake clang libclang-dev perl pkg-config protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cargo build --release --bin mcpg-operator --bin crdgen

# ----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="mcpg-operator" \
      org.opencontainers.image.description="Kubernetes operator for MCPG (Model Context Protocol Gateway)" \
      org.opencontainers.image.licenses="Apache-2.0"

# ca-certificates for outbound TLS (OCI registries, the Kubernetes API);
# tini for PID-1 signal handling.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/mcpg-operator /usr/local/bin/mcpg-operator
COPY --from=build /src/target/release/crdgen /usr/local/bin/crdgen

# 65534 (nobody) matches the runAsUser the published chart sets, so a
# securityContext-mounted webhook certificate stays readable.
USER 65534:65534
WORKDIR /tmp

ENV RUST_LOG=info

EXPOSE 9443 8443

ENTRYPOINT ["tini", "--", "mcpg-operator"]
