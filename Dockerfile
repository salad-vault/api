# ---- Stage 1 : cargo-chef (cache des dépendances Cargo) ----
FROM rust:1.88-slim-bookworm AS chef

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --locked
WORKDIR /app

# ---- Stage 2 : Planification du plan de build ----
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- Stage 3 : Compilation des dépendances (couche cachée) ----
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Cette couche est mise en cache tant que Cargo.toml/Cargo.lock ne change pas
RUN cargo chef cook --release --recipe-path recipe.json

# Compilation du code source
COPY . .
RUN cargo build --release

# ---- Stage 4 : Image de production minimale ----
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Utilisateur non-root pour limiter la surface d'attaque
RUN useradd --system --no-create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

# Volume pour la base de données SQLite (persistance entre redémarrages)
RUN mkdir -p /data && chown appuser:appuser /data
VOLUME ["/data"]

COPY --from=builder /app/target/release/saladvault-api /usr/local/bin/saladvault-api

USER appuser

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3001/health || exit 1

CMD ["saladvault-api"]
