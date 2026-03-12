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
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Volume pour la base de données SQLite (persistance entre redémarrages)
VOLUME ["/data"]

COPY --from=builder /app/target/release/saladvault-api /usr/local/bin/saladvault-api

EXPOSE 3001
CMD ["saladvault-api"]
