# SaladVault API

Backend Zero-Knowledge pour le gestionnaire de mots de passe [SaladVault](https://saladvault.com).

Le serveur ne voit **jamais** d'email, de mot de passe ou d'entree en clair. Toutes les donnees sont chiffrees cote client avant d'etre transmises.

## Stack

- **Langage :** Rust
- **Framework :** Actix Web
- **Base de donnees :** SQLite (WAL mode) via `rusqlite` bundled
- **Authentification :** JWT (access + refresh tokens)
- **Crypto serveur :** Argon2id (verification), HMAC-SHA256 (blind index), AES-GCM (TOTP secrets)

## Prerequisites

- [Rust](https://rustup.rs/) (edition 2021)

## Configuration

Copier `.env` a la racine et renseigner les variables :

| Variable | Description | Default |
|----------|-------------|---------|
| `HOST` | Adresse d'ecoute | `127.0.0.1` |
| `PORT` | Port d'ecoute | `3001` |
| `DATABASE_PATH` | Chemin vers le fichier SQLite | `saladvault_server.db` |
| `JWT_SECRET` | Cle secrete pour signer les JWT | *(a changer en production)* |
| `JWT_ACCESS_LIFETIME` | Duree access token (secondes) | `900` (15 min) |
| `JWT_REFRESH_LIFETIME` | Duree refresh token (secondes) | `2592000` (30 jours) |
| `SMTP_HOST` | Serveur SMTP | *(vide)* |
| `SMTP_PORT` | Port SMTP | `587` |
| `SMTP_USER` | Utilisateur SMTP | *(vide)* |
| `SMTP_PASS` | Mot de passe SMTP | *(vide)* |
| `SMTP_FROM` | Adresse expediteur | `noreply@saladvault.com` |
| `MFA_ENCRYPTION_KEY` | Cle 32 bytes hex pour chiffrer les secrets TOTP | *(generer avec `openssl rand -hex 32`)* |

## Lancement

```bash
cargo run
```

## Tests

```bash
cargo test
```

## Docker

```bash
docker build -t saladvault-api .
docker run -p 3001:3001 -v saladvault-data:/data saladvault-api
```

## Licence

[AGPL-3.0-or-later](LICENSE)
