use std::path::Path;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

/// Connection pool type used throughout the API.
pub type DbPool = Pool<SqliteConnectionManager>;

/// Initializer that sets PRAGMAs on every new connection.
#[derive(Debug)]
struct SqliteInit;

impl r2d2::CustomizeConnection<Connection, rusqlite::Error> for SqliteInit {
    fn on_acquire(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;",
        )?;
        Ok(())
    }
}

/// Create a connection pool for the server SQLite database and run migrations.
pub fn create_pool(path: &Path) -> Result<DbPool, Box<dyn std::error::Error>> {
    let manager = SqliteConnectionManager::file(path);
    let pool = Pool::builder()
        .max_size(8)
        .connection_customizer(Box::new(SqliteInit))
        .build(manager)?;

    // Run migrations on one connection
    let conn = pool.get()?;
    run_migrations(&conn)?;

    Ok(pool)
}

/// Create an in-memory pool for testing (single connection to share state).
#[cfg(test)]
pub fn create_pool_in_memory() -> Result<DbPool, Box<dyn std::error::Error>> {
    let manager = SqliteConnectionManager::memory();
    let pool = Pool::builder()
        .max_size(1)
        .connection_customizer(Box::new(SqliteInit))
        .build(manager)?;

    let conn = pool.get()?;
    run_migrations(&conn)?;

    Ok(pool)
}

fn run_migrations(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS server_users (
            blind_id        TEXT PRIMARY KEY,
            auth_hash       TEXT NOT NULL,
            auth_salt       BLOB NOT NULL,
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            last_seen_at    TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS sync_vaults (
            blind_id        TEXT PRIMARY KEY,
            vault_blob      BLOB NOT NULL,
            version         INTEGER NOT NULL DEFAULT 1,
            updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (blind_id) REFERENCES server_users(blind_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS deadman_config (
            blind_id              TEXT PRIMARY KEY,
            enabled               INTEGER NOT NULL DEFAULT 0,
            inactivity_days       INTEGER NOT NULL DEFAULT 90,
            recipient_email       TEXT NOT NULL DEFAULT '',
            recovery_blob_enc     BLOB,
            triggered             INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (blind_id) REFERENCES server_users(blind_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token_hash      TEXT PRIMARY KEY,
            blind_id        TEXT NOT NULL,
            expires_at      TEXT NOT NULL,
            FOREIGN KEY (blind_id) REFERENCES server_users(blind_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS mfa_secrets (
            blind_id        TEXT PRIMARY KEY,
            totp_secret_enc BLOB NOT NULL,
            enabled         INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (blind_id) REFERENCES server_users(blind_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS mfa_tokens (
            token_hash      TEXT PRIMARY KEY,
            blind_id        TEXT NOT NULL,
            token_type      TEXT NOT NULL CHECK (token_type IN ('setup', 'challenge')),
            expires_at      TEXT NOT NULL,
            attempt_count   INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (blind_id) REFERENCES server_users(blind_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS subscriptions (
            blind_id                TEXT PRIMARY KEY,
            stripe_customer_id      TEXT NOT NULL,
            stripe_subscription_id  TEXT,
            plan                    TEXT NOT NULL DEFAULT 'jardinier',
            status                  TEXT NOT NULL DEFAULT 'inactive',
            trial_end               TEXT,
            current_period_end      TEXT,
            created_at              TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at              TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (blind_id) REFERENCES server_users(blind_id) ON DELETE CASCADE
        );


        CREATE TABLE IF NOT EXISTS email_verifications (
            blind_id        TEXT PRIMARY KEY,
            code_hash       TEXT NOT NULL,
            expires_at      TEXT NOT NULL,
            verified        INTEGER NOT NULL DEFAULT 0,
            attempt_count   INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        );
        ",
    )?;

    Ok(())
}
