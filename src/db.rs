use std::path::Path;

use rusqlite::Connection;

/// Open (or create) the server SQLite database and run migrations.
pub fn open_database(path: &Path) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open(path)?;

    // Enable WAL mode and foreign keys
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;",
    )?;

    run_migrations(&conn)?;

    Ok(conn)
}

/// Open an in-memory database for testing purposes.
#[cfg(test)]
pub fn open_database_in_memory() -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch("PRAGMA foreign_keys = ON;",)?;
    run_migrations(&conn)?;
    Ok(conn)
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
        ",
    )?;

    Ok(())
}
