use actix_web::{get, put, web, HttpRequest, HttpResponse};
use base64::Engine;
use rusqlite::params;

use crate::config::Config;
use crate::error::ApiError;
use crate::handlers::auth::extract_blind_id_from_request;
use crate::models::{SyncPushRequest, SyncStatusResponse, SyncVaultResponse};

type DbPool = web::Data<std::sync::Mutex<rusqlite::Connection>>;

/// GET /sync/vault
///
/// Download the encrypted vault blob for the authenticated user.
/// Returns 404 if no vault has been synced yet.
#[get("/sync/vault")]
pub async fn get_vault(
    db: DbPool,
    config: web::Data<Config>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let blind_id = extract_blind_id_from_request(&req, &config)?;

    let conn = db
        .lock()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let row: (Vec<u8>, i64, String) = conn
        .query_row(
            "SELECT vault_blob, version, updated_at FROM sync_vaults WHERE blind_id = ?1",
            params![blind_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| ApiError::NotFound("No synced vault found".to_string()))?;

    let vault_b64 = base64::engine::general_purpose::STANDARD.encode(&row.0);

    Ok(HttpResponse::Ok().json(SyncVaultResponse {
        vault_blob: vault_b64,
        version: row.1,
        updated_at: row.2,
    }))
}

/// PUT /sync/vault
///
/// Upload a new encrypted vault blob. The client must send the expected
/// version number. If the server version is higher, the push is rejected
/// (conflict — client should pull first).
#[put("/sync/vault")]
pub async fn put_vault(
    db: DbPool,
    config: web::Data<Config>,
    req: HttpRequest,
    body: web::Json<SyncPushRequest>,
) -> Result<HttpResponse, ApiError> {
    let blind_id = extract_blind_id_from_request(&req, &config)?;

    let vault_bytes = base64::engine::general_purpose::STANDARD
        .decode(&body.vault_blob)
        .map_err(|_| ApiError::BadRequest("Invalid base64 vault_blob".to_string()))?;

    let conn = db
        .lock()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Check current version (if any)
    let current_version: Option<i64> = conn
        .query_row(
            "SELECT version FROM sync_vaults WHERE blind_id = ?1",
            params![blind_id],
            |row| row.get(0),
        )
        .ok();

    if let Some(server_ver) = current_version {
        if body.version <= server_ver {
            return Err(ApiError::Conflict(format!(
                "Server version is {server_ver}, client sent {}. Pull first.",
                body.version
            )));
        }
    }

    let new_version = body.version;

    // Upsert vault
    conn.execute(
        "INSERT INTO sync_vaults (blind_id, vault_blob, version, updated_at)
         VALUES (?1, ?2, ?3, datetime('now'))
         ON CONFLICT(blind_id) DO UPDATE SET
            vault_blob = excluded.vault_blob,
            version = excluded.version,
            updated_at = excluded.updated_at",
        params![blind_id, vault_bytes, new_version],
    )?;

    // Also update last_seen_at
    conn.execute(
        "UPDATE server_users SET last_seen_at = datetime('now') WHERE blind_id = ?1",
        params![blind_id],
    )?;

    let updated_at: String = conn
        .query_row(
            "SELECT updated_at FROM sync_vaults WHERE blind_id = ?1",
            params![blind_id],
            |row| row.get(0),
        )?;

    Ok(HttpResponse::Ok().json(SyncStatusResponse {
        version: new_version,
        updated_at,
    }))
}

/// GET /sync/status
///
/// Return the current vault version and last update time
/// without downloading the full blob.
#[get("/sync/status")]
pub async fn sync_status(
    db: DbPool,
    config: web::Data<Config>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let blind_id = extract_blind_id_from_request(&req, &config)?;

    let conn = db
        .lock()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT version, updated_at FROM sync_vaults WHERE blind_id = ?1",
            params![blind_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();

    match row {
        Some((version, updated_at)) => {
            Ok(HttpResponse::Ok().json(SyncStatusResponse { version, updated_at }))
        }
        None => Ok(HttpResponse::Ok().json(SyncStatusResponse {
            version: 0,
            updated_at: String::new(),
        })),
    }
}
