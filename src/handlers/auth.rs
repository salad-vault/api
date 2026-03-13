use actix_web::{post, web, HttpRequest, HttpResponse};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::params;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::error::ApiError;
use crate::middleware::auth::{create_access_token, create_refresh_token, validate_token};
use crate::models::{
    AuthResponse, LoginRequest, MfaLoginChallengeResponse, MfaSetupConfirmRequest,
    MfaSetupResponse, MfaVerifyRequest, RefreshRequest, RegisterRequest,
};

type DbPool = web::Data<crate::db::DbPool>;

// ── Auth Handlers ──

/// POST /auth/register
///
/// Register a new server account. The client sends:
/// - blind_id: HMAC-SHA256 of email (same as desktop)
/// - auth_hash: Argon2id hash of the server password (computed client-side)
/// - auth_salt: base64-encoded salt used for Argon2id
///
/// Returns MFA setup data (TOTP secret + QR URI). No JWT is issued yet.
/// The client must call POST /auth/mfa/setup/confirm to complete registration.
#[post("/auth/register")]
pub async fn register(
    db: DbPool,
    config: web::Data<Config>,
    body: web::Json<RegisterRequest>,
) -> Result<HttpResponse, ApiError> {
    let conn = db
        .get()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Check if user already exists
    let exists: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM server_users WHERE blind_id = ?1",
        params![body.blind_id],
        |row| row.get(0),
    )?;

    if exists {
        return Err(ApiError::Conflict("Account already exists".to_string()));
    }

    // Decode auth_salt from base64
    let salt_bytes = base64::engine::general_purpose::STANDARD
        .decode(&body.auth_salt)
        .map_err(|_| ApiError::BadRequest("Invalid base64 salt".to_string()))?;

    // Store user
    conn.execute(
        "INSERT INTO server_users (blind_id, auth_hash, auth_salt) VALUES (?1, ?2, ?3)",
        params![body.blind_id, body.auth_hash, salt_bytes],
    )?;

    // Generate TOTP secret (20 bytes for SHA-1 HMAC)
    let totp_secret = generate_totp_secret();

    // Encrypt TOTP secret for at-rest storage
    let totp_secret_enc = encrypt_mfa_secret(&totp_secret, &config.mfa_encryption_key)?;

    // Store in mfa_secrets (not yet enabled)
    conn.execute(
        "INSERT INTO mfa_secrets (blind_id, totp_secret_enc, enabled) VALUES (?1, ?2, 0)",
        params![body.blind_id, totp_secret_enc],
    )?;

    // Generate MFA setup token
    let setup_token = uuid::Uuid::new_v4().to_string();
    let setup_token_hash = hash_token(&setup_token);
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
    conn.execute(
        "INSERT INTO mfa_tokens (token_hash, blind_id, token_type, expires_at) VALUES (?1, ?2, 'setup', ?3)",
        params![setup_token_hash, body.blind_id, expires_at.to_rfc3339()],
    )?;

    // Build otpauth URI
    let secret_b32 = base32_encode(&totp_secret);
    let blind_id_short = &body.blind_id[..8.min(body.blind_id.len())];
    let totp_uri = format!(
        "otpauth://totp/SaladVault:{}?secret={}&issuer=SaladVault&algorithm=SHA1&digits=6&period=30",
        blind_id_short, secret_b32
    );

    Ok(HttpResponse::Created().json(MfaSetupResponse {
        mfa_setup_token: setup_token,
        totp_secret_base32: secret_b32,
        totp_uri,
    }))
}

/// POST /auth/mfa/setup/confirm
///
/// Confirm MFA setup during registration. Validates the first TOTP code,
/// enables MFA, and issues JWT + refresh tokens.
#[post("/auth/mfa/setup/confirm")]
pub async fn mfa_setup_confirm(
    db: DbPool,
    config: web::Data<Config>,
    body: web::Json<MfaSetupConfirmRequest>,
) -> Result<HttpResponse, ApiError> {
    let conn = db
        .get()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let token_hash = hash_token(&body.mfa_setup_token);

    // Look up the setup token
    let (blind_id, expires_at_str, attempt_count): (String, String, i32) = conn
        .query_row(
            "SELECT blind_id, expires_at, attempt_count FROM mfa_tokens WHERE token_hash = ?1 AND token_type = 'setup'",
            params![token_hash],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| ApiError::Unauthorized("Invalid MFA token".to_string()))?;

    // Check expiry
    let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at_str)
        .map_err(|_| ApiError::Internal("Invalid expiry format".to_string()))?;
    if chrono::Utc::now() > expires_at {
        // Cleanup orphaned registration
        cleanup_orphan_registration(&conn, &token_hash, &blind_id)?;
        return Err(ApiError::Unauthorized("MFA setup expired".to_string()));
    }

    // Check rate limit (5 attempts max)
    if attempt_count >= 5 {
        cleanup_orphan_registration(&conn, &token_hash, &blind_id)?;
        return Err(ApiError::TooManyRequests("Too many attempts".to_string()));
    }

    // Load and decrypt TOTP secret
    let totp_secret_enc: Vec<u8> = conn
        .query_row(
            "SELECT totp_secret_enc FROM mfa_secrets WHERE blind_id = ?1",
            params![blind_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::Internal("MFA secret not found".to_string()))?;
    let totp_secret = decrypt_mfa_secret(&totp_secret_enc, &config.mfa_encryption_key)?;

    // Verify TOTP code
    if !verify_totp(&totp_secret, &body.totp_code, 1) {
        conn.execute(
            "UPDATE mfa_tokens SET attempt_count = attempt_count + 1 WHERE token_hash = ?1",
            params![token_hash],
        )?;
        return Err(ApiError::Unauthorized("Invalid TOTP code".to_string()));
    }

    // Success: enable MFA
    conn.execute(
        "UPDATE mfa_secrets SET enabled = 1 WHERE blind_id = ?1",
        params![blind_id],
    )?;

    // Delete the setup token
    conn.execute(
        "DELETE FROM mfa_tokens WHERE token_hash = ?1",
        params![token_hash],
    )?;

    // Issue JWT + refresh tokens
    let access_token = create_access_token(&blind_id, &config)?;
    let refresh_token = create_refresh_token();
    let refresh_hash = hash_token(&refresh_token);
    let rt_expires =
        chrono::Utc::now() + chrono::Duration::seconds(config.jwt_refresh_lifetime_secs);
    conn.execute(
        "INSERT INTO refresh_tokens (token_hash, blind_id, expires_at) VALUES (?1, ?2, ?3)",
        params![refresh_hash, blind_id, rt_expires.to_rfc3339()],
    )?;

    Ok(HttpResponse::Ok().json(AuthResponse {
        access_token,
        refresh_token,
    }))
}

/// POST /auth/login
///
/// Authenticate with blind_id + auth_hash.
/// Returns an MFA challenge token instead of JWT tokens.
/// The client must call POST /auth/mfa/verify to complete login.
#[post("/auth/login")]
pub async fn login(
    db: DbPool,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, ApiError> {
    let conn = db
        .get()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Fetch stored auth_hash
    let stored_hash: String = conn
        .query_row(
            "SELECT auth_hash FROM server_users WHERE blind_id = ?1",
            params![body.blind_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::Unauthorized("Invalid credentials".to_string()))?;

    // Constant-time comparison
    if !constant_time_eq(stored_hash.as_bytes(), body.auth_hash.as_bytes()) {
        return Err(ApiError::Unauthorized("Invalid credentials".to_string()));
    }

    // Update last_seen_at
    conn.execute(
        "UPDATE server_users SET last_seen_at = datetime('now') WHERE blind_id = ?1",
        params![body.blind_id],
    )?;

    // Generate MFA challenge token
    let challenge_token = uuid::Uuid::new_v4().to_string();
    let challenge_hash = hash_token(&challenge_token);
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);

    // Clean up any existing challenge tokens for this user
    conn.execute(
        "DELETE FROM mfa_tokens WHERE blind_id = ?1 AND token_type = 'challenge'",
        params![body.blind_id],
    )?;

    conn.execute(
        "INSERT INTO mfa_tokens (token_hash, blind_id, token_type, expires_at) VALUES (?1, ?2, 'challenge', ?3)",
        params![challenge_hash, body.blind_id, expires_at.to_rfc3339()],
    )?;

    Ok(HttpResponse::Ok().json(MfaLoginChallengeResponse {
        mfa_challenge_token: challenge_token,
    }))
}

/// POST /auth/mfa/verify
///
/// Verify TOTP code during login. Issues JWT + refresh tokens on success.
#[post("/auth/mfa/verify")]
pub async fn mfa_verify(
    db: DbPool,
    config: web::Data<Config>,
    body: web::Json<MfaVerifyRequest>,
) -> Result<HttpResponse, ApiError> {
    let conn = db
        .get()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let token_hash = hash_token(&body.mfa_challenge_token);

    // Look up challenge token
    let (blind_id, expires_at_str, attempt_count): (String, String, i32) = conn
        .query_row(
            "SELECT blind_id, expires_at, attempt_count FROM mfa_tokens WHERE token_hash = ?1 AND token_type = 'challenge'",
            params![token_hash],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| ApiError::Unauthorized("Invalid MFA token".to_string()))?;

    // Check expiry
    let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at_str)
        .map_err(|_| ApiError::Internal("Invalid expiry format".to_string()))?;
    if chrono::Utc::now() > expires_at {
        conn.execute(
            "DELETE FROM mfa_tokens WHERE token_hash = ?1",
            params![token_hash],
        )?;
        return Err(ApiError::Unauthorized("MFA challenge expired".to_string()));
    }

    // Rate limit: 5 attempts
    if attempt_count >= 5 {
        conn.execute(
            "DELETE FROM mfa_tokens WHERE token_hash = ?1",
            params![token_hash],
        )?;
        return Err(ApiError::TooManyRequests("Too many attempts".to_string()));
    }

    // Load TOTP secret
    let totp_secret_enc: Vec<u8> = conn
        .query_row(
            "SELECT totp_secret_enc FROM mfa_secrets WHERE blind_id = ?1 AND enabled = 1",
            params![blind_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::Internal("MFA not configured".to_string()))?;
    let totp_secret = decrypt_mfa_secret(&totp_secret_enc, &config.mfa_encryption_key)?;

    // Verify TOTP
    if !verify_totp(&totp_secret, &body.totp_code, 1) {
        conn.execute(
            "UPDATE mfa_tokens SET attempt_count = attempt_count + 1 WHERE token_hash = ?1",
            params![token_hash],
        )?;
        return Err(ApiError::Unauthorized("Invalid TOTP code".to_string()));
    }

    // Success: delete challenge token
    conn.execute(
        "DELETE FROM mfa_tokens WHERE token_hash = ?1",
        params![token_hash],
    )?;

    // Issue tokens
    let access_token = create_access_token(&blind_id, &config)?;
    let refresh_token = create_refresh_token();
    let refresh_hash = hash_token(&refresh_token);
    let rt_expires =
        chrono::Utc::now() + chrono::Duration::seconds(config.jwt_refresh_lifetime_secs);
    conn.execute(
        "INSERT INTO refresh_tokens (token_hash, blind_id, expires_at) VALUES (?1, ?2, ?3)",
        params![refresh_hash, blind_id, rt_expires.to_rfc3339()],
    )?;

    Ok(HttpResponse::Ok().json(AuthResponse {
        access_token,
        refresh_token,
    }))
}

/// POST /auth/refresh
///
/// Exchange a valid refresh token for a new access + refresh token pair.
/// The old refresh token is invalidated (rotation).
#[post("/auth/refresh")]
pub async fn refresh(
    db: DbPool,
    config: web::Data<Config>,
    body: web::Json<RefreshRequest>,
) -> Result<HttpResponse, ApiError> {
    let conn = db
        .get()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let refresh_hash = hash_token(&body.refresh_token);

    // Look up the refresh token
    let (blind_id, expires_at_str): (String, String) = conn
        .query_row(
            "SELECT blind_id, expires_at FROM refresh_tokens WHERE token_hash = ?1",
            params![refresh_hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| ApiError::Unauthorized("Invalid refresh token".to_string()))?;

    // Check expiry
    let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at_str)
        .map_err(|_| ApiError::Internal("Invalid expiry format".to_string()))?;
    if chrono::Utc::now() > expires_at {
        conn.execute(
            "DELETE FROM refresh_tokens WHERE token_hash = ?1",
            params![refresh_hash],
        )?;
        return Err(ApiError::Unauthorized("Refresh token expired".to_string()));
    }

    // Rotate: delete old, create new
    conn.execute(
        "DELETE FROM refresh_tokens WHERE token_hash = ?1",
        params![refresh_hash],
    )?;

    let access_token = create_access_token(&blind_id, &config)?;
    let new_refresh = create_refresh_token();
    let new_hash = hash_token(&new_refresh);
    let new_expires = chrono::Utc::now()
        + chrono::Duration::seconds(config.jwt_refresh_lifetime_secs);

    conn.execute(
        "INSERT INTO refresh_tokens (token_hash, blind_id, expires_at) VALUES (?1, ?2, ?3)",
        params![new_hash, blind_id, new_expires.to_rfc3339()],
    )?;

    Ok(HttpResponse::Ok().json(AuthResponse {
        access_token,
        refresh_token: new_refresh,
    }))
}

/// POST /auth/logout
///
/// Invalidate all refresh tokens for the current user.
/// Requires a valid JWT.
#[post("/auth/logout")]
pub async fn logout(
    db: DbPool,
    config: web::Data<Config>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let blind_id = extract_blind_id_from_request(&req, &config)?;

    let conn = db
        .get()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    conn.execute(
        "DELETE FROM refresh_tokens WHERE blind_id = ?1",
        params![blind_id],
    )?;

    Ok(HttpResponse::NoContent().finish())
}

/// GET /auth/salt/{blind_id}
///
/// Return the auth_salt for a given blind_id so the client can
/// derive the auth_hash before calling /auth/login.
#[actix_web::get("/auth/salt/{blind_id}")]
pub async fn get_salt(
    db: DbPool,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let blind_id = path.into_inner();
    let conn = db
        .get()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let salt_bytes: Vec<u8> = conn
        .query_row(
            "SELECT auth_salt FROM server_users WHERE blind_id = ?1",
            params![blind_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::NotFound("User not found".to_string()))?;

    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(&salt_bytes);

    Ok(HttpResponse::Ok().json(serde_json::json!({ "auth_salt": salt_b64 })))
}

// ── Helpers ──

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract blind_id from JWT in Authorization header.
pub fn extract_blind_id_from_request(
    req: &HttpRequest,
    config: &Config,
) -> Result<String, ApiError> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::Unauthorized("Invalid Authorization format".to_string()))?;

    let claims = validate_token(token, config)?;
    Ok(claims.sub)
}

// ── TOTP Helpers ──

/// Generate a 20-byte random TOTP secret (SHA-1 HMAC key size).
fn generate_totp_secret() -> [u8; 20] {
    let mut secret = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut secret);
    secret
}

/// Base32-encode bytes (RFC 4648, no padding, uppercase).
fn base32_encode(data: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(data)
}

/// Encrypt TOTP secret for at-rest storage using AES-256-GCM.
/// Returns: [12 bytes nonce][ciphertext + auth tag]
fn encrypt_mfa_secret(secret: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, ApiError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| ApiError::Internal(format!("AES init error: {e}")))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, secret)
        .map_err(|e| ApiError::Internal(format!("AES encrypt error: {e}")))?;

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt TOTP secret from at-rest storage.
fn decrypt_mfa_secret(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, ApiError> {
    if data.len() < 13 {
        return Err(ApiError::Internal("Invalid MFA secret data".to_string()));
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| ApiError::Internal(format!("AES init error: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| ApiError::Internal("MFA secret decryption failed".to_string()))
}

/// Verify a TOTP code with the given skew tolerance.
/// Checks current time step and ±skew steps.
fn verify_totp(secret: &[u8], code: &str, skew: u64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let current_step = now / 30;

    for step in (current_step.saturating_sub(skew))..=(current_step + skew) {
        let expected = generate_totp_code(secret, step);
        if constant_time_eq(expected.as_bytes(), code.as_bytes()) {
            return true;
        }
    }
    false
}

/// Generate a 6-digit TOTP code for a given time step (RFC 6238 / RFC 4226).
fn generate_totp_code(secret: &[u8], step: u64) -> String {
    let step_bytes = step.to_be_bytes();
    let mut mac =
        <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC-SHA1 accepts any key length");
    mac.update(&step_bytes);
    let result = mac.finalize().into_bytes();

    let offset = (result[19] & 0x0f) as usize;
    let code = ((result[offset] as u32 & 0x7f) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);
    let code = code % 1_000_000;
    format!("{:06}", code)
}

/// Cleanup an orphaned registration (user + mfa_secret + mfa_token).
fn cleanup_orphan_registration(
    conn: &rusqlite::Connection,
    token_hash: &str,
    blind_id: &str,
) -> Result<(), ApiError> {
    conn.execute(
        "DELETE FROM mfa_tokens WHERE token_hash = ?1",
        params![token_hash],
    )?;
    conn.execute(
        "DELETE FROM mfa_secrets WHERE blind_id = ?1",
        params![blind_id],
    )?;
    conn.execute(
        "DELETE FROM server_users WHERE blind_id = ?1",
        params![blind_id],
    )?;
    Ok(())
}

/// Cleanup orphaned registrations (called periodically from background task).
/// Deletes users whose MFA was never enabled and whose setup token has expired.
pub fn cleanup_orphan_registrations(
    pool: &crate::db::DbPool,
) {
    let Ok(conn) = pool.get() else { return };
    let result = conn.execute_batch(
        "DELETE FROM server_users WHERE blind_id IN (
            SELECT ms.blind_id FROM mfa_secrets ms
            LEFT JOIN mfa_tokens mt ON ms.blind_id = mt.blind_id AND mt.token_type = 'setup'
            WHERE ms.enabled = 0
            AND (mt.token_hash IS NULL OR mt.expires_at < datetime('now'))
        );
        DELETE FROM mfa_tokens WHERE expires_at < datetime('now');",
    );
    if let Err(e) = result {
        log::error!("Failed to cleanup orphan registrations: {e}");
    }
}
