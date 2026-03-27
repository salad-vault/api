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
    AuthResponse, DeleteAccountRequest, DeleteAccountResponse, LoginRequest,
    MfaLoginChallengeResponse, MfaSetupConfirmRequest, MfaSetupResponse, MfaVerifyRequest,
    RefreshRequest, RegisterRequest, SendVerificationCodeRequest, SendVerificationCodeResponse,
    VerifyCodeRequest, VerifyCodeResponse,
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

    // Check email verification
    let verified: bool = conn
        .query_row(
            "SELECT verified FROM email_verifications WHERE blind_id = ?1",
            params![body.blind_id],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if !verified {
        return Err(ApiError::BadRequest("Email not verified".to_string()));
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

    // Clean up email verification record
    conn.execute(
        "DELETE FROM email_verifications WHERE blind_id = ?1",
        params![body.blind_id],
    )?;

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

// ── Account Deletion ──

/// POST /auth/account/delete
///
/// Delete the authenticated user's account. Requires a valid TOTP code.
/// Cancels any active Stripe subscription (best-effort) and deletes all
/// user data from the database (cascading FKs handle related tables).
#[post("/auth/account/delete")]
pub async fn delete_account(
    db: DbPool,
    config: web::Data<Config>,
    req: HttpRequest,
    body: web::Json<DeleteAccountRequest>,
) -> Result<HttpResponse, ApiError> {
    let blind_id = extract_blind_id_from_request(&req, &config)?;

    let conn = db
        .get()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Load and decrypt TOTP secret
    let totp_secret_enc: Vec<u8> = conn
        .query_row(
            "SELECT totp_secret_enc FROM mfa_secrets WHERE blind_id = ?1 AND enabled = 1",
            params![blind_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::Unauthorized("Invalid credentials".to_string()))?;
    let totp_secret = decrypt_mfa_secret(&totp_secret_enc, &config.mfa_encryption_key)?;

    // Verify TOTP code
    if !verify_totp(&totp_secret, &body.totp_code, 1) {
        return Err(ApiError::Unauthorized("Invalid credentials".to_string()));
    }

    // Cancel Stripe subscription if active (best-effort)
    if !config.stripe_secret_key.is_empty() {
        let stripe_data: Option<(String, Option<String>)> = conn
            .query_row(
                "SELECT stripe_customer_id, stripe_subscription_id FROM subscriptions WHERE blind_id = ?1",
                params![blind_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        if let Some((customer_id, sub_id)) = stripe_data {
            let client = reqwest::Client::new();

            // Cancel subscription if exists
            if let Some(ref sid) = sub_id {
                if !sid.is_empty() {
                    let _ = client
                        .delete(format!("https://api.stripe.com/v1/subscriptions/{sid}"))
                        .header("Authorization", format!("Bearer {}", config.stripe_secret_key))
                        .send()
                        .await;
                }
            }

            // Delete Stripe customer
            if !customer_id.is_empty() {
                let _ = client
                    .delete(format!("https://api.stripe.com/v1/customers/{customer_id}"))
                    .header("Authorization", format!("Bearer {}", config.stripe_secret_key))
                    .send()
                    .await;
            }
        }
    }

    // Delete user — CASCADE handles all related tables
    conn.execute(
        "DELETE FROM server_users WHERE blind_id = ?1",
        params![blind_id],
    )?;

    log::info!("Account deleted: blind_id={}", &blind_id[..8.min(blind_id.len())]);

    Ok(HttpResponse::Ok().json(DeleteAccountResponse { deleted: true }))
}

// ── Email Verification ──

/// POST /auth/email/send-code
///
/// Send a 6-digit verification code to the provided email address.
/// The email is used only for sending and is NOT stored in the database.
/// This is the only controlled exception to zero-knowledge, during registration only.
#[post("/auth/email/send-code")]
pub async fn send_verification_code(
    db: DbPool,
    config: web::Data<Config>,
    body: web::Json<SendVerificationCodeRequest>,
) -> Result<HttpResponse, ApiError> {
    // Basic email format validation
    if !body.email.contains('@') || body.email.len() < 5 {
        return Err(ApiError::BadRequest("Invalid email format".to_string()));
    }

    let conn = db
        .get()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Rate limit: max one code per blind_id per 60 seconds
    let recent: bool = conn
        .query_row(
            "SELECT created_at > datetime('now', '-60 seconds') FROM email_verifications WHERE blind_id = ?1",
            params![body.blind_id],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if recent {
        return Err(ApiError::TooManyRequests(
            "Please wait before requesting a new code".to_string(),
        ));
    }

    // Generate 6-digit code
    let code = {
        use rand::Rng;
        rand::thread_rng().gen_range(100_000..=999_999).to_string()
    };
    let code_hash = hash_token(&code);
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);

    // Upsert verification record
    conn.execute(
        "INSERT INTO email_verifications (blind_id, code_hash, expires_at, verified, attempt_count)
         VALUES (?1, ?2, ?3, 0, 0)
         ON CONFLICT(blind_id) DO UPDATE SET
            code_hash = excluded.code_hash,
            expires_at = excluded.expires_at,
            verified = 0,
            attempt_count = 0,
            created_at = datetime('now')",
        params![body.blind_id, code_hash, expires_at.to_rfc3339()],
    )?;

    // Send email via SMTP — the email address is NOT stored, only used for sending
    send_verification_email(&config, &body.email, &code).await?;

    Ok(HttpResponse::Ok().json(SendVerificationCodeResponse { sent: true }))
}

/// POST /auth/email/verify-code
///
/// Verify a 6-digit code previously sent via send-code.
/// On success, marks the blind_id as verified (required before /auth/register).
#[post("/auth/email/verify-code")]
pub async fn verify_code(
    db: DbPool,
    body: web::Json<VerifyCodeRequest>,
) -> Result<HttpResponse, ApiError> {
    let conn = db
        .get()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Look up verification record
    let (code_hash, expires_at_str, attempt_count, verified): (String, String, i32, bool) = conn
        .query_row(
            "SELECT code_hash, expires_at, attempt_count, verified FROM email_verifications WHERE blind_id = ?1",
            params![body.blind_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| ApiError::BadRequest("No verification pending".to_string()))?;

    // Already verified
    if verified {
        return Ok(HttpResponse::Ok().json(VerifyCodeResponse { verified: true }));
    }

    // Check expiry
    let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at_str)
        .map_err(|_| ApiError::Internal("Invalid expiry format".to_string()))?;
    if chrono::Utc::now() > expires_at {
        conn.execute(
            "DELETE FROM email_verifications WHERE blind_id = ?1",
            params![body.blind_id],
        )?;
        return Err(ApiError::Unauthorized("Verification code expired".to_string()));
    }

    // Rate limit: 5 attempts
    if attempt_count >= 5 {
        conn.execute(
            "DELETE FROM email_verifications WHERE blind_id = ?1",
            params![body.blind_id],
        )?;
        return Err(ApiError::TooManyRequests("Too many attempts".to_string()));
    }

    // Verify code (constant-time comparison)
    let provided_hash = hash_token(&body.code);
    if !constant_time_eq(provided_hash.as_bytes(), code_hash.as_bytes()) {
        conn.execute(
            "UPDATE email_verifications SET attempt_count = attempt_count + 1 WHERE blind_id = ?1",
            params![body.blind_id],
        )?;
        return Err(ApiError::Unauthorized("Invalid verification code".to_string()));
    }

    // Mark as verified
    conn.execute(
        "UPDATE email_verifications SET verified = 1 WHERE blind_id = ?1",
        params![body.blind_id],
    )?;

    Ok(HttpResponse::Ok().json(VerifyCodeResponse { verified: true }))
}

/// Send a verification email with a 6-digit code via SMTP.
async fn send_verification_email(config: &Config, recipient: &str, code: &str) -> Result<(), ApiError> {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    let email = Message::builder()
        .from(
            config
                .smtp_from
                .parse()
                .map_err(|_| ApiError::Internal("Invalid SMTP_FROM address".to_string()))?,
        )
        .to(recipient
            .parse()
            .map_err(|_| ApiError::BadRequest("Invalid recipient email".to_string()))?)
        .subject("SaladVault - Code de vérification")
        .header(ContentType::TEXT_PLAIN)
        .body(format!(
            "Votre code de vérification SaladVault : {code}\n\nCe code expire dans 5 minutes.\nSi vous n'avez pas demandé ce code, ignorez cet email."
        ))
        .map_err(|e| ApiError::Internal(format!("Failed to build email: {e}")))?;

    let creds = Credentials::new(config.smtp_user.clone(), config.smtp_pass.clone());

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
        .map_err(|e| ApiError::Internal(format!("SMTP relay error: {e}")))?
        .port(config.smtp_port)
        .credentials(creds)
        .build();

    mailer
        .send(email)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to send verification email: {e}")))?;

    Ok(())
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
        DELETE FROM mfa_tokens WHERE expires_at < datetime('now');
        DELETE FROM email_verifications WHERE expires_at < datetime('now') AND verified = 0;",
    );
    if let Err(e) = result {
        log::error!("Failed to cleanup orphan registrations: {e}");
    }
}
