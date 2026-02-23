use serde::{Deserialize, Serialize};

// ── Auth ──

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub blind_id: String,
    pub auth_hash: String,
    pub auth_salt: String, // base64-encoded
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub blind_id: String,
    pub auth_hash: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

// ── JWT Claims ──

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // blind_id
    pub exp: i64,    // expiration timestamp
    pub iat: i64,    // issued at
}

// ── Sync ──

#[derive(Debug, Deserialize)]
pub struct SyncPushRequest {
    pub vault_blob: String, // base64-encoded encrypted blob
    pub version: i64,
}

#[derive(Debug, Serialize)]
pub struct SyncVaultResponse {
    pub vault_blob: String, // base64-encoded
    pub version: i64,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct SyncStatusResponse {
    pub version: i64,
    pub updated_at: String,
}

// ── Dead Man's Switch ──

#[derive(Debug, Deserialize)]
pub struct DeadmanConfigRequest {
    pub enabled: bool,
    pub inactivity_days: u32,
    pub recipient_email: String,
    pub recovery_blob_enc: Option<String>, // base64-encoded
}

#[derive(Debug, Serialize)]
pub struct DeadmanStatusResponse {
    pub enabled: bool,
    pub inactivity_days: u32,
    pub last_seen_at: String,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    pub last_seen_at: String,
}

// ── MFA ──

#[derive(Debug, Serialize)]
pub struct MfaSetupResponse {
    pub mfa_setup_token: String,
    pub totp_secret_base32: String,
    pub totp_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct MfaSetupConfirmRequest {
    pub mfa_setup_token: String,
    pub totp_code: String,
}

#[derive(Debug, Serialize)]
pub struct MfaLoginChallengeResponse {
    pub mfa_challenge_token: String,
}

#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    pub mfa_challenge_token: String,
    pub totp_code: String,
}
