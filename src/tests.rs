//! Integration tests for the SaladVault API.
//!
//! Uses actix_web::test with an in-memory SQLite database.
//! Tests the full flow: health → register → MFA confirm → login → sync.

use std::sync::Mutex;

use actix_web::{test, web, App};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::config::Config;
use crate::db;
use crate::routes;

/// Build a test config with known secrets.
fn test_config() -> Config {
    Config {
        host: "127.0.0.1".to_string(),
        port: 3001,
        db_path: std::path::PathBuf::from(":memory:"),
        jwt_secret: "test_jwt_secret_for_integration_tests".to_string(),
        jwt_access_lifetime_secs: 900,
        jwt_refresh_lifetime_secs: 2_592_000,
        smtp_host: String::new(),
        smtp_port: 587,
        smtp_user: String::new(),
        smtp_pass: String::new(),
        smtp_from: "test@saladvault.com".to_string(),
        mfa_encryption_key: [0x42u8; 32],
    }
}

/// Generate a 6-digit TOTP code for a given secret and time step (RFC 6238).
fn generate_test_totp(secret: &[u8], step: u64) -> String {
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
    format!("{:06}", code % 1_000_000)
}

/// Decrypt a TOTP secret encrypted with AES-256-GCM (same as handlers::auth).
fn decrypt_totp_secret(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).unwrap()
}

// ── Tests ──

#[actix_web::test]
async fn test_health_endpoint() {
    let conn = db::open_database_in_memory().unwrap();
    let db_data = web::Data::new(Mutex::new(conn));
    let config_data = web::Data::new(test_config());
    let app = test::init_service(
        App::new()
            .app_data(db_data)
            .app_data(config_data)
            .configure(routes::configure),
    )
    .await;

    let req = test::TestRequest::get().uri("/health").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
}

#[actix_web::test]
async fn test_register_duplicate_rejected() {
    let conn = db::open_database_in_memory().unwrap();
    let db_data = web::Data::new(Mutex::new(conn));
    let config_data = web::Data::new(test_config());
    let app = test::init_service(
        App::new()
            .app_data(db_data)
            .app_data(config_data)
            .configure(routes::configure),
    )
    .await;

    let b64 = base64::engine::general_purpose::STANDARD;
    let salt = b64.encode([0u8; 32]);

    let register_body = serde_json::json!({
        "blind_id": "test_blind_id_001",
        "auth_hash": "fakehash123",
        "auth_salt": salt,
    });

    // First registration should succeed (201)
    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(&register_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);

    // Second registration with same blind_id should fail (409 Conflict)
    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(&register_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 409);
}

#[actix_web::test]
async fn test_full_register_mfa_login_sync_flow() {
    let conn = db::open_database_in_memory().expect("Failed to open in-memory database");
    let db_data = web::Data::new(Mutex::new(conn));
    let config = test_config();
    let config_data = web::Data::new(config.clone());

    let app = test::init_service(
        App::new()
            .app_data(db_data.clone())
            .app_data(config_data)
            .configure(routes::configure),
    )
    .await;

    let b64 = base64::engine::general_purpose::STANDARD;
    let salt = b64.encode([0u8; 32]);
    let blind_id = "full_flow_test_blind_id";

    // ── Step 1: Register ──
    let req = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(serde_json::json!({
            "blind_id": blind_id,
            "auth_hash": "argon2_hash_placeholder",
            "auth_salt": salt,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let mfa_setup_token = body["mfa_setup_token"].as_str().unwrap().to_string();

    // ── Step 2: Retrieve TOTP secret from DB and generate valid code ──
    let totp_secret = {
        let conn = db_data.lock().unwrap();
        let enc: Vec<u8> = conn
            .query_row(
                "SELECT totp_secret_enc FROM mfa_secrets WHERE blind_id = ?1",
                rusqlite::params![blind_id],
                |row| row.get(0),
            )
            .unwrap();
        decrypt_totp_secret(&enc, &config.mfa_encryption_key)
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let totp_code = generate_test_totp(&totp_secret, now / 30);

    // ── Step 3: Confirm MFA setup ──
    let req = test::TestRequest::post()
        .uri("/auth/mfa/setup/confirm")
        .set_json(serde_json::json!({
            "mfa_setup_token": mfa_setup_token,
            "totp_code": totp_code,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let _initial_access = body["access_token"].as_str().unwrap().to_string();
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    // ── Step 4: Login (step 1 — get MFA challenge) ──
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "blind_id": blind_id,
            "auth_hash": "argon2_hash_placeholder",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let mfa_challenge_token = body["mfa_challenge_token"].as_str().unwrap().to_string();

    // ── Step 5: Verify MFA to complete login ──
    let totp_code = generate_test_totp(&totp_secret, now / 30);
    let req = test::TestRequest::post()
        .uri("/auth/mfa/verify")
        .set_json(serde_json::json!({
            "mfa_challenge_token": mfa_challenge_token,
            "totp_code": totp_code,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let access_token = body["access_token"].as_str().unwrap().to_string();

    // ── Step 6: Sync — push a vault blob ──
    let vault_data = b64.encode(b"encrypted_vault_data_here");
    let req = test::TestRequest::put()
        .uri("/sync/vault")
        .insert_header(("Authorization", format!("Bearer {access_token}")))
        .set_json(serde_json::json!({
            "vault_blob": vault_data,
            "version": 1,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["version"], 1);

    // ── Step 7: Sync — pull the vault back ──
    let req = test::TestRequest::get()
        .uri("/sync/vault")
        .insert_header(("Authorization", format!("Bearer {access_token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["vault_blob"], vault_data);
    assert_eq!(body["version"], 1);

    // ── Step 8: Sync status ──
    let req = test::TestRequest::get()
        .uri("/sync/status")
        .insert_header(("Authorization", format!("Bearer {access_token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["version"], 1);

    // ── Step 9: Refresh token ──
    let req = test::TestRequest::post()
        .uri("/auth/refresh")
        .set_json(serde_json::json!({
            "refresh_token": refresh_token,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    // ── Step 10: Logout ──
    let req = test::TestRequest::post()
        .uri("/auth/logout")
        .insert_header(("Authorization", format!("Bearer {access_token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 204);
}

#[actix_web::test]
async fn test_sync_without_auth_rejected() {
    let conn = db::open_database_in_memory().unwrap();
    let db_data = web::Data::new(Mutex::new(conn));
    let config_data = web::Data::new(test_config());
    let app = test::init_service(
        App::new()
            .app_data(db_data)
            .app_data(config_data)
            .configure(routes::configure),
    )
    .await;

    // No Authorization header → should fail
    let req = test::TestRequest::get().uri("/sync/vault").to_request();
    let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_login_nonexistent_user_rejected() {
    let conn = db::open_database_in_memory().unwrap();
    let db_data = web::Data::new(Mutex::new(conn));
    let config_data = web::Data::new(test_config());
    let app = test::init_service(
        App::new()
            .app_data(db_data)
            .app_data(config_data)
            .configure(routes::configure),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "blind_id": "nonexistent_user",
            "auth_hash": "fakehash",
        }))
        .to_request();
    let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}
