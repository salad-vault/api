use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use jsonwebtoken::{decode, DecodingKey, Validation};

use crate::config::Config;
use crate::error::ApiError;
use crate::models::Claims;

/// Extract and validate JWT from the Authorization header.
/// Returns the blind_id (subject) on success.
pub fn extract_jwt(req: &ServiceRequest, config: &Config) -> Result<String, ApiError> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::Unauthorized("Invalid Authorization format".to_string()))?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &Validation::default(),
    )?;

    Ok(token_data.claims.sub)
}

/// Helper to extract blind_id from a validated JWT in request extensions.
/// Handlers call this after the JWT has been validated.
pub fn get_blind_id(req: &actix_web::HttpRequest) -> Result<String, Error> {
    req.extensions()
        .get::<String>()
        .cloned()
        .ok_or_else(|| {
            actix_web::error::ErrorUnauthorized("Missing authentication")
        })
}

/// Validate a JWT token string directly and return Claims.
pub fn validate_token(token: &str, config: &Config) -> Result<Claims, ApiError> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

/// Create an access token for a given blind_id.
pub fn create_access_token(blind_id: &str, config: &Config) -> Result<String, ApiError> {
    let now = chrono::Utc::now().timestamp();
    let claims = Claims {
        sub: blind_id.to_string(),
        iat: now,
        exp: now + config.jwt_access_lifetime_secs,
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(token)
}

/// Create a refresh token (random UUID).
pub fn create_refresh_token() -> String {
    uuid::Uuid::new_v4().to_string()
}
