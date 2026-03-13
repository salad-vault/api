use jsonwebtoken::{decode, DecodingKey, Validation};

use crate::config::Config;
use crate::error::ApiError;
use crate::models::Claims;

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
