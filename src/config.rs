use std::path::PathBuf;

/// Server configuration loaded from environment variables.
#[derive(Clone)]
pub struct Config {
    /// Server listen address (e.g. "127.0.0.1")
    pub host: String,
    /// Server listen port (e.g. 8080)
    pub port: u16,
    /// Path to the SQLite database file
    pub db_path: PathBuf,
    /// Secret key for signing JWT tokens
    pub jwt_secret: String,
    /// JWT access token lifetime in seconds (default: 900 = 15 min)
    pub jwt_access_lifetime_secs: i64,
    /// JWT refresh token lifetime in seconds (default: 2592000 = 30 days)
    pub jwt_refresh_lifetime_secs: i64,
    /// SMTP server host for Dead Man's Switch emails
    pub smtp_host: String,
    /// SMTP server port
    pub smtp_port: u16,
    /// SMTP username
    pub smtp_user: String,
    /// SMTP password
    pub smtp_pass: String,
    /// Sender email address
    pub smtp_from: String,
    /// 32-byte key for encrypting TOTP secrets at rest (hex-encoded in env)
    pub mfa_encryption_key: [u8; 32],
}

impl Config {
    /// Load configuration from environment variables (with defaults).
    pub fn from_env() -> Self {
        Self {
            host: std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: std::env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3001),
            db_path: PathBuf::from(
                std::env::var("DATABASE_PATH").unwrap_or_else(|_| "saladvault_server.db".to_string()),
            ),
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "CHANGE_THIS_JWT_SECRET_IN_PRODUCTION".to_string()),
            jwt_access_lifetime_secs: std::env::var("JWT_ACCESS_LIFETIME")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(900),
            jwt_refresh_lifetime_secs: std::env::var("JWT_REFRESH_LIFETIME")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2_592_000),
            smtp_host: std::env::var("SMTP_HOST").unwrap_or_default(),
            smtp_port: std::env::var("SMTP_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(587),
            smtp_user: std::env::var("SMTP_USER").unwrap_or_default(),
            smtp_pass: std::env::var("SMTP_PASS").unwrap_or_default(),
            smtp_from: std::env::var("SMTP_FROM")
                .unwrap_or_else(|_| "noreply@saladvault.com".to_string()),
            mfa_encryption_key: {
                let key_hex = std::env::var("MFA_ENCRYPTION_KEY").unwrap_or_else(|_| {
                    "0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string()
                });
                let bytes = hex::decode(&key_hex).expect(
                    "MFA_ENCRYPTION_KEY must be hex-encoded (64 hex chars = 32 bytes). \
                     Generate one with: openssl rand -hex 32"
                );
                bytes
                    .try_into()
                    .expect(
                        "MFA_ENCRYPTION_KEY must be exactly 32 bytes (64 hex chars). \
                         Generate one with: openssl rand -hex 32"
                    )
            },
        }
    }
}
