use actix_web::{get, post, put, web, HttpRequest, HttpResponse};
use base64::Engine;
use rusqlite::params;

use crate::config::Config;
use crate::error::ApiError;
use crate::handlers::auth::extract_blind_id_from_request;
use crate::models::{DeadmanConfigRequest, DeadmanStatusResponse, HeartbeatResponse};

type DbPool = web::Data<std::sync::Mutex<rusqlite::Connection>>;

/// POST /deadman/heartbeat
///
/// Update the user's last_seen_at timestamp.
/// Called by the desktop client after each unlock or periodically.
#[post("/deadman/heartbeat")]
pub async fn heartbeat(
    db: DbPool,
    config: web::Data<Config>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let blind_id = extract_blind_id_from_request(&req, &config)?;

    let conn = db
        .lock()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    conn.execute(
        "UPDATE server_users SET last_seen_at = datetime('now') WHERE blind_id = ?1",
        params![blind_id],
    )?;

    let last_seen_at: String = conn
        .query_row(
            "SELECT last_seen_at FROM server_users WHERE blind_id = ?1",
            params![blind_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::NotFound("User not found".to_string()))?;

    Ok(HttpResponse::Ok().json(HeartbeatResponse { last_seen_at }))
}

/// GET /deadman/status
///
/// Return the Dead Man's Switch status for the authenticated user.
#[get("/deadman/status")]
pub async fn status(
    db: DbPool,
    config: web::Data<Config>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let blind_id = extract_blind_id_from_request(&req, &config)?;

    let conn = db
        .lock()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let last_seen_at: String = conn
        .query_row(
            "SELECT last_seen_at FROM server_users WHERE blind_id = ?1",
            params![blind_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::NotFound("User not found".to_string()))?;

    // Check if deadman config exists
    let dm_config: Option<(bool, u32)> = conn
        .query_row(
            "SELECT enabled, inactivity_days FROM deadman_config WHERE blind_id = ?1",
            params![blind_id],
            |row| {
                let enabled: bool = row.get(0)?;
                let days: u32 = row.get(1)?;
                Ok((enabled, days))
            },
        )
        .ok();

    let (enabled, inactivity_days) = dm_config.unwrap_or((false, 90));

    Ok(HttpResponse::Ok().json(DeadmanStatusResponse {
        enabled,
        inactivity_days,
        last_seen_at,
    }))
}

/// PUT /deadman/config
///
/// Update the Dead Man's Switch configuration.
/// The recipient_email is stored in plain text (MVP compromise —
/// it's the contact's email, not the user's).
/// The recovery_blob_enc is an opaque encrypted blob the server
/// cannot read.
#[put("/deadman/config")]
pub async fn update_config(
    db: DbPool,
    config: web::Data<Config>,
    req: HttpRequest,
    body: web::Json<DeadmanConfigRequest>,
) -> Result<HttpResponse, ApiError> {
    let blind_id = extract_blind_id_from_request(&req, &config)?;

    let recovery_blob: Option<Vec<u8>> = body
        .recovery_blob_enc
        .as_ref()
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok());

    let conn = db
        .lock()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    conn.execute(
        "INSERT INTO deadman_config (blind_id, enabled, inactivity_days, recipient_email, recovery_blob_enc)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(blind_id) DO UPDATE SET
            enabled = excluded.enabled,
            inactivity_days = excluded.inactivity_days,
            recipient_email = excluded.recipient_email,
            recovery_blob_enc = excluded.recovery_blob_enc,
            triggered = 0",
        params![
            blind_id,
            body.enabled,
            body.inactivity_days,
            body.recipient_email,
            recovery_blob,
        ],
    )?;

    Ok(HttpResponse::Ok().finish())
}

/// Check all Dead Man's Switch configurations and send emails
/// for users who exceeded their inactivity threshold.
///
/// This function is meant to be called periodically (e.g. every hour)
/// from a background task spawned at server startup.
pub async fn check_deadman_triggers(
    db: &std::sync::Mutex<rusqlite::Connection>,
    config: &Config,
) {
    let results = {
        let conn = match db.lock() {
            Ok(c) => c,
            Err(_) => return,
        };

        let mut stmt = match conn.prepare(
            "SELECT dc.blind_id, dc.inactivity_days, dc.recipient_email, dc.recovery_blob_enc,
                    su.last_seen_at
             FROM deadman_config dc
             JOIN server_users su ON su.blind_id = dc.blind_id
             WHERE dc.enabled = 1
               AND dc.triggered = 0
               AND dc.recipient_email != ''
               AND dc.recovery_blob_enc IS NOT NULL",
        ) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Dead Man's Switch query error: {e}");
                return;
            }
        };

        let rows: Vec<(String, u32, String, Vec<u8>, String)> = match stmt.query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        }) {
            Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                log::error!("Dead Man's Switch row iteration error: {e}");
                return;
            }
        };

        rows
    };

    for (blind_id, inactivity_days, recipient_email, recovery_blob, last_seen_at) in results {
        // Parse last_seen_at
        let last_seen = match chrono::NaiveDateTime::parse_from_str(&last_seen_at, "%Y-%m-%d %H:%M:%S") {
            Ok(dt) => dt.and_utc(),
            Err(_) => continue,
        };

        let threshold = chrono::Utc::now()
            - chrono::Duration::days(inactivity_days as i64);

        if last_seen < threshold {
            log::warn!(
                "Dead Man's Switch triggered for user {blind_id} (last seen: {last_seen_at})"
            );

            // Send email
            if send_recovery_email(config, &recipient_email, &recovery_blob).await {
                // Mark as triggered so we don't send again
                if let Ok(conn) = db.lock() {
                    let _ = conn.execute(
                        "UPDATE deadman_config SET triggered = 1 WHERE blind_id = ?1",
                        params![blind_id],
                    );
                }
            }
        }
    }
}

/// Send the encrypted recovery blob to the recipient via SMTP.
async fn send_recovery_email(config: &Config, recipient: &str, recovery_blob: &[u8]) -> bool {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    if config.smtp_host.is_empty() {
        log::warn!("SMTP not configured, skipping Dead Man's Switch email");
        return false;
    }

    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(recovery_blob);

    let email = match Message::builder()
        .from(
            config
                .smtp_from
                .parse()
                .unwrap_or_else(|_| "noreply@saladvault.com".parse().unwrap()),
        )
        .to(match recipient.parse() {
            Ok(addr) => addr,
            Err(_) => {
                log::error!("Invalid recipient email: {recipient}");
                return false;
            }
        })
        .subject("SaladVault - Kit de Secours (Dead Man's Switch)")
        .header(ContentType::TEXT_PLAIN)
        .body(format!(
            "Ce message a ete envoye automatiquement par SaladVault.\n\n\
             Le proprietaire de ce coffre-fort n'a pas ete actif depuis la periode configuree.\n\n\
             Voici le kit de secours chiffre (base64) :\n\n\
             {blob_b64}\n\n\
             Pour dechiffrer ces donnees, vous aurez besoin du mot de passe \
             que le proprietaire vous a communique."
        )) {
        Ok(e) => e,
        Err(err) => {
            log::error!("Failed to build email: {err}");
            return false;
        }
    };

    let creds = Credentials::new(config.smtp_user.clone(), config.smtp_pass.clone());

    let mailer = match AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host) {
        Ok(builder) => builder
            .port(config.smtp_port)
            .credentials(creds)
            .build(),
        Err(err) => {
            log::error!("Failed to create SMTP transport: {err}");
            return false;
        }
    };

    match mailer.send(email).await {
        Ok(_) => {
            log::info!("Dead Man's Switch email sent to {recipient}");
            true
        }
        Err(err) => {
            log::error!("Failed to send Dead Man's Switch email: {err}");
            false
        }
    }
}
