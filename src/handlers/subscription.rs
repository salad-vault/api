use actix_web::{get, post, web, HttpRequest, HttpResponse};
use rusqlite::params;
use serde::Deserialize;

use crate::config::Config;
use crate::error::ApiError;
use crate::handlers::auth::extract_blind_id_from_request;
use crate::models::{CheckoutSessionResponse, PortalSessionResponse, SubscriptionStatusResponse};

type DbPool = web::Data<crate::db::DbPool>;

/// GET /subscription/status
///
/// Return the subscription status for the authenticated user.
/// Defaults to "jardinier" (free) if no subscription record exists.
#[get("/subscription/status")]
pub async fn subscription_status(
    db: DbPool,
    config: web::Data<Config>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let blind_id = extract_blind_id_from_request(&req, &config)?;

    let conn = db
        .get()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let row: Option<(String, String, Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT plan, status, trial_end, current_period_end FROM subscriptions WHERE blind_id = ?1",
            params![blind_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .ok();

    match row {
        Some((plan, status, trial_end, current_period_end)) => {
            Ok(HttpResponse::Ok().json(SubscriptionStatusResponse {
                plan,
                status,
                trial_end,
                current_period_end,
            }))
        }
        None => Ok(HttpResponse::Ok().json(SubscriptionStatusResponse {
            plan: "jardinier".to_string(),
            status: "active".to_string(),
            trial_end: None,
            current_period_end: None,
        })),
    }
}

/// POST /subscription/checkout
///
/// Create a Stripe Checkout Session for the Maraicher Pro plan.
/// Returns the checkout URL for the client to redirect to.
#[post("/subscription/checkout")]
pub async fn create_checkout(
    db: DbPool,
    config: web::Data<Config>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let blind_id = extract_blind_id_from_request(&req, &config)?;

    if config.stripe_secret_key.is_empty() {
        return Err(ApiError::Internal("Stripe not configured".to_string()));
    }

    let conn = db
        .get()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Check if user already has a Stripe customer ID
    let existing_customer: Option<String> = conn
        .query_row(
            "SELECT stripe_customer_id FROM subscriptions WHERE blind_id = ?1",
            params![blind_id],
            |row| row.get(0),
        )
        .ok();

    let client = reqwest::Client::new();

    // Create or reuse Stripe customer
    let customer_id = match existing_customer {
        Some(id) => id,
        None => {
            let resp = client
                .post("https://api.stripe.com/v1/customers")
                .header("Authorization", format!("Bearer {}", config.stripe_secret_key))
                .form(&[("metadata[blind_id]", blind_id.as_str())])
                .send()
                .await
                .map_err(|e| ApiError::Internal(format!("Stripe request failed: {e}")))?;

            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| ApiError::Internal(format!("Stripe response parse error: {e}")))?;

            let cid = body["id"]
                .as_str()
                .ok_or_else(|| ApiError::Internal("Stripe customer creation failed".to_string()))?
                .to_string();

            // Upsert subscription record with customer ID
            conn.execute(
                "INSERT INTO subscriptions (blind_id, stripe_customer_id, plan, status)
                 VALUES (?1, ?2, 'jardinier', 'inactive')
                 ON CONFLICT(blind_id) DO UPDATE SET stripe_customer_id = excluded.stripe_customer_id",
                params![blind_id, cid],
            )?;

            cid
        }
    };

    // Create Checkout Session
    let resp = client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .header("Authorization", format!("Bearer {}", config.stripe_secret_key))
        .form(&[
            ("customer", customer_id.as_str()),
            ("mode", "subscription"),
            ("line_items[0][price]", config.stripe_price_id_maraicher.as_str()),
            ("line_items[0][quantity]", "1"),
            ("success_url", "saladvault://subscription/success"),
            ("cancel_url", "saladvault://subscription/cancel"),
            ("subscription_data[trial_period_days]", "14"),
        ])
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("Stripe checkout request failed: {e}")))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| ApiError::Internal(format!("Stripe checkout parse error: {e}")))?;

    let checkout_url = body["url"]
        .as_str()
        .ok_or_else(|| ApiError::Internal("Stripe checkout session creation failed".to_string()))?
        .to_string();

    Ok(HttpResponse::Ok().json(CheckoutSessionResponse { checkout_url }))
}

/// POST /subscription/portal
///
/// Create a Stripe Customer Portal session for the authenticated user.
/// The portal lets users manage their subscription (cancel, update payment, etc.).
#[post("/subscription/portal")]
pub async fn create_portal(
    db: DbPool,
    config: web::Data<Config>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let blind_id = extract_blind_id_from_request(&req, &config)?;

    if config.stripe_secret_key.is_empty() {
        return Err(ApiError::Internal("Stripe not configured".to_string()));
    }

    let conn = db
        .get()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let customer_id: String = conn
        .query_row(
            "SELECT stripe_customer_id FROM subscriptions WHERE blind_id = ?1",
            params![blind_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::NotFound("No subscription found".to_string()))?;

    let client = reqwest::Client::new();

    let resp = client
        .post("https://api.stripe.com/v1/billing_portal/sessions")
        .header("Authorization", format!("Bearer {}", config.stripe_secret_key))
        .form(&[
            ("customer", customer_id.as_str()),
            ("return_url", "saladvault://subscription/portal-return"),
        ])
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("Stripe portal request failed: {e}")))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| ApiError::Internal(format!("Stripe portal parse error: {e}")))?;

    let portal_url = body["url"]
        .as_str()
        .ok_or_else(|| ApiError::Internal("Stripe portal session creation failed".to_string()))?
        .to_string();

    Ok(HttpResponse::Ok().json(PortalSessionResponse { portal_url }))
}

/// POST /subscription/webhook
///
/// Handle Stripe webhook events. Verifies the webhook signature,
/// then processes relevant events to update subscription status.
#[post("/subscription/webhook")]
pub async fn webhook(
    db: DbPool,
    config: web::Data<Config>,
    req: HttpRequest,
    body: web::Bytes,
) -> Result<HttpResponse, ApiError> {
    // Verify Stripe signature
    let sig = req
        .headers()
        .get("Stripe-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::BadRequest("Missing Stripe-Signature header".to_string()))?;

    verify_stripe_signature(&body, sig, &config.stripe_webhook_secret)?;

    let event: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| ApiError::BadRequest(format!("Invalid JSON: {e}")))?;

    let event_type = event["type"]
        .as_str()
        .unwrap_or("");

    let conn = db
        .get()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    match event_type {
        "checkout.session.completed" => {
            let customer_id = event["data"]["object"]["customer"]
                .as_str()
                .unwrap_or("");
            let subscription_id = event["data"]["object"]["subscription"]
                .as_str()
                .unwrap_or("");

            if !customer_id.is_empty() && !subscription_id.is_empty() {
                conn.execute(
                    "UPDATE subscriptions SET
                        stripe_subscription_id = ?1,
                        plan = 'maraicher',
                        status = 'active',
                        updated_at = datetime('now')
                     WHERE stripe_customer_id = ?2",
                    params![subscription_id, customer_id],
                )?;
            }
        }
        "invoice.paid" => {
            let subscription_id = event["data"]["object"]["subscription"]
                .as_str()
                .unwrap_or("");
            let period_end = event["data"]["object"]["lines"]["data"][0]["period"]["end"]
                .as_i64();

            if !subscription_id.is_empty() {
                let period_end_str = period_end
                    .map(|ts| {
                        chrono::DateTime::from_timestamp(ts, 0)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_default()
                    });

                conn.execute(
                    "UPDATE subscriptions SET
                        status = 'active',
                        current_period_end = ?1,
                        updated_at = datetime('now')
                     WHERE stripe_subscription_id = ?2",
                    params![period_end_str, subscription_id],
                )?;
            }
        }
        "customer.subscription.deleted" => {
            let subscription_id = event["data"]["object"]["id"]
                .as_str()
                .unwrap_or("");

            if !subscription_id.is_empty() {
                conn.execute(
                    "UPDATE subscriptions SET
                        plan = 'jardinier',
                        status = 'canceled',
                        updated_at = datetime('now')
                     WHERE stripe_subscription_id = ?1",
                    params![subscription_id],
                )?;
            }
        }
        "customer.subscription.trial_will_end" => {
            // Informational — could be used to notify, but we keep zero-knowledge
            // so no email sending from here. Client polls status.
        }
        _ => {
            // Ignore unhandled event types
        }
    }

    Ok(HttpResponse::Ok().finish())
}

/// Verify a Stripe webhook signature using HMAC-SHA256.
fn verify_stripe_signature(
    payload: &[u8],
    sig_header: &str,
    secret: &str,
) -> Result<(), ApiError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Parse the signature header: t=timestamp,v1=signature
    let mut timestamp = "";
    let mut signature = "";

    for part in sig_header.split(',') {
        let part = part.trim();
        if let Some(t) = part.strip_prefix("t=") {
            timestamp = t;
        } else if let Some(s) = part.strip_prefix("v1=") {
            signature = s;
        }
    }

    if timestamp.is_empty() || signature.is_empty() {
        return Err(ApiError::BadRequest("Invalid Stripe signature format".to_string()));
    }

    // Construct the signed payload: timestamp.payload
    let signed_payload = format!("{timestamp}.");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| ApiError::Internal(format!("HMAC error: {e}")))?;
    mac.update(signed_payload.as_bytes());
    mac.update(payload);

    let expected = mac.finalize().into_bytes();
    let expected_hex = hex::encode(expected);

    if expected_hex != signature {
        return Err(ApiError::BadRequest("Invalid webhook signature".to_string()));
    }

    Ok(())
}

/// Check if a user has an active Maraicher subscription.
/// Returns Ok(()) if they do, Err(ApiError) if not.
pub fn require_active_subscription(
    conn: &rusqlite::Connection,
    blind_id: &str,
) -> Result<(), ApiError> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT plan, status FROM subscriptions WHERE blind_id = ?1",
            params![blind_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();

    match row {
        Some((plan, status)) if plan == "maraicher" && (status == "active" || status == "trialing") => {
            Ok(())
        }
        _ => Err(ApiError::Unauthorized(
            "Active Maraicher subscription required for cloud sync".to_string(),
        )),
    }
}

/// Deserialization helper for Stripe events (unused but available for typed parsing).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct StripeEvent {
    id: String,
    #[serde(rename = "type")]
    event_type: String,
    data: serde_json::Value,
}
