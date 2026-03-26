use actix_web::web;

use crate::handlers::{auth, deadman, health, subscription, sync};

/// Register all API routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(health::health)
        // Auth
        .service(auth::register)
        .service(auth::login)
        .service(auth::mfa_setup_confirm)
        .service(auth::mfa_verify)
        .service(auth::refresh)
        .service(auth::logout)
        .service(auth::get_salt)
        .service(auth::delete_account)
        .service(auth::send_verification_code)
        .service(auth::verify_code)
        // Sync
        .service(sync::get_vault)
        .service(sync::put_vault)
        .service(sync::sync_status)
        // Subscription
        .service(subscription::subscription_status)
        .service(subscription::create_checkout)
        .service(subscription::create_portal)
        .service(subscription::webhook)
        // Dead Man's Switch
        .service(deadman::heartbeat)
        .service(deadman::status)
        .service(deadman::update_config);
}
