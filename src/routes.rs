use actix_web::web;

use crate::handlers::{auth, deadman, health, sync};

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
        // Sync
        .service(sync::get_vault)
        .service(sync::put_vault)
        .service(sync::sync_status)
        // Dead Man's Switch
        .service(deadman::heartbeat)
        .service(deadman::status)
        .service(deadman::update_config);
}
