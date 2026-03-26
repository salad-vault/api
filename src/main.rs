mod config;
mod db;
mod error;
mod handlers;
mod middleware;
mod models;
mod routes;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load .env if present
    let _ = dotenvy::dotenv();

    // Initialize logger
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let config = config::Config::from_env();
    let bind_addr = format!("{}:{}", config.host, config.port);

    log::info!("Starting SaladVault API server on {bind_addr}");

    // Open database connection pool
    let pool = db::create_pool(&config.db_path)
        .expect("Failed to create database connection pool");
    let db_data = web::Data::new(pool);
    let config_data = web::Data::new(config.clone());

    // Spawn Dead Man's Switch background checker (every hour)
    {
        let db_check = db_data.clone();
        let config_check = config.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                log::info!("Running Dead Man's Switch check...");
                handlers::deadman::check_deadman_triggers(
                    db_check.get_ref(),
                    &config_check,
                )
                .await;

                log::info!("Cleaning up orphaned MFA registrations...");
                handlers::auth::cleanup_orphan_registrations(db_check.get_ref());
            }
        });
    }

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin_fn(|origin, _req_head| {
                let o = origin.as_bytes();
                o.starts_with(b"chrome-extension://")
                    || o.starts_with(b"moz-extension://")
                    || o.starts_with(b"ms-browser-extension://")
            })
            .allowed_methods(vec!["GET", "POST", "PUT"])
            .allowed_headers(vec!["Authorization", "Content-Type"])
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(db_data.clone())
            .app_data(config_data.clone())
            .configure(routes::configure)
    })
    .bind(&bind_addr)?
    .run()
    .await
}

#[cfg(test)]
mod tests;
