mod config;
mod db;
mod error;
mod handlers;
mod middleware;
mod models;
mod routes;

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
        App::new()
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
