mod api;
mod broker;
mod db;
mod http_frame;
mod identity;

use api::AppState;
use broker::BrokerState;
use broker::DeliveryEngine;
use std::path::PathBuf;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "agent_broker=info".into()),
        )
        .init();

    let port: u16 = std::env::var("BROKER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(4200);

    let data_dir = std::env::var("BROKER_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs_or_default());

    std::fs::create_dir_all(&data_dir).ok();

    let db_path = data_dir.join("agent-broker.db");
    tracing::info!("Data directory: {}", data_dir.display());

    let repo = Arc::new(db::open(&db_path).expect("Failed to open database"));
    let broker_state = Arc::new(BrokerState::new(repo));
    let delivery = Arc::new(DeliveryEngine::new(broker_state.clone()));

    // Periodic cleanup: delivered messages after 6h, pending after 7 days
    let cleanup_delivery = delivery.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
        loop {
            interval.tick().await;
            let (delivered, pending) = cleanup_delivery.cleanup(6, 168);
            if delivered > 0 || pending > 0 {
                tracing::info!("Cleanup: removed {delivered} delivered, {pending} expired pending messages");
            }
        }
    });

    // Nonce eviction: runs every 120s — TTL is 60s, so at most 2 TTLs of stale entries accumulate
    let broker_state_for_cleanup = broker_state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(120));
        loop {
            interval.tick().await;
            broker_state_for_cleanup.nonce_store.evict_expired();
        }
    });

    let config = api::routes::BrokerConfig {
        admin_key: std::env::var("BROKER_ADMIN_KEY").ok(),
        rate_limit_rps: std::env::var("RATE_LIMIT_RPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100),
        boards_registration_token: std::env::var("BOARDS_REGISTRATION_TOKEN")
            .ok()
            .filter(|s| !s.is_empty()),
        archive_dms: std::env::var("BROKER_ARCHIVE_DMS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false),
        relay_timeout: std::time::Duration::from_secs(
            std::env::var("BROKER_RELAY_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5u64),
        ),
        log_file: std::env::var("BROKER_LOG_FILE").ok().filter(|s| !s.is_empty()),
    };
    let wire_log = config.log_file.as_ref().and_then(|path| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| tracing::warn!("BROKER_LOG_FILE open failed for {path:?}: {e}"))
            .ok()
            .map(|file| {
                let (tx, rx) = std::sync::mpsc::sync_channel::<String>(1024);
                std::thread::spawn(move || {
                    use std::io::{BufWriter, Write};
                    let mut writer = BufWriter::new(file);
                    for entry in rx {
                        let _ = writer.write_all(entry.as_bytes());
                        let _ = writer.flush();
                    }
                });
                Arc::new(tx)
            })
    });
    let rate_limiter = Arc::new(api::middleware::ProjectRateLimiter::new(config.rate_limit_rps));

    let app_state = Arc::new(AppState {
        broker: broker_state,
        delivery,
        config,
        rate_limiter,
        relay_map: Arc::new(dashmap::DashMap::new()),
        wire_log,
    });

    let app = api::http_router(app_state.clone())
        .nest("/admin", api::admin_router())
        .route("/ws", axum::routing::get(api::handle_ws))
        .with_state(app_state);

    let addr = format!("127.0.0.1:{port}");
    tracing::info!("Agent broker listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind");

    axum::serve(listener, app).await.expect("Server error");
}

fn dirs_or_default() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".agent-broker")
}
