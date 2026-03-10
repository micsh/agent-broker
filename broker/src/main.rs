mod api;
mod broker;
mod db;
mod identity;
mod stanza;

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

    let app_state = Arc::new(AppState {
        broker: broker_state,
        delivery,
    });

    let app = api::http_router()
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
