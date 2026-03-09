mod api;
mod broker;
mod db;

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

    let db_path = std::env::var("BROKER_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let dir = dirs_or_default();
            dir.join("agent-broker.db")
        });

    // Ensure parent directory exists
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    tracing::info!("Database: {}", db_path.display());

    let database = db::Db::open(&db_path).expect("Failed to open database");
    let db = Arc::new(database);
    let broker_state = Arc::new(BrokerState::new(db));
    let delivery = Arc::new(DeliveryEngine::new(broker_state.clone()));

    let app_state = Arc::new(AppState {
        broker: broker_state,
        delivery,
    });

    let app = api::http_router()
        .route("/ws", axum::routing::get(api::handle_ws))
        .with_state(app_state);

    let addr = format!("0.0.0.0:{port}");
    tracing::info!("Agent broker listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind");

    axum::serve(listener, app).await.expect("Server error");
}

/// Default data directory: ~/.agent-broker/
fn dirs_or_default() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".agent-broker")
}

