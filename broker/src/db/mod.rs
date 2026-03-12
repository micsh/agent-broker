mod schema;
pub mod repository;

pub use repository::Repository;

use rusqlite::Connection;
use std::path::Path;

/// Open (or create) the broker database at the given path.
pub fn open(path: &Path) -> Result<Repository, String> {
    let conn = Connection::open(path)
        .map_err(|e| format!("Failed to open database: {e}"))?;

    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
        .map_err(|e| format!("Failed to set pragmas: {e}"))?;

    schema::ensure_schema(&conn)?;
    migrate(&conn)?;

    Ok(Repository::new(conn))
}

/// Open an in-memory database (for tests).
#[allow(dead_code)]
pub fn open_memory() -> Result<Repository, String> {
    let conn = Connection::open_in_memory()
        .map_err(|e| format!("Failed to open in-memory database: {e}"))?;

    conn.execute_batch("PRAGMA foreign_keys=ON;")
        .map_err(|e| format!("Failed to set pragmas: {e}"))?;

    schema::ensure_schema(&conn)?;
    migrate(&conn)?;

    Ok(Repository::new(conn))
}

/// Migrate channels table to composite PRIMARY KEY (id, project) if needed.
/// Safe to run on a fresh database (no-op when schema is already current).
pub fn migrate(conn: &Connection) -> Result<(), String> {
    // Detect old single-column PK: pragma_table_info returns one row per column with pk > 0
    let pk_count: i64 = conn
        .prepare("SELECT COUNT(*) FROM pragma_table_info('channels') WHERE pk > 0")
        .and_then(|mut s| s.query_row([], |r| r.get(0)))
        .unwrap_or(0);

    // If pk_count == 1, the old schema has a sole TEXT PRIMARY KEY — migrate it
    if pk_count != 1 {
        return Ok(());
    }

    conn.execute_batch("
        BEGIN;

        CREATE TABLE channels_new (
            id          TEXT NOT NULL,
            project     TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_utc TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (id, project)
        );
        INSERT INTO channels_new SELECT id, COALESCE(project, ''), description, created_utc FROM channels;

        CREATE TABLE subscriptions_new (
            agent_name     TEXT NOT NULL,
            project        TEXT NOT NULL,
            channel_id     TEXT NOT NULL,
            subscribed_utc TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (agent_name, project, channel_id),
            FOREIGN KEY (agent_name, project) REFERENCES agents(name, project),
            FOREIGN KEY (channel_id, project) REFERENCES channels_new(id, project)
        );
        INSERT INTO subscriptions_new SELECT agent_name, project, channel_id, subscribed_utc FROM subscriptions;

        DROP TABLE subscriptions;
        DROP TABLE channels;
        ALTER TABLE channels_new RENAME TO channels;
        ALTER TABLE subscriptions_new RENAME TO subscriptions;

        COMMIT;
    ").map_err(|e| format!("Channel schema migration failed: {e}"))
}
