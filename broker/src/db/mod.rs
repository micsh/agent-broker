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

/// Run schema migrations.
/// Migration 1: channels composite PK (from old single-column PK) + backfill orphaned channel rows
///   from subscriptions (NEW-8: pre-CT-2 data may have subscription references without channel rows).
/// Migration 2: seed cross_project_allowed_sources default-allow entries for all existing projects.
/// Safe to run on a fresh database (idempotent).
pub fn migrate(conn: &Connection) -> Result<(), String> {
    // Migration 1: channels composite PK
    // Detect old single-column PK: pragma_table_info returns one row per column with pk > 0
    let pk_count: i64 = conn
        .prepare("SELECT COUNT(*) FROM pragma_table_info('channels') WHERE pk > 0")
        .and_then(|mut s| s.query_row([], |r| r.get(0)))
        .unwrap_or(0);

    // If pk_count == 1, the old schema has a sole TEXT PRIMARY KEY — migrate it
    if pk_count == 1 {
        conn.execute_batch("
            PRAGMA foreign_keys=OFF;
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

            -- NEW-8: backfill any channel rows that existed only as subscription references
            -- (pre-CT-2 data may have subscriptions whose channel rows were lost in the migration).
            INSERT OR IGNORE INTO channels (id, project, created_utc)
            SELECT DISTINCT channel_id, project, datetime('now')
            FROM subscriptions
            WHERE (channel_id || '|' || project) NOT IN
                (SELECT id || '|' || project FROM channels);

            COMMIT;
            PRAGMA foreign_keys=ON;
        ").map_err(|e| format!("Channel schema migration failed: {e}"))?;
    }

    // Migration 2: seed default-allow ('*') for all projects registered before this migration.
    // INSERT OR IGNORE makes this idempotent — safe to run on every startup.
    conn.execute_batch("
        INSERT OR IGNORE INTO cross_project_allowed_sources
        SELECT '*', name FROM projects;
    ").map_err(|e| format!("cross_project_allowed_sources backfill failed: {e}"))?;

    Ok(())
}
