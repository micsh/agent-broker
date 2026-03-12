use rusqlite::Connection;

/// Ensure all required tables exist.
pub fn ensure_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS projects (
            name        TEXT PRIMARY KEY,
            key_hash    TEXT NOT NULL,
            created_utc TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS agents (
            name        TEXT NOT NULL,
            project     TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT '',
            created_utc TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (name, project),
            FOREIGN KEY (project) REFERENCES projects(name)
        );

        CREATE TABLE IF NOT EXISTS channels (
            id          TEXT NOT NULL,
            project     TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_utc TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (id, project),
            FOREIGN KEY (project) REFERENCES projects(name)
        );

        CREATE TABLE IF NOT EXISTS subscriptions (
            agent_name     TEXT NOT NULL,
            project        TEXT NOT NULL,
            channel_id     TEXT NOT NULL,
            subscribed_utc TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (agent_name, project, channel_id),
            FOREIGN KEY (agent_name, project) REFERENCES agents(name, project),
            FOREIGN KEY (channel_id, project) REFERENCES channels(id, project)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id          TEXT PRIMARY KEY,
            from_agent  TEXT NOT NULL,
            from_project TEXT NOT NULL,
            to_agent    TEXT,
            to_channel  TEXT,
            body        TEXT NOT NULL,
            metadata    TEXT,
            created_utc TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS delivery_log (
            message_id  TEXT NOT NULL,
            agent_name  TEXT NOT NULL,
            project     TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'pending',
            delivered_utc TEXT,
            PRIMARY KEY (message_id, agent_name, project),
            FOREIGN KEY (message_id) REFERENCES messages(id),
            FOREIGN KEY (agent_name, project) REFERENCES agents(name, project)
        );

        CREATE INDEX IF NOT EXISTS idx_messages_to_agent ON messages(to_agent);
        CREATE INDEX IF NOT EXISTS idx_messages_to_channel ON messages(to_channel);
        CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_utc);
        CREATE INDEX IF NOT EXISTS idx_delivery_pending ON delivery_log(agent_name, project, status)
            WHERE status = 'pending';
        ",
    )
    .map_err(|e| format!("Schema setup failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        ensure_schema(&conn).unwrap();// second run should succeed
    }
}
