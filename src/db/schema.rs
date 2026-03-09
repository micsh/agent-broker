use rusqlite::Connection;

/// Run all schema migrations.
pub fn migrate(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS agents (
            name        TEXT NOT NULL,
            project     TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT '',
            token       TEXT NOT NULL,
            created_utc TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (name, project)
        );

        CREATE TABLE IF NOT EXISTS presence (
            agent_name  TEXT NOT NULL,
            project     TEXT NOT NULL,
            state       TEXT NOT NULL DEFAULT 'offline',
            session_id  TEXT,
            updated_utc TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (agent_name, project),
            FOREIGN KEY (agent_name, project) REFERENCES agents(name, project)
        );

        CREATE TABLE IF NOT EXISTS channels (
            id          TEXT PRIMARY KEY,
            project     TEXT,
            description TEXT NOT NULL DEFAULT '',
            created_utc TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS subscriptions (
            agent_name  TEXT NOT NULL,
            project     TEXT NOT NULL,
            channel_id  TEXT NOT NULL,
            subscribed_utc TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (agent_name, project, channel_id),
            FOREIGN KEY (agent_name, project) REFERENCES agents(name, project),
            FOREIGN KEY (channel_id) REFERENCES channels(id)
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
    .map_err(|e| format!("Migration failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        migrate(&conn).unwrap(); // second run should succeed
    }
}
