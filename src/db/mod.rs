mod schema;

use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

/// Thread-safe database handle wrapping a SQLite connection.
pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    /// Open (or create) the broker database at the given path.
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path)
            .map_err(|e| format!("Failed to open database: {e}"))?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| format!("Failed to set pragmas: {e}"))?;

        schema::migrate(&conn)?;

        Ok(Db { conn: Mutex::new(conn) })
    }

    /// Open an in-memory database (for tests).
    #[allow(dead_code)]
    pub fn open_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory()
            .map_err(|e| format!("Failed to open in-memory database: {e}"))?;

        conn.execute_batch("PRAGMA foreign_keys=ON;")
            .map_err(|e| format!("Failed to set pragmas: {e}"))?;

        schema::migrate(&conn)?;

        Ok(Db { conn: Mutex::new(conn) })
    }

    /// Access the connection under lock.
    pub fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("database lock poisoned")
    }
}
