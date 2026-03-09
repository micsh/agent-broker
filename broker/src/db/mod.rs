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

    Ok(Repository::new(conn))
}
