use crate::database::DatabaseError;

use std::path::PathBuf;

use rusqlite::{Connection, Row, ToSql, Transaction, NO_PARAMS};

// Note that we don't share a global struct that would contain the connection here.
// As the bundled sqlite is compiled with SQLITE_THREADSAFE, quoting sqlite.org:
// > Multi-thread. In this mode, SQLite can be safely used by multiple threads provided that
// > no single database connection is used simultaneously in two or more threads.
// Therefore the below routines create a new connection and can be used from any thread.

/// Perform a set of modifications to the database inside a single transaction
pub fn db_exec<F>(path: &PathBuf, modifications: F) -> Result<(), DatabaseError>
where
    F: Fn(&Transaction) -> Result<(), DatabaseError>,
{
    let mut conn = Connection::open(path)
        .map_err(|e| DatabaseError(format!("Opening database: {}", e.to_string())))?;
    let tx = conn
        .transaction()
        .map_err(|e| DatabaseError(format!("Creating transaction: {}", e.to_string())))?;

    modifications(&tx)?;
    tx.commit()
        .map_err(|e| DatabaseError(format!("Comitting transaction: {}", e.to_string())))?;

    Ok(())
}

// Internal helper for queries boilerplate
fn db_query<'a, P, F, T>(
    path: &PathBuf,
    stmt_str: &'a str,
    params: P,
    f: F,
) -> Result<Vec<rusqlite::Result<T>>, DatabaseError>
where
    P: IntoIterator,
    P::Item: ToSql,
    F: FnMut(&Row<'_>) -> rusqlite::Result<T>,
{
    let conn = Connection::open(path)
        .map_err(|e| DatabaseError(format!("Opening database for query: {}", e.to_string())))?;

    let x = Ok(conn
        .prepare(stmt_str)
        .map_err(|e| DatabaseError(format!("Preparing query: '{}'", e.to_string())))?
        .query_map(params, f)
        .map_err(|e| DatabaseError(format!("Executing query: '{}'", e.to_string())))?
        .collect::<Vec<rusqlite::Result<T>>>());
    x
}

/// Get the database version
pub fn db_version(db_path: &PathBuf) -> Result<u32, DatabaseError> {
    let rows = db_query(db_path, "SELECT version FROM version", NO_PARAMS, |row| {
        row.get::<_, u32>(0)
    })?;

    Ok(*rows
        .get(0)
        .ok_or_else(|| DatabaseError("No row in version table?".to_string()))?
        .as_ref()
        .map_err(|e| DatabaseError(format!("Getting version: '{}'", e.to_string())))?)
}

/// A "wallet" as stored in the database
#[derive(Clone)]
pub struct DbWallet {
    id: u32,
    timestamp: u32,
    vault_descriptor: String,
    unvault_descriptor: String,
}

/// Get the database wallet. We only support single wallet, so this always return the first row.
pub fn db_wallet(db_path: &PathBuf) -> Result<DbWallet, DatabaseError> {
    let rows = db_query(db_path, "SELECT * FROM wallets", NO_PARAMS, |row| {
        Ok(DbWallet {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            vault_descriptor: row.get(2)?,
            unvault_descriptor: row.get(3)?,
        })
    })?;

    Ok(rows
        .get(0)
        .ok_or_else(|| DatabaseError("No row in wallet table?".to_string()))?
        .as_ref()
        .map_err(|e| DatabaseError(format!("Getting wallet: '{}'", e.to_string())))?
        .clone())
}

// Add more db_* method here!
