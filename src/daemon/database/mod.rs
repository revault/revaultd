pub mod actions;
pub mod interface;
pub mod schema;

use revault_tx::bitcoin::util::psbt::Error as PsbtError;

// FIXME: make this an enum and have actual specific errors
#[derive(PartialEq, Eq, Debug)]
pub struct DatabaseError(pub String);

impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Database error: {}", self.0)
    }
}

impl std::error::Error for DatabaseError {}

impl From<revault_tx::Error> for DatabaseError {
    fn from(e: revault_tx::Error) -> Self {
        Self(format!("Transaction error: {}", e))
    }
}

impl From<rusqlite::Error> for DatabaseError {
    fn from(e: rusqlite::Error) -> Self {
        Self(format!("SQLite error: {}", e))
    }
}

impl From<PsbtError> for DatabaseError {
    fn from(e: PsbtError) -> Self {
        Self(format!("PSBT error: {}", e))
    }
}

pub const DB_VERSION: u32 = 0;
