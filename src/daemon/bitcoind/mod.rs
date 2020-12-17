use crate::database::DatabaseError;

use jsonrpc::{
    error::{Error, RpcError},
    simple_http,
};

pub mod actions;
pub mod interface;

/// Minimum number of confirmations before treating a deposit as confirmed
const MIN_CONF: u64 = 6;

/// An error happened in the bitcoind-manager thread
#[derive(Debug)]
pub enum BitcoindError {
    /// It can be related to us..
    Custom(String),
    /// Or directly to bitcoind's RPC server
    Server(Error),
}

impl BitcoindError {
    /// Is bitcoind just starting ?
    pub fn is_warming_up(&self) -> bool {
        match self {
            // https://github.com/bitcoin/bitcoin/blob/dca80ffb45fcc8e6eedb6dc481d500dedab4248b/src/rpc/protocol.h#L49
            BitcoindError::Server(Error::Rpc(RpcError { code, .. })) => *code == -28,
            _ => false,
        }
    }
}

impl std::fmt::Display for BitcoindError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BitcoindError::Custom(ref s) => write!(f, "Bitcoind manager error: {}", s),
            BitcoindError::Server(ref e) => write!(f, "Bitcoind server error: {}", e),
        }
    }
}

impl std::error::Error for BitcoindError {}

impl From<DatabaseError> for BitcoindError {
    fn from(e: DatabaseError) -> Self {
        Self::Custom(format!("Database error in bitcoind thread: {}", e))
    }
}

impl From<simple_http::Error> for BitcoindError {
    fn from(e: simple_http::Error) -> Self {
        Self::Server(Error::Transport(Box::new(e)))
    }
}
