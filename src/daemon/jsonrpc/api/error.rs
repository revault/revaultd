use crate::daemon::{
    bitcoind::BitcoindError, communication::CommunicationError, control::RpcControlError,
    database::DatabaseError,
};

use std::sync::mpsc::{RecvError, SendError};

use jsonrpc_core::{types::error::ErrorCode::ServerError, Error as JsonRpcError};

pub struct Error(ErrorCode, String);

impl From<CommunicationError> for Error {
    fn from(e: CommunicationError) -> Error {
        let code = match e {
            CommunicationError::Net(_) => ErrorCode::TRANSPORT_ERROR,
            CommunicationError::WatchtowerNack(_, _) => ErrorCode::WT_SIG_NACK,
            CommunicationError::SignatureStorage => ErrorCode::COORDINATOR_SIG_STORE_ERROR,
            CommunicationError::SpendTxStorage => ErrorCode::COORDINATOR_SPEND_STORE_ERROR,
            CommunicationError::CosigAlreadySigned => ErrorCode::COSIGNER_ALREADY_SIGN_ERROR,
            CommunicationError::CosigInsanePsbt => ErrorCode::COSIGNER_INSANE_ERROR,
        };
        Error(code, e.to_string())
    }
}

impl From<CommunicationError> for JsonRpcError {
    fn from(e: CommunicationError) -> JsonRpcError {
        Error::from(e).into()
    }
}

impl From<RpcControlError> for Error {
    fn from(e: RpcControlError) -> Error {
        let code = match e {
            RpcControlError::InvalidStatus(..) => ErrorCode::INVALID_STATUS_ERROR,
            RpcControlError::UnknownOutPoint(_) => ErrorCode::RESOURCE_NOT_FOUND_ERROR,
            RpcControlError::Database(_) => ErrorCode::INTERNAL_ERROR,
            RpcControlError::Tx(_) => ErrorCode::INTERNAL_ERROR,
            RpcControlError::Bitcoind(_) => ErrorCode::BITCOIND_ERROR,
            RpcControlError::ThreadCommunication(_) => ErrorCode::INTERNAL_ERROR,
            RpcControlError::TransactionNotFound => ErrorCode::INTERNAL_ERROR,
        };
        Error(code, e.to_string())
    }
}

impl From<BitcoindError> for Error {
    fn from(e: BitcoindError) -> Error {
        Error(ErrorCode::BITCOIND_ERROR, e.to_string())
    }
}

impl<T> From<SendError<T>> for Error {
    fn from(e: SendError<T>) -> Error {
        Error(ErrorCode::INTERNAL_ERROR, e.to_string())
    }
}

impl From<revault_tx::Error> for Error {
    fn from(e: revault_tx::Error) -> Error {
        Error(ErrorCode::INTERNAL_ERROR, e.to_string())
    }
}

impl From<revault_tx::error::TransactionCreationError> for Error {
    fn from(e: revault_tx::error::TransactionCreationError) -> Error {
        Error(ErrorCode::INTERNAL_ERROR, e.to_string())
    }
}

impl From<RecvError> for Error {
    fn from(e: RecvError) -> Error {
        Error(ErrorCode::INTERNAL_ERROR, e.to_string())
    }
}

impl From<DatabaseError> for Error {
    fn from(e: DatabaseError) -> Error {
        Error(ErrorCode::INTERNAL_ERROR, e.to_string())
    }
}

impl From<DatabaseError> for JsonRpcError {
    fn from(e: DatabaseError) -> JsonRpcError {
        Error::from(e).into()
    }
}

impl From<Error> for JsonRpcError {
    fn from(e: Error) -> JsonRpcError {
        JsonRpcError {
            code: ServerError(e.0 as i64),
            message: e.1,
            data: None,
        }
    }
}

#[allow(non_camel_case_types)]
pub enum ErrorCode {
    /// Internal error
    INTERNAL_ERROR = 11000,
    /// An error internal to revault_net, generally a transport error
    TRANSPORT_ERROR = 12000,
    /// The watchtower refused our signatures
    WT_SIG_NACK = 13_000,
    /// The Coordinator told us they could not store our signature
    COORDINATOR_SIG_STORE_ERROR = 13100,
    /// The Coordinator told us they could not store our Spend transaction
    COORDINATOR_SPEND_STORE_ERROR = 13101,
    /// The Cosigning Server returned null to our request!
    COSIGNER_ALREADY_SIGN_ERROR = 13201,
    /// The Cosigning Server tried to fool us!
    COSIGNER_INSANE_ERROR = 13202,
    /// Bitcoind error
    BITCOIND_ERROR = 14000,
    /// Resource not found
    RESOURCE_NOT_FOUND_ERROR = 15000,
    /// Vault status was invalid
    INVALID_STATUS_ERROR = 15001,
}
