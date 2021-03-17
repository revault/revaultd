use crate::revaultd::VaultStatus;
use revault_tx::{
    bitcoin::{util::bip32::ChildNumber, Address, Amount, OutPoint, Txid},
    transactions::{
        CancelTransaction, EmergencyTransaction, SpendTransaction, UnvaultEmergencyTransaction,
        UnvaultTransaction,
    },
};

use std::{collections::BTreeMap, sync::mpsc::SyncSender};

/// Incoming from RPC server thread
#[derive(Debug)]
pub enum RpcMessageIn {
    Shutdown,
    // Network, blockheight, sync progress
    GetInfo(SyncSender<(String, u32, f64)>),
    ListVaults(
        (Option<Vec<VaultStatus>>, Option<Vec<OutPoint>>),
        SyncSender<Vec<ListVaultsEntry>>,
    ),
    DepositAddr(SyncSender<Address>),
    GetRevocationTxs(
        OutPoint,
        // None if the deposit does not exist
        // FIXME: use a Result with RpcControlError!
        SyncSender<
            Option<(
                CancelTransaction,
                EmergencyTransaction,
                UnvaultEmergencyTransaction,
            )>,
        >,
    ),
    // Returns None if the transactions could all be stored succesfully
    // FIXME: use a Result with RpcControlError!
    RevocationTxs(
        (
            OutPoint,
            CancelTransaction,
            EmergencyTransaction,
            UnvaultEmergencyTransaction,
        ),
        SyncSender<Option<String>>,
    ),
    GetUnvaultTx(
        OutPoint,
        SyncSender<Result<UnvaultTransaction, RpcControlError>>,
    ),
    UnvaultTx(
        (OutPoint, UnvaultTransaction),
        SyncSender<Result<(), RpcControlError>>,
    ),
    ListPresignedTransactions(
        Option<Vec<OutPoint>>,
        SyncSender<Result<Vec<VaultPresignedTransactions>, RpcControlError>>,
    ),
    ListOnchainTransactions(
        Option<Vec<OutPoint>>,
        SyncSender<Result<Vec<VaultOnchainTransactions>, RpcControlError>>,
    ),
    GetSpendTx(
        Vec<OutPoint>,
        BTreeMap<Address, u64>,
        u64,
        SyncSender<Result<SpendTransaction, RpcControlError>>,
    ),
}

/// Outgoing to the bitcoind poller thread
#[derive(Debug)]
pub enum BitcoindMessageOut {
    Shutdown,
    SyncProgress(SyncSender<f64>),
    WalletTransaction(Txid, SyncSender<Option<WalletTransaction>>),
}

/// Outgoing to the signature fetcher thread
#[derive(Debug)]
pub enum SigFetcherMessageOut {
    Shutdown,
}

#[derive(Debug)]
pub struct WalletTransaction {
    pub hex: String,
    // None if unconfirmed
    pub blockheight: Option<u32>,
    pub received_time: u32,
}

#[derive(Debug)]
pub struct VaultPresignedTransactions {
    pub outpoint: OutPoint,
    pub unvault: UnvaultTransaction,
    pub cancel: CancelTransaction,
    // None if not stakeholder
    pub emergency: Option<EmergencyTransaction>,
    pub unvault_emergency: Option<UnvaultEmergencyTransaction>,
}

#[derive(Debug)]
pub struct VaultOnchainTransactions {
    pub outpoint: OutPoint,
    pub deposit: WalletTransaction,
    pub unvault: Option<WalletTransaction>,
    pub cancel: Option<WalletTransaction>,
    // Always None if not stakeholder
    pub emergency: Option<WalletTransaction>,
    pub unvault_emergency: Option<WalletTransaction>,
    pub spend: Option<WalletTransaction>,
}

#[derive(Debug)]
pub struct ListVaultsEntry {
    pub amount: Amount,
    pub blockheight: u32,
    pub status: VaultStatus,
    pub deposit_outpoint: OutPoint,
    pub derivation_index: ChildNumber,
    pub address: Address,
    pub received_at: u32,
    pub updated_at: u32,
}

/// An error that occured during RPC message handling
#[derive(Debug)]
pub enum RpcControlError {
    UnknownOutpoint(OutPoint),
    // .0 is current status, .1 is required status
    InvalidStatus((VaultStatus, VaultStatus)),
    InvalidPsbt(String),
    Communication(String),
    Transaction(revault_tx::Error),
    SpendLowFeerate(u64, u64),
}

impl std::fmt::Display for RpcControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownOutpoint(ref o) => write!(f, "No vault at '{}'", o),
            Self::InvalidStatus((current, required)) => write!(
                f,
                "Invalid vault status: '{}'. Need '{}'",
                current, required
            ),
            Self::InvalidPsbt(reason) => write!(f, "Invalid PSBT: '{}'", reason),
            Self::Communication(reason) => write!(f, "Communication error: '{}'", reason),
            Self::Transaction(e) => write!(f, "Transaction management error: '{}'", e),
            Self::SpendLowFeerate(required, actual) => write!(
                f,
                "Required feerate ('{}') is significantly higher than actual feerate ('{}')",
                required, actual
            ),
        }
    }
}

impl std::error::Error for RpcControlError {}

impl From<revault_tx::Error> for RpcControlError {
    fn from(e: revault_tx::Error) -> Self {
        Self::Transaction(e)
    }
}
