use crate::revaultd::VaultStatus;
use revault_tx::{
    bitcoin::{Address, Amount, OutPoint, Txid},
    transactions::{
        CancelTransaction, EmergencyTransaction, SpendTransaction, UnvaultEmergencyTransaction,
        UnvaultTransaction, VaultTransaction,
    },
};

use std::sync::mpsc::SyncSender;

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
        SyncSender<
            Option<(
                CancelTransaction,
                EmergencyTransaction,
                UnvaultEmergencyTransaction,
            )>,
        >,
    ),
    // Returns None if the transactions could all be stored succesfully
    RevocationTxs(
        (
            OutPoint,
            CancelTransaction,
            EmergencyTransaction,
            UnvaultEmergencyTransaction,
        ),
        SyncSender<Option<String>>,
    ),
    ListTransactions(
        Option<Vec<OutPoint>>,
        SyncSender<
            // None if the deposit does not exist
            Vec<VaultTransactions>,
        >,
    ),
}

/// Outgoing to the bitcoind poller thread
#[derive(Debug)]
pub enum BitcoindMessageOut {
    Shutdown,
    SyncProgress(SyncSender<f64>),
    WalletTransaction(Txid, SyncSender<Option<WalletTransaction>>),
}

#[derive(Debug)]
pub struct WalletTransaction {
    pub hex: String,
    pub blockheight: Option<u32>,
    pub received_time: u32,
}

#[derive(Debug)]
pub struct TransactionResource<T> {
    // None if unconfirmed
    pub wallet_tx: Option<WalletTransaction>,
    pub tx: T,
    pub is_signed: bool,
}

#[derive(Debug)]
pub struct VaultTransactions {
    pub outpoint: OutPoint,
    pub deposit: TransactionResource<VaultTransaction>,
    pub unvault: TransactionResource<UnvaultTransaction>,
    // None if not spending
    pub spend: Option<TransactionResource<SpendTransaction>>,
    pub cancel: TransactionResource<CancelTransaction>,
    pub emergency: TransactionResource<EmergencyTransaction>,
    pub unvault_emergency: TransactionResource<UnvaultEmergencyTransaction>,
}

#[derive(Debug)]
pub struct ListVaultsEntry {
    // amount, status, txid, vout
    pub amount: Amount,
    pub status: VaultStatus,
    pub deposit_outpoint: OutPoint,
}
