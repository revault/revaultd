use crate::revaultd::VaultStatus;
use revault_tx::bitcoin::{Address, Txid};

use std::sync::mpsc::SyncSender;

/// Incoming from RPC server thread
#[derive(Debug)]
pub enum RpcMessageIn {
    Shutdown,
    // Network, blockheight, sync progress
    GetInfo(SyncSender<(String, u32, f64)>),
    ListVaults(
        (Option<Vec<VaultStatus>>, Option<Vec<Txid>>),
        // amount, status, txid, vout
        SyncSender<Vec<(u64, String, String, u32)>>,
    ),
    DepositAddr(SyncSender<Address>),
}

/// Outgoing to the bitcoind poller thread
#[derive(Debug)]
pub enum BitcoindMessageOut {
    Shutdown,
    SyncProgress(SyncSender<f64>),
}
