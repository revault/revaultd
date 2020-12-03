use std::sync::mpsc::SyncSender;

/// Incoming from RPC server thread
#[derive(Debug)]
pub enum RpcMessageIn {
    Shutdown,
    // Network, blockheight, sync progress
    GetInfo(SyncSender<(String, u32, f64)>),
}

/// Incoming from bitcoind poller thread
#[derive(Debug)]
pub enum BitcoindMessageIn {}

/// Incoming from a spawned thread
#[derive(Debug)]
pub enum ThreadMessageIn {
    Rpc(RpcMessageIn),
    Bitcoind(BitcoindMessageIn),
}

/// Outgoing to the bitcoind poller thread
#[derive(Debug)]
pub enum BitcoindMessageOut {
    Shutdown,
    SyncProgress(SyncSender<f64>),
}
