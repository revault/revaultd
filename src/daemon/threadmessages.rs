/// Messages for communications with our spawned threads

/// Incoming from RPC server thread
#[derive(Debug, PartialEq)]
pub enum RpcMessageIn {
    Shutdown,
}

/// Incoming from bitcoind poller thread
#[derive(Debug, PartialEq)]
pub enum BitcoindMessageIn {}

/// Incoming from a spawned thread
#[derive(Debug, PartialEq)]
pub enum ThreadMessageIn {
    Rpc(RpcMessageIn),
    Bitcoind(BitcoindMessageIn),
}

/// Outgoing to the bitcoind poller thread
#[derive(Debug, PartialEq)]
pub enum BitcoindMessageOut {
    Shutdown,
}
