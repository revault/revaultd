/// Messages sent by the threads we start

#[derive(Debug)]
pub enum RpcMessage {
    Shutdown,
}

#[derive(Debug)]
pub enum BitcoindMessage {}

#[derive(Debug)]
pub enum ThreadMessage {
    Rpc(RpcMessage),
    Bitcoind(BitcoindMessage),
}
