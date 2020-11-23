/// Messages sent by the threads we start

#[derive(Debug, PartialEq)]
pub enum RpcMessage {
    Shutdown,
}

#[derive(Debug, PartialEq)]
pub enum BitcoindMessage {}

#[derive(Debug, PartialEq)]
pub enum ThreadMessage {
    Rpc(RpcMessage),
    Bitcoind(BitcoindMessage),
}
