use jsonrpc_derive::rpc;

#[rpc(server)]
pub trait RpcApi {
    /// Stops the daemon
    #[rpc(name = "stop")]
    fn stop(&self) -> jsonrpc_core::Result<()>;
}
