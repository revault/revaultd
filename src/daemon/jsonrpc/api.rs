use crate::threadmessages::*;

use std::{
    sync::atomic::{AtomicBool, Ordering},
    sync::mpsc::Sender,
    sync::Arc,
};

use jsonrpc_derive::rpc;

#[derive(Clone)]
pub struct JsonRpcMetaData {
    pub tx: Sender<ThreadMessage>,
    pub shutdown: Arc<AtomicBool>,
}
impl jsonrpc_core::Metadata for JsonRpcMetaData {}

impl JsonRpcMetaData {
    pub fn from_tx(tx: Sender<ThreadMessage>) -> Self {
        JsonRpcMetaData {
            tx,
            shutdown: Arc::from(AtomicBool::from(false)),
        }
    }

    pub fn is_shutdown(&self) -> bool {
        return self.shutdown.load(Ordering::Relaxed);
    }

    pub fn shutdown(&self) {
        // Relaxed is fine, worse case we just stop at the next iteration on ARM
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

#[rpc(server)]
pub trait RpcApi {
    type Metadata;

    /// Stops the daemon
    #[rpc(meta, name = "stop")]
    fn stop(&self, meta: Self::Metadata) -> jsonrpc_core::Result<()>;
}

pub struct RpcImpl;
impl RpcApi for RpcImpl {
    type Metadata = JsonRpcMetaData;

    fn stop(&self, meta: JsonRpcMetaData) -> jsonrpc_core::Result<()> {
        meta.shutdown();
        meta.tx
            .send(ThreadMessage::Rpc(RpcMessage::Shutdown))
            .unwrap();
        Ok(())
    }
}
