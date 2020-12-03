use crate::threadmessages::*;
use common::VERSION;

use std::{
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender},
        Arc,
    },
};

use jsonrpc_derive::rpc;
use serde_json::json;

#[derive(Clone)]
pub struct JsonRpcMetaData {
    pub tx: Sender<ThreadMessageIn>,
    pub shutdown: Arc<AtomicBool>,
}
impl jsonrpc_core::Metadata for JsonRpcMetaData {}

impl JsonRpcMetaData {
    pub fn from_tx(tx: Sender<ThreadMessageIn>) -> Self {
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

    /// Get informations about the daemon
    #[rpc(meta, name = "getinfo")]
    fn getinfo(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value>;
}

pub struct RpcImpl;
impl RpcApi for RpcImpl {
    type Metadata = JsonRpcMetaData;

    fn stop(&self, meta: JsonRpcMetaData) -> jsonrpc_core::Result<()> {
        meta.shutdown();
        meta.tx
            .send(ThreadMessageIn::Rpc(RpcMessageIn::Shutdown))
            .unwrap();
        Ok(())
    }

    fn getinfo(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value> {
        let (response_tx, response_rx) = mpsc::sync_channel(0);
        meta.tx
            .send(ThreadMessageIn::Rpc(RpcMessageIn::GetInfo(response_tx)))
            .unwrap_or_else(|e| {
                log::error!("Sending 'getinfo' to main thread: {:?}", e);
                process::exit(1);
            });
        let (net, height, progress) = response_rx.recv().unwrap_or_else(|e| {
            log::error!("Receiving 'getinfo' result from main thread: {:?}", e);
            process::exit(1);
        });

        Ok(json!({
            "version": VERSION.to_string(),
            "network": net,
            "blockheight": height,
            "sync": progress,
        }))
    }
}
