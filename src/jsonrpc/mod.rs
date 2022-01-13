mod api;
pub mod server;

use crate::{
    revaultd::RevaultD,
    threadmessages::{BitcoindSender, SigFetcherSender},
};

use std::{
    sync::{Arc, RwLock},
    thread::JoinHandle,
};

#[derive(Clone)]
pub struct RpcUtils {
    pub revaultd: Arc<RwLock<RevaultD>>,
    pub bitcoind_conn: BitcoindSender,
    pub bitcoind_thread: Arc<RwLock<JoinHandle<()>>>,
    pub sigfetcher_conn: SigFetcherSender,
    pub sigfetcher_thread: Arc<RwLock<JoinHandle<()>>>,
}
