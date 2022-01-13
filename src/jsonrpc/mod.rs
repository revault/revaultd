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

/// Some calls are Stakeholder-only or Manager-only. This makes the API code
/// aware of whether we were started as such to immediately forbid some of them.
#[derive(Debug, Clone, Copy)]
pub enum UserRole {
    Manager,
    Stakeholder,
    ManagerStakeholder,
}

#[derive(Clone)]
pub struct RpcUtils {
    pub revaultd: Arc<RwLock<RevaultD>>,
    pub bitcoind_conn: BitcoindSender,
    pub bitcoind_thread: Arc<RwLock<JoinHandle<()>>>,
    pub sigfetcher_conn: SigFetcherSender,
    pub sigfetcher_thread: Arc<RwLock<JoinHandle<()>>>,
}
