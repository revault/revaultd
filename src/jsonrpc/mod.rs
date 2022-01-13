mod api;
pub mod server;

use crate::{
    revaultd::RevaultD,
    threadmessages::{BitcoindSender, SigFetcherSender},
};

use std::sync::{Arc, RwLock};

// TODO: would be nice to harmonize with DaemonHandle..
/// Data needed to handle JSONRPC requests.
#[derive(Clone)]
pub struct RpcUtils {
    pub revaultd: Arc<RwLock<RevaultD>>,
    pub bitcoind_conn: BitcoindSender,
    pub sigfetcher_conn: SigFetcherSender,
}
