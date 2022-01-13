pub use revault_net;
pub use revault_tx;

mod bitcoind;
pub mod commands;
mod communication;
pub mod config;
mod database;
mod jsonrpc;
mod revaultd;
pub use crate::revaultd::*;
mod sigfetcher;
mod threadmessages;
mod utils;

// FIXME: make it an integer
pub const VERSION: &str = "0.3.1";

use crate::{
    bitcoind::{bitcoind_main_loop, start_bitcoind},
    database::actions::setup_db,
    jsonrpc::{
        server::{rpcserver_loop, rpcserver_setup},
        RpcUtils,
    },
    sigfetcher::signature_fetcher_loop,
    threadmessages::{BitcoindSender, BitcoindThread, SigFetcherSender, SigFetcherThread},
};

use std::{
    panic, process,
    sync::{mpsc, Arc, RwLock},
    thread,
};

// A panic in any thread should stop the main thread, and print the panic.
fn setup_panic_hook() {
    panic::set_hook(Box::new(move |panic_info| {
        let file = panic_info
            .location()
            .map(|l| l.file())
            .unwrap_or_else(|| "'unknown'");
        let line = panic_info
            .location()
            .map(|l| l.line().to_string())
            .unwrap_or_else(|| "'unknown'".to_string());

        let bt = backtrace::Backtrace::new();
        let info = panic_info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| panic_info.payload().downcast_ref::<String>().cloned());
        log::error!(
            "panic occurred at line {} of file {}: {:?}\n{:?}",
            line,
            file,
            info,
            bt
        );

        process::exit(1);
    }));
}

// FIXME: the fields shouldn't be publicly accessible
pub struct DaemonHandle {
    pub revaultd: Arc<RwLock<RevaultD>>,
    pub bitcoind: BitcoindSender,
    pub sigfetcher: SigFetcherSender,
    pub bitcoind_thread: thread::JoinHandle<()>,
    pub sigfetcher_thread: thread::JoinHandle<()>,
}

impl DaemonHandle {
    /// This starts the Revault daemon. Call `shutdown` to shut it down.
    ///
    /// **Note**: we internally use threads, and set a panic hook. A downstream application must
    /// not overwrite this panic hook.
    pub fn start(mut revaultd: RevaultD) -> Self {
        setup_panic_hook();

        // First and foremost
        log::info!("Setting up database");
        setup_db(&mut revaultd).expect("Error setting up database");

        log::info!("Setting up bitcoind connection");
        let bitcoind = start_bitcoind(&mut revaultd).expect("Error setting up bitcoind");

        // We start two threads, the bitcoind one to poll bitcoind for chain updates,
        // and the sigfetcher one to poll the coordinator for missing signatures
        // for pre-signed transactions.
        // The RPC requests are handled in the main thread, which may send requests
        // to the others.

        // The communication from us to the bitcoind thread
        let (bitcoind_tx, bitcoind_rx) = mpsc::channel();

        // The communication from us to the signature poller
        let (sigfetcher_tx, sigfetcher_rx) = mpsc::channel();

        let revaultd = Arc::new(RwLock::new(revaultd));
        let bit_revaultd = revaultd.clone();
        let bitcoind_thread = thread::spawn(move || {
            bitcoind_main_loop(bitcoind_rx, bit_revaultd, bitcoind)
                .expect("Error in bitcoind main loop");
        });

        let sigfetcher_revaultd = revaultd.clone();
        let sigfetcher_thread = thread::spawn(move || {
            signature_fetcher_loop(sigfetcher_rx, sigfetcher_revaultd)
                .expect("Error in signature fetcher thread")
        });

        log::info!(
            "revaultd started on network {}",
            revaultd.read().unwrap().bitcoind_config.network
        );
        let bitcoind: BitcoindSender = bitcoind_tx.into();
        let sigfetcher: SigFetcherSender = sigfetcher_tx.into();
        Self {
            revaultd,
            bitcoind,
            sigfetcher,
            bitcoind_thread,
            sigfetcher_thread,
        }
    }

    // NOTE: this moves out the data as it should not be reused after shutdown
    /// Shut down the Revault daemon.
    pub fn shutdown(self) {
        self.bitcoind.shutdown();
        self.sigfetcher.shutdown();

        self.bitcoind_thread
            .join()
            .expect("Joining bitcoind thread");
        self.sigfetcher_thread
            .join()
            .expect("Joining sigfetcher thread");
    }

    /// Run the RPC server until it receives a 'stop' command, then shutdown the daemon.
    pub fn rpc_server(self) {
        log::info!("Starting JSONRPC server");
        let socket = rpcserver_setup(self.revaultd.read().unwrap().rpc_socket_file())
            .expect("Setting up JSONRPC server");

        // Handle RPC commands until we die.
        let rpc_utils = RpcUtils {
            revaultd: self.revaultd.clone(),
            bitcoind_conn: self.bitcoind.clone(),
            sigfetcher_conn: self.sigfetcher.clone(),
        };
        rpcserver_loop(socket, rpc_utils).expect("Error in the main loop");

        self.shutdown();
    }
}
