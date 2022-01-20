pub use revault_net;
pub use revault_tx;

mod bitcoind;
pub mod commands;
mod communication;
pub mod config;
mod database;
mod jsonrpc;
mod revaultd;
mod sigfetcher;
mod threadmessages;
mod utils;

// FIXME: make it an integer
pub const VERSION: &str = "0.3.1";

pub use crate::revaultd::{CpfpKeyError, NoiseKeyError};
use crate::{
    bitcoind::{bitcoind_main_loop, start_bitcoind, BitcoindError},
    commands::DaemonCommands,
    config::Config,
    database::{actions::setup_db, DatabaseError},
    revaultd::RevaultD,
    sigfetcher::signature_fetcher_loop,
    threadmessages::{BitcoindSender, BitcoindThread, SigFetcherSender, SigFetcherThread},
};
use revault_tx::bitcoin::hashes::hex::ToHex;

use std::{
    error, fmt, io, panic, process,
    sync::{mpsc, Arc, RwLock, RwLockReadGuard},
    thread,
};

use daemonize_simple::Daemonize;

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

#[derive(Debug)]
pub enum StartupError {
    Cpfp(CpfpKeyError),
    Noise(NoiseKeyError),
    Io(io::Error),
    DefaultDatadir,
    Db(DatabaseError),
    Bitcoind(BitcoindError),
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Cpfp(e) => write!(f, "{}", e),
            Self::Noise(e) => write!(f, "{}", e),
            Self::Io(e) => write!(f, "{}", e),
            Self::DefaultDatadir => write!(f, "Could not locate the default data directory."),
            Self::Db(e) => write!(f, "Database error when starting revaultd: '{}'", e),
            Self::Bitcoind(e) => write!(f, "Bitcoind error when starting revaultd: '{}'", e),
        }
    }
}

impl error::Error for StartupError {}

impl From<BitcoindError> for StartupError {
    fn from(e: BitcoindError) -> Self {
        Self::Bitcoind(e)
    }
}

impl From<CpfpKeyError> for StartupError {
    fn from(e: CpfpKeyError) -> Self {
        Self::Cpfp(e)
    }
}

impl From<DatabaseError> for StartupError {
    fn from(e: DatabaseError) -> Self {
        Self::Db(e)
    }
}

impl From<io::Error> for StartupError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<NoiseKeyError> for StartupError {
    fn from(e: NoiseKeyError) -> Self {
        Self::Noise(e)
    }
}

#[derive(Clone)]
pub struct DaemonControl {
    revaultd: Arc<RwLock<RevaultD>>,
    bitcoind_conn: BitcoindSender,
    sigfetcher_conn: SigFetcherSender,
}

impl DaemonControl {
    pub fn new(
        revaultd: Arc<RwLock<RevaultD>>,
        bitcoind_conn: BitcoindSender,
        sigfetcher_conn: SigFetcherSender,
    ) -> Self {
        Self {
            revaultd,
            bitcoind_conn,
            sigfetcher_conn,
        }
    }

    /// Send a shutdown message to the threads
    pub(crate) fn send_shutdown(&self) {
        self.bitcoind_conn.shutdown();
        self.sigfetcher_conn.shutdown();
    }

    // TODO: make it optional at compile time
    /// Start and bind the server to the configured UNIX socket
    pub fn rpc_server_setup(&self) -> Result<jsonrpc::server::UnixListener, io::Error> {
        let socket_file = self.revaultd.read().unwrap().rpc_socket_file();
        jsonrpc::server::rpcserver_setup(socket_file)
    }
}

impl DaemonCommands for DaemonControl {
    fn revaultd(&self) -> RwLockReadGuard<RevaultD> {
        self.revaultd.read().unwrap()
    }
    fn bitcoind(&self) -> &dyn BitcoindThread {
        &self.bitcoind_conn
    }
}

pub struct DaemonHandle {
    pub control: DaemonControl,
    bitcoind_thread: thread::JoinHandle<()>,
    sigfetcher_thread: thread::JoinHandle<()>,
}

impl DaemonHandle {
    /// This starts the Revault daemon. Call `shutdown` to shut it down.
    ///
    /// **Note**: we internally use threads, and set a panic hook. A downstream application must
    /// not overwrite this panic hook.
    pub fn start(config: Config) -> Result<Self, StartupError> {
        setup_panic_hook();

        // FIXME: should probably be from_db(), would allow us to not use Option members
        let mut revaultd = RevaultD::from_config(config).unwrap_or_else(|e| {
            log::error!("Error creating global state: {}", e);
            process::exit(1);
        });
        log::info!(
            "Using Noise static public key: '{}'",
            revaultd.noise_pubkey().0.to_hex()
        );
        log::debug!(
            "Coordinator static public key: '{}'",
            revaultd.coordinator_noisekey.0.to_hex()
        );

        // First and foremost
        log::info!("Setting up database");
        setup_db(&mut revaultd)?;

        log::info!("Setting up bitcoind connection");
        let bitcoind = start_bitcoind(&mut revaultd)?;

        // NOTE: it's safe to daemonize now, as we don't carry any open DB connection
        // https://www.sqlite.org/howtocorrupt.html#_carrying_an_open_database_connection_across_a_fork_
        if revaultd.daemon {
            log::info!("Daemonizing");
            let log_file = revaultd.log_file();
            let daemon = Daemonize {
                // TODO: Make this configurable for inits
                pid_file: Some(revaultd.pid_file()),
                stdout_file: Some(log_file.clone()),
                stderr_file: Some(log_file),
                chdir: Some(revaultd.data_dir.clone()),
                append: true,
                ..Daemonize::default()
            };
            daemon.doit().unwrap_or_else(|e| {
                // The panic hook will log::error
                panic!("Error daemonizing: {}", e);
            });
        }

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
        Ok(Self {
            control: DaemonControl::new(revaultd, bitcoind, sigfetcher),
            bitcoind_thread,
            sigfetcher_thread,
        })
    }

    // NOTE: this moves out the data as it should not be reused after shutdown
    /// Shut down the Revault daemon.
    pub fn shutdown(self) {
        self.control.send_shutdown();

        self.bitcoind_thread
            .join()
            .expect("Joining bitcoind thread");
        self.sigfetcher_thread
            .join()
            .expect("Joining sigfetcher thread");
    }

    // TODO: make it optional at compilation time
    /// Start the JSONRPC server and listen for commands until we are stopped
    pub fn rpc_server(&self) -> Result<(), io::Error> {
        log::info!("Starting JSONRPC server");

        let socket = self.control.rpc_server_setup()?;
        jsonrpc::server::rpcserver_loop(socket, self.control.clone())
    }
}
