pub use revault_net;
pub use revault_tx;

mod bitcoind;
mod communication;
pub mod config;
mod control;
mod database;
mod jsonrpc;
mod revaultd;
mod sigfetcher;
mod threadmessages;
mod utils;

pub const VERSION: &str = "0.3.1";

use crate::{
    bitcoind::{bitcoind_main_loop, start_bitcoind},
    control::RpcUtils,
    database::actions::setup_db,
    jsonrpc::{
        server::{rpcserver_loop, rpcserver_setup},
        UserRole,
    },
    sigfetcher::signature_fetcher_loop,
    threadmessages::BitcoindSender,
};

pub use crate::revaultd::RevaultD;

use std::{
    io::{self, Write},
    panic, process,
    sync::{mpsc, Arc, RwLock},
    thread, time,
};

pub fn daemon_main(mut revaultd: RevaultD) {
    let user_role = match (revaultd.is_stakeholder(), revaultd.is_manager()) {
        (true, false) => UserRole::Stakeholder,
        (false, true) => UserRole::Manager,
        (true, true) => UserRole::ManagerStakeholder,
        _ => unreachable!(),
    };

    // First and foremost
    log::info!("Setting up database");
    setup_db(&mut revaultd).expect("Error setting up database");

    log::info!("Setting up bitcoind connection");
    let bitcoind = start_bitcoind(&mut revaultd).expect("Error setting up bitcoind");

    log::info!("Starting JSONRPC server");
    let socket = rpcserver_setup(revaultd.rpc_socket_file()).expect("Setting up JSONRPC server");

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
        bitcoind_main_loop(bitcoind_rx, bit_revaultd, Arc::new(RwLock::new(bitcoind)))
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

    // Handle RPC commands until we die.
    let bitcoind_thread = Arc::new(RwLock::new(bitcoind_thread));
    let sigfetcher_thread = Arc::new(RwLock::new(sigfetcher_thread));
    let rpc_utils = RpcUtils {
        revaultd,
        bitcoind_conn: BitcoindSender::from(bitcoind_tx),
        bitcoind_thread: bitcoind_thread.clone(),
        sigfetcher_tx,
        sigfetcher_thread: sigfetcher_thread.clone(),
    };
    rpcserver_loop(socket, user_role, rpc_utils).expect("Error in the main loop");

    // If the RPC server loop stops, we've been told to shutdown!
    let bitcoind_thread = unsafe { Arc::into_raw(bitcoind_thread).read().into_inner() };
    let sigfetcher_thread = unsafe { Arc::into_raw(sigfetcher_thread).read().into_inner() };
    bitcoind_thread
        .unwrap()
        .join()
        .expect("Joining bitcoind thread");
    sigfetcher_thread
        .unwrap()
        .join()
        .expect("Joining sigfetcher thread");

    // We are always logging to stdout, should it be then piped to the log file (if daemon) or
    // not. So just make sure that all messages were actually written.
    io::stdout().flush().expect("Flushing stdout");
}

// This creates the log file automagically if it doesn't exist, and logs on stdout
// if None is given
pub fn setup_logger(log_level: log::LevelFilter) -> Result<(), fern::InitError> {
    let dispatcher = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}][{}] {}",
                time::SystemTime::now()
                    .duration_since(time::UNIX_EPOCH)
                    .unwrap_or_else(|e| {
                        println!("Can't get time since epoch: '{}'. Using a dummy value.", e);
                        time::Duration::from_secs(0)
                    })
                    .as_secs(),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log_level);

    dispatcher.chain(std::io::stdout()).apply()?;

    Ok(())
}

// A panic in any thread should stop the main thread, and print the panic.
pub fn setup_panic_hook() {
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
