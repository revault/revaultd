mod bitcoind;
mod control;
mod database;
mod jsonrpc;
mod revaultd;
mod sigfetcher;
mod threadmessages;
mod utils;

use crate::{
    bitcoind::{bitcoind_main_loop, start_bitcoind},
    control::RpcUtils,
    database::actions::setup_db,
    jsonrpc::{
        server::{rpcserver_loop, rpcserver_setup},
        UserRole,
    },
    revaultd::RevaultD,
    sigfetcher::signature_fetcher_loop,
};
use common::{assume_ok, config::Config};
use revault_net::sodiumoxide;
use revault_tx::bitcoin::hashes::hex::ToHex;

use std::{
    env,
    io::{self, Write},
    panic,
    path::PathBuf,
    process,
    sync::{mpsc, Arc, RwLock},
    thread, time,
};

use daemonize_simple::Daemonize;

fn parse_args(args: Vec<String>) -> Option<PathBuf> {
    if args.len() == 1 {
        return None;
    }

    if args.len() != 3 {
        eprintln!("Unknown arguments '{:?}'.", args);
        eprintln!("Only '--conf <configuration file path>' is supported.");
        process::exit(1);
    }

    Some(PathBuf::from(args[2].to_owned()))
}

fn daemon_main(mut revaultd: RevaultD) {
    let user_role = match (revaultd.is_stakeholder(), revaultd.is_manager()) {
        (true, false) => UserRole::Stakeholder,
        (false, true) => UserRole::Manager,
        (true, true) => UserRole::ManagerStakeholder,
        _ => unreachable!(),
    };

    // First and foremost
    log::info!("Setting up database");
    assume_ok!(setup_db(&mut revaultd), "Error setting up database");

    log::info!("Setting up bitcoind connection");
    let bitcoind = assume_ok!(start_bitcoind(&mut revaultd), "Error setting up bitcoind");

    log::info!("Starting JSONRPC server");
    let socket = assume_ok!(
        rpcserver_setup(revaultd.rpc_socket_file()),
        "Setting up JSONRPC server"
    );

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
        assume_ok!(
            bitcoind_main_loop(bitcoind_rx, bit_revaultd, Arc::new(RwLock::new(bitcoind))),
            "Error in bitcoind main loop"
        );
    });

    let sigfetcher_revaultd = revaultd.clone();
    let sigfetcher_thread = thread::spawn(move || {
        assume_ok!(
            signature_fetcher_loop(sigfetcher_rx, sigfetcher_revaultd),
            "Error in signature fetcher thread"
        )
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
        bitcoind_tx,
        bitcoind_thread: bitcoind_thread.clone(),
        sigfetcher_tx,
        sigfetcher_thread: sigfetcher_thread.clone(),
    };
    assume_ok!(
        rpcserver_loop(socket, user_role, rpc_utils),
        "Error in the main loop"
    );

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
    assume_ok!(io::stdout().flush(), "Flushing stdout");
}

// This creates the log file automagically if it doesn't exist, and logs on stdout
// if None is given
fn setup_logger(log_level: log::LevelFilter) -> Result<(), fern::InitError> {
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

        if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            log::error!("panic occurred at line {} of file {}: {:?}", line, file, s);
        } else {
            log::error!("panic occurred at line {} of file {}", line, file);
        }

        process::exit(1);
    }));
}

fn main() {
    let args = env::args().collect();
    let conf_file = parse_args(args);

    // We use libsodium for Noise keys and Noise channels (through revault_net)
    sodiumoxide::init().unwrap_or_else(|_| {
        eprintln!("Error init'ing libsodium");
        process::exit(1);
    });

    let config = Config::from_file(conf_file).unwrap_or_else(|e| {
        eprintln!("Error parsing config: {}", e);
        process::exit(1);
    });
    setup_logger(config.log_level).unwrap_or_else(|e| {
        eprintln!("Error setting up logger: {}", e);
        process::exit(1);
    });
    // FIXME: should probably be from_db(), would allow us to not use Option members
    let revaultd = RevaultD::from_config(config).unwrap_or_else(|e| {
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

    setup_panic_hook();

    if revaultd.daemon {
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
            eprintln!("Error daemonizing: {}", e);
            process::exit(1);
        });
        println!("Started revaultd daemon");
    }

    daemon_main(revaultd);
}
