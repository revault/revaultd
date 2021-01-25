mod bitcoind;
mod control;
mod database;
mod jsonrpc;
mod revaultd;
mod threadmessages;

use crate::{
    bitcoind::actions::{bitcoind_main_loop, start_bitcoind},
    control::handle_rpc_messages,
    database::actions::setup_db,
    jsonrpc::server::{rpcserver_loop, rpcserver_setup},
    revaultd::RevaultD,
};
use common::{assume_ok, config::Config};
use revault_tx::bitcoin::hashes::hex::ToHex;

use std::{
    env,
    path::PathBuf,
    process,
    str::FromStr,
    sync::{mpsc, Arc, RwLock},
    thread,
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
    let (db_path, network) = (revaultd.db_file(), revaultd.bitcoind_config.network);

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

    // We start two threads, the JSONRPC one in order to be controlled externally,
    // and the bitcoind one to poll bitcoind until we die.
    // We may get requests from the RPC one, and send requests to the bitcoind one.

    // The communication from them to us
    let (rpc_tx, rpc_rx) = mpsc::channel();

    // The communication from us to the bitcoind thread
    let (bitcoind_tx, bitcoind_rx) = mpsc::channel();

    let rpc_thread = thread::spawn(move || {
        assume_ok!(
            rpcserver_loop(rpc_tx, socket),
            "Error in JSONRPC server event loop"
        );
    });

    let revaultd = Arc::new(RwLock::new(revaultd));
    let bit_revaultd = revaultd.clone();
    let bitcoind_thread = thread::spawn(move || {
        assume_ok!(
            bitcoind_main_loop(bitcoind_rx, bit_revaultd, &bitcoind),
            "Error in bitcoind main loop"
        );
    });

    log::info!(
        "revaultd started on network {}",
        revaultd.read().unwrap().bitcoind_config.network
    );
    // Handle RPC commands until we die.
    assume_ok!(
        handle_rpc_messages(
            revaultd,
            db_path,
            network,
            rpc_rx,
            bitcoind_tx,
            bitcoind_thread,
            rpc_thread,
        ),
        "Error in main loop"
    );
}

// This creates the log file automagically if it doesn't exist, and logs on stdout
// if None is given
fn setup_logger(
    log_file: Option<&str>,
    log_level: log::LevelFilter,
) -> Result<(), fern::InitError> {
    let dispatcher = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log_level);

    if let Some(log_file) = log_file {
        dispatcher.chain(fern::log_file(log_file)?).apply()?;
    } else {
        dispatcher.chain(std::io::stdout()).apply()?;
    }

    Ok(())
}

fn main() {
    let args = env::args().collect();
    let conf_file = parse_args(args);

    let config = Config::from_file(conf_file).unwrap_or_else(|e| {
        eprintln!("Error parsing config: {}", e);
        process::exit(1);
    });
    let log_level = if let Some(ref level) = &config.log_level {
        log::LevelFilter::from_str(level.as_str()).unwrap_or_else(|e| {
            eprintln!("Invalid log level: {}", e);
            process::exit(1);
        })
    } else {
        log::LevelFilter::Info
    };
    // FIXME: should probably be from_db(), would allow us to not use Option members
    let revaultd = RevaultD::from_config(config).unwrap_or_else(|e| {
        eprintln!("Error creating global state: {}", e);
        process::exit(1);
    });

    let log_file = revaultd.log_file();
    let log_output = if revaultd.daemon {
        Some(log_file.to_str().expect("Valid unicode"))
    } else {
        None
    };
    setup_logger(log_output, log_level).unwrap_or_else(|e| {
        eprintln!("Error setting up logger: {}", e);
        process::exit(1);
    });
    log::info!(
        "Using Noise static public key: '{}'",
        revaultd.noise_secret.pubkey().0.to_hex()
    );

    if revaultd.daemon {
        let daemon = Daemonize {
            // TODO: Make this configurable for inits
            pid_file: Some(revaultd.pid_file()),
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
