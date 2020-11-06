mod bitcoind;
mod config;
mod revaultd;

use crate::{
    bitcoind::{
        actions::{bitcoind_sanity_checks, wait_for_bitcoind_synced},
        interface::BitcoinD,
    },
    config::parse_config,
    revaultd::RevaultD,
};

use std::path::PathBuf;
use std::{env, process};

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

fn daemon_main(revaultd: RevaultD) {
    let bitcoind = BitcoinD::new(&revaultd.bitcoind_config).unwrap_or_else(|e| {
        log::error!("Could not connect to bitcoind: {}", e.to_string());
        process::exit(1);
    });

    bitcoind_sanity_checks(&bitcoind, &revaultd.bitcoind_config).unwrap_or_else(|e| {
        // FIXME: handle warming up
        log::error!("Error checking bitcoind: {}", e.to_string());
        process::exit(1);
    });

    wait_for_bitcoind_synced(&bitcoind, &revaultd.bitcoind_config).unwrap_or_else(|e| {
        log::error!("Error while updating tip: {}", e.to_string());
        process::exit(1);
    });

    log::info!(
        "revaultd started on network {}",
        revaultd.bitcoind_config.network
    );
}

// This creates the log file automagically if it doesn't exist
fn setup_logger<'a>(log_file: &'a str) -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        // FIXME: make this configurable
        .level(log::LevelFilter::Trace)
        .chain(fern::log_file(log_file)?)
        .apply()?;

    Ok(())
}

fn main() {
    let args = env::args().collect();
    let conf_file = parse_args(args);

    let config = parse_config(conf_file).unwrap_or_else(|e| {
        eprintln!("Error parsing config: {}", e);
        process::exit(1);
    });
    let revaultd = RevaultD::from_config(config).unwrap_or_else(|e| {
        eprintln!("Error creating global state: {}", e);
        process::exit(1);
    });
    let data_dir_str = revaultd
        .data_dir
        .to_str()
        .expect("Impossible: the datadir path is valid unicode");

    let log_file: PathBuf = [data_dir_str, "log"].iter().collect();
    setup_logger(&log_file.to_str().expect("Valid unicode")).unwrap_or_else(|e| {
        eprintln!("Error setting up logger: {}", e);
        process::exit(1);
    });

    let mut daemon = Daemonize::default();
    // TODO: Make this configurable for inits
    daemon.pid_file = Some([data_dir_str, "revaultd.pid"].iter().collect());
    daemon.doit().unwrap_or_else(|e| {
        eprintln!("Error daemonizing: {}", e);
        process::exit(1);
    });
    daemon_main(revaultd);
}
