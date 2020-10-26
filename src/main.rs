mod bitcoind;
mod config;
mod database;
mod revaultd;

use crate::{bitcoind::actions::setup_bitcoind, config::parse_config, revaultd::RevaultD};

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
    // This aborts on error
    let bitcoind = setup_bitcoind(&revaultd);

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

    setup_logger(&revaultd.log_file().to_str().expect("Valid unicode")).unwrap_or_else(|e| {
        eprintln!("Error setting up logger: {}", e);
        process::exit(1);
    });

    let mut daemon = Daemonize::default();
    // TODO: Make this configurable for inits
    daemon.pid_file = Some(revaultd.pid_file());
    daemon.doit().unwrap_or_else(|e| {
        eprintln!("Error daemonizing: {}", e);
        process::exit(1);
    });
    daemon_main(revaultd);
}
