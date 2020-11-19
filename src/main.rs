mod bitcoind;
mod config;
mod database;
mod revaultd;

use crate::{
    bitcoind::actions::{bitcoind_main_loop, setup_bitcoind},
    config::Config,
    database::actions::setup_db,
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

fn daemon_main(mut revaultd: RevaultD) {
    // First and foremost
    setup_db(&mut revaultd).unwrap_or_else(|e| {
        log::error!("Error setting up database: '{}'", e.to_string());
        process::exit(1);
    });

    let bitcoind = setup_bitcoind(&mut revaultd).unwrap_or_else(|e| {
        log::error!("Error setting up bitcoind: {}", e.to_string());
        process::exit(1);
    });

    log::info!(
        "revaultd started on network {}",
        revaultd.bitcoind_config.network
    );

    // We poll bitcoind until we die
    bitcoind_main_loop(&mut revaultd, &bitcoind).unwrap_or_else(|e| {
        log::error!("Error in bitcoind main loop: {}", e.to_string());
        process::exit(1);
    });
}

// This creates the log file automagically if it doesn't exist, and logs on stdout
// if None is given
fn setup_logger(log_file: Option<&str>) -> Result<(), fern::InitError> {
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
        // FIXME: make this configurable
        .level(log::LevelFilter::Trace);

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
    setup_logger(log_output).unwrap_or_else(|e| {
        eprintln!("Error setting up logger: {}", e);
        process::exit(1);
    });

    if revaultd.daemon {
        let mut daemon = Daemonize::default();
        // TODO: Make this configurable for inits
        daemon.pid_file = Some(revaultd.pid_file());
        daemon.doit().unwrap_or_else(|e| {
            eprintln!("Error daemonizing: {}", e);
            process::exit(1);
        });
        println!("Started revaultd daemon");
    }

    daemon_main(revaultd);
}
