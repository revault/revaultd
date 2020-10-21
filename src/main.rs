mod bitcoind;
mod config;
mod revaultd;

use std::path::PathBuf;
use std::{env, process};

use bitcoind::interface::BitcoinD;
use config::parse_config;
use revaultd::RevaultD;

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
        eprintln!("Could not connect to bitcoind: {}", e.to_string());
        process::exit(1);
    });
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

    let mut daemon = Daemonize::default();
    // TODO: Make this configurable for inits
    daemon.pid_file = Some(
        [
            revaultd
                .data_dir
                .to_str()
                .expect("Impossible: the datadir path is valid unicode"),
            "revaultd.pid",
        ]
        .iter()
        .collect(),
    );
    daemon.doit().unwrap_or_else(|e| {
        eprintln!("Error daemonizing: {}", e);
        process::exit(1);
    });
    daemon_main(revaultd);
}
