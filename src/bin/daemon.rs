use revault_net::sodiumoxide;
use revault_tx::bitcoin::hashes::hex::ToHex;
use std::{env, path::PathBuf, process, time};

use daemonize_simple::Daemonize;
use revaultd::{config::Config, daemon_start, rpc_server_loop, RevaultD};

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

    let daemon_handle = daemon_start(revaultd);
    rpc_server_loop(daemon_handle);
}
