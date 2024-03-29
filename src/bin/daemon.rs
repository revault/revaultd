use revault_net::sodiumoxide;
use std::{
    env,
    io::{self, Write},
    path::PathBuf,
    process, time,
};

use revaultd::{config::Config, DaemonHandle};

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

    let daemon_handle = DaemonHandle::start(config).unwrap_or_else(|e| {
        // The panic hook will log::error
        panic!("Starting Revault daemon: {}", e);
    });
    // Listen for incoming commands, then shutdown when we are stopped
    daemon_handle
        .rpc_server()
        .expect("Fatal error in JSONRPC server");
    log::info!("Stopping revaultd");
    daemon_handle.shutdown();

    // We are always logging to stdout, should it be then piped to the log file (if self) or
    // not. So just make sure that all messages were actually written.
    io::stdout().flush().expect("Flushing stdout");
}
