use crate::{
    bitcoind::actions::{bitcoind_main_loop, setup_bitcoind},
    database::actions::setup_db,
    revaultd::RevaultD,
};

pub fn start(mut revaultd: RevaultD) -> Result<(), Box<dyn std::error::Error>> {
    // First and foremost
    setup_db(&mut revaultd).map_err(|e| {
        log::error!("Error setting up database: '{}'", e.to_string());
        e
    })?;

    // This aborts on error
    let bitcoind = setup_bitcoind(&mut revaultd)?;

    log::info!(
        "revaultd started on network {}",
        revaultd.bitcoind_config.network
    );

    // We poll bitcoind until we die
    bitcoind_main_loop(&mut revaultd, &bitcoind).map_err(|e| {
        log::error!("Error in bitcoind main loop: {}", e.to_string());
        e
    })?;

    Ok(())
}
