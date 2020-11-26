use crate::{
    bitcoind::{interface::BitcoinD, BitcoindError},
    database::{
        actions::{db_insert_new_vault, db_unvault_deposit},
        interface::db_wallet,
    },
    revaultd::RevaultD,
    threadmessages::ThreadMessage,
};
use common::config::BitcoindConfig;
use revault_tx::{
    bitcoin::{consensus::encode, hashes::hex::FromHex, Network, Transaction},
    transactions::VaultTransaction,
};

use std::{
    sync::{mpsc::Sender, Arc, RwLock},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn check_bitcoind_network(
    bitcoind: &BitcoinD,
    config_network: &Network,
) -> Result<(), BitcoindError> {
    let chaininfo = bitcoind.getblockchaininfo()?;
    let chain = chaininfo
        .get("chain")
        .and_then(|c| c.as_str())
        .ok_or_else(|| {
            BitcoindError("No valid 'chain' in getblockchaininfo response?".to_owned())
        })?;
    let bip70_net = match config_network {
        Network::Bitcoin => "main",
        Network::Testnet => "test",
        Network::Regtest => "regtest",
    };

    if !bip70_net.eq(chain) {
        return Err(BitcoindError(format!(
            "Wrong network, bitcoind is on '{}' but our config says '{}' ({})",
            chain, bip70_net, config_network
        )));
    }

    Ok(())
}

/// Some sanity checks to be done at startup to make sure our bitcoind isn't going to fail under
/// our feet for a legitimate reason.
fn bitcoind_sanity_checks(
    bitcoind: &BitcoinD,
    bitcoind_config: &BitcoindConfig,
) -> Result<(), BitcoindError> {
    check_bitcoind_network(&bitcoind, &bitcoind_config.network)
}

/// Polls bitcoind until we are synced.
/// Tries to be smart with getblockchaininfo calls.
fn wait_for_bitcoind_synced(
    bitcoind: &BitcoinD,
    bitcoind_config: &BitcoindConfig,
) -> Result<(), BitcoindError> {
    // We need to take the edge case in which all headers aren't downloaded yet
    // into account.
    let mut first = true;

    loop {
        let chaininfo = bitcoind.getblockchaininfo()?;
        let (headers, blocks, ibd) = (
            chaininfo
                .get("headers")
                .and_then(|h| h.as_u64())
                .ok_or_else(|| {
                    BitcoindError("No valid 'headers' in getblockchaininfo response?".to_owned())
                })?,
            chaininfo
                .get("blocks")
                .and_then(|b| b.as_u64())
                .ok_or_else(|| {
                    BitcoindError("No valid 'blocks' in getblockchaininfo response?".to_owned())
                })?,
            chaininfo
                .get("initialblockdownload")
                .and_then(|i| i.as_bool())
                .ok_or_else(|| {
                    BitcoindError(
                        "No valid 'initialblockdownload' in getblockchaininfo response?".to_owned(),
                    )
                })?,
        );
        let mut delta = if headers > blocks {
            headers - blocks
        } else {
            0
        };

        if ibd {
            // Ok, so we have some time. Let's try to avoid slowing it down by
            // spamming it with getblockchaininfo calls.

            if first {
                log::info!(
                    "Bitcoind is currently performing IBD, this is going to \
                        take some time."
                );
            }

            // First: wait for it to gather all headers, if the current delta is
            // big enough. let's assume it won't take longer than 5min from now
            // for mainnet.
            // Then: get the number of blocks left to DL
            if (first || delta > 1_000) && blocks < 100_000 {
                log::info!("Waiting for bitcoind to gather enough headers..");
                if bitcoind_config.network.to_string().eq("regtest") {
                    thread::sleep(Duration::from_secs(3));
                } else {
                    thread::sleep(Duration::from_secs(5 * 60));
                }

                let chaininfo = bitcoind.getblockchaininfo()?;
                let (headers, blocks) = (
                    chaininfo
                        .get("headers")
                        .and_then(|h| h.as_u64())
                        .ok_or_else(|| {
                            BitcoindError(
                                "No valid 'headers' in getblockchaininfo response?".to_owned(),
                            )
                        })?,
                    chaininfo
                        .get("blocks")
                        .and_then(|b| b.as_u64())
                        .ok_or_else(|| {
                            BitcoindError(
                                "No valid 'blocks' in getblockchaininfo response?".to_owned(),
                            )
                        })?,
                );
                delta = headers - blocks;
            }
        } else if delta == 0 {
            return Ok(());
        }

        // Sleeping a second per 20 blocks seems a good upper bound estimation
        // (~7h for 500_000 blocks), so we divide it by 2 here in order to be
        // conservative. Eg if 10_000 are left to be downloaded we'll check back
        // in ~4min.
        let sleep_duration = Duration::from_secs(delta / 20 / 2);
        log::info!("We'll poll bitcoind again in {:?} seconds", sleep_duration);
        // FIXME: maybe Edouard will need more fine-grained updates eventually
        thread::sleep(sleep_duration);

        first = false;
    }
}

fn unload_all_wallets(bitcoind: &BitcoinD) -> Result<(), BitcoindError> {
    for wallet_name in bitcoind.listwallets()? {
        bitcoind.unloadwallet(wallet_name)?;
    }

    Ok(())
}

// This creates the actual wallet file, and imports the descriptors
fn maybe_create_wallet(revaultd: &mut RevaultD, bitcoind: &BitcoinD) -> Result<(), BitcoindError> {
    let wallet = db_wallet(&revaultd.db_file())
        .map_err(|e| BitcoindError(format!("Error getting wallet from db: {}", e.to_string())))?;
    let bitcoind_wallet_path = revaultd.watchonly_wallet_file(wallet.id);
    let bitcoind_wallet_str = bitcoind_wallet_path
        .to_str()
        .expect("Path is valid unicode")
        .to_string();
    // Did we just create the wallet ?
    let curr_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_secs())
        .map_err(|e| BitcoindError(format!("Computing time since epoch: {}", e.to_string())))?;
    let fresh_wallet = (curr_timestamp - wallet.timestamp as u64) < 30;

    if !bitcoind_wallet_path.exists() {
        bitcoind.createwallet_startup(bitcoind_wallet_str)?;

        // Now, import descriptors.
        // TODO: maybe warn, depending on the timestamp, that it's going to take some time.
        // In theory, we could just import the vault (deposit) descriptor expressed using xpubs, give a
        // range to bitcoind as the gap limit, and be fine.
        // Unfortunately we cannot just import descriptors as is, since bitcoind does not support
        // Miniscript ones yet. Worse, we actually need to derive them to pass them to bitcoind since
        // the vault one (which we are interested about) won't be expressed with a `multi()` statement (
        // currently supported by bitcoind) if there are more than 15 stakeholders.
        // Therefore, we derive [max index] `addr()` descriptors to import into bitcoind, and handle
        // the derivation index mess ourselves :'(
        let mut addresses = revaultd.all_deposit_addresses();
        for i in 0..addresses.len() {
            addresses[i] = bitcoind.addr_descriptor(&addresses[i])?;
        }
        log::trace!("Importing deposit descriptors '{:?}'", &addresses);
        bitcoind.startup_import_deposit_descriptors(addresses, wallet.timestamp, fresh_wallet)?;

        // As a consequence, we don't have enough information to opportunistically import a
        // descriptor at the reception of a deposit anymore. Thus we need to blindly import *both*
        // deposit and unvault descriptors..
        let mut addresses = revaultd.all_unvault_addresses();
        for i in 0..addresses.len() {
            addresses[i] = bitcoind.addr_descriptor(&addresses[i])?;
        }
        log::trace!("Importing unvault descriptors '{:?}'", &addresses);
        bitcoind.startup_import_unvault_descriptors(addresses, wallet.timestamp, fresh_wallet)?;
    }

    Ok(())
}

fn maybe_load_wallet(revaultd: &RevaultD, bitcoind: &BitcoinD) -> Result<(), BitcoindError> {
    let wallet = db_wallet(&revaultd.db_file())
        .map_err(|e| BitcoindError(format!("Error getting wallet from db: {}", e.to_string())))?;
    let bitcoind_wallet_path = revaultd
        .watchonly_wallet_file(wallet.id)
        .to_str()
        .expect("Path is valid unicode")
        .to_string();

    if !bitcoind.listwallets()?.contains(&bitcoind_wallet_path) {
        log::info!("Loading wallet '{}'.", bitcoind_wallet_path);
        bitcoind.loadwallet_startup(bitcoind_wallet_path.clone())?;
    }

    Ok(())
}

/// Connects to, sanity checks, and wait for bitcoind to be synced.
/// Called at startup, will log and abort on error.
pub fn setup_bitcoind(revaultd: &mut RevaultD) -> Result<BitcoinD, BitcoindError> {
    let bitcoind = BitcoinD::new(&revaultd.bitcoind_config)
        .map_err(|e| BitcoindError(format!("Could not connect to bitcoind: {}", e.to_string())))?;

    bitcoind_sanity_checks(&bitcoind, &revaultd.bitcoind_config).map_err(|e| {
        // FIXME: handle warming up
        BitcoindError(format!("Error checking bitcoind: {}", e.to_string()))
    })?;

    wait_for_bitcoind_synced(&bitcoind, &revaultd.bitcoind_config)
        .map_err(|e| BitcoindError(format!("Error while updating tip: {}", e.to_string())))?;

    unload_all_wallets(&bitcoind)
        .map_err(|e| BitcoindError(format!("Unloading existing wallets: {}", e.to_string())))?;

    maybe_create_wallet(revaultd, &bitcoind)
        .map_err(|e| BitcoindError(format!("Error while creating wallet: {}", e.to_string())))?;

    maybe_load_wallet(&revaultd, &bitcoind)
        .map_err(|e| BitcoindError(format!("Error while loading wallet: {}", e.to_string())))?;

    Ok(bitcoind)
}

fn tx_from_hex(hex: &str) -> Result<Transaction, BitcoindError> {
    let mut bytes = Vec::from_hex(hex)
        .map_err(|e| BitcoindError(format!("Parsing tx hex: '{}'", e.to_string())))?;
    encode::deserialize::<Transaction>(&mut bytes)
        .map_err(|e| BitcoindError(format!("Deserializing tx hex: '{}'", e.to_string())))
}

fn poll_bitcoind(
    revaultd: &mut Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
) -> Result<(), BitcoindError> {
    let (new_deposits, spent_deposits) =
        bitcoind.sync_deposits(&revaultd.read().unwrap().vaults)?;

    for (outpoint, utxo) in new_deposits.into_iter() {
        let derivation_index = *revaultd
            .read()
            .unwrap()
            .derivation_index_map
            .get(&utxo.txo.script_pubkey)
            .ok_or_else(|| BitcoindError(format!("Unknown derivation index for: {:#?}", &utxo)))?;
        let wallet_tx = bitcoind.get_wallet_transaction(outpoint.txid)?;
        let vault_tx = VaultTransaction(tx_from_hex(&wallet_tx.0).map_err(|e| {
            BitcoindError(format!(
                "Deserializing tx from hex: '{}'. Transaction: '{}'",
                e.to_string(),
                wallet_tx.0
            ))
        })?);
        let blockheight = wallet_tx
            .1
            .ok_or_else(|| BitcoindError("Deposit transaction isn't confirmed!".to_string()))?;

        db_insert_new_vault(
            &revaultd.read().unwrap().db_file(),
            revaultd.read().unwrap().wallet_id,
            utxo.status,
            blockheight,
            outpoint.txid.to_vec(),
            outpoint.vout,
            utxo.txo.value as u32,
            derivation_index,
            vault_tx,
        )
        .map_err(|e| BitcoindError(format!("Database error: {}", e.to_string())))?;
        revaultd.write().unwrap().vaults.insert(outpoint, utxo);

        // Mind the gap! https://www.youtube.com/watch?v=UOPyGKDQuRk
        // FIXME: of course, that's rudimentary
        if derivation_index > revaultd.read().unwrap().current_unused_index {
            revaultd.write().unwrap().current_unused_index += 1;
            let next_addr = bitcoind
                .addr_descriptor(&revaultd.write().unwrap().last_deposit_address().to_string())?;
            bitcoind.import_fresh_deposit_descriptor(next_addr)?;
            let next_addr = bitcoind
                .addr_descriptor(&revaultd.write().unwrap().last_unvault_address().to_string())?;
            bitcoind.import_fresh_unvault_descriptor(next_addr)?;
        }
    }

    for (outpoint, utxo) in spent_deposits.into_iter() {
        let deriv_index = *revaultd.read().unwrap()
            .derivation_index_map
            .get(&utxo.txo.script_pubkey)
            .ok_or_else(|| BitcoindError(
                    format!("A deposit was spent for which we don't know the corresponding xpub derivation. Outpoint: '{}'\nUtxo: '{:#?}'",
                        &outpoint,
                        &utxo)))?;
        let unvault_addr = revaultd
            .write()
            .unwrap()
            .unvault_address(deriv_index)
            .to_string();

        if let Some(unvault_outpoint) = bitcoind.unvault_from_vault(&outpoint, unvault_addr)? {
            log::debug!(
                "The deposit utxo created via '{}' was unvaulted via '{}'",
                &outpoint,
                &unvault_outpoint
            );
            // Note that it *might* have actually been confirmed during the last 30s, but it's not
            // a big deal to have it marked as unconfirmed for the next 30s..
            db_unvault_deposit(
                &revaultd.read().unwrap().db_file(),
                outpoint.txid.to_vec(),
                outpoint.vout,
            )
            // TODO: something like From<DbError> for BitcoindError ?
            .map_err(|e| BitcoindError(format!("Database error: {}", e.to_string())))?;
        } else if false {
            // TODO: handle bypass
        } else {
            log::warn!(
                "The deposit utxo created via '{}' just vanished. Maybe a reorg is ongoing?",
                &outpoint
            );
        }
    }

    // TODO: keep track of unconfirmed unvaults and eventually mark them as confirmed

    Ok(())
}

/// The bitcoind event loop.
/// Poll bitcoind every 30 seconds, and update our state accordingly.
pub fn bitcoind_main_loop(
    _tx: Sender<ThreadMessage>,
    mut revaultd: Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
) -> Result<(), BitcoindError> {
    let mut last_poll = None;

    while !revaultd.read().unwrap().shutdown {
        let now = Instant::now();
        if let Some(last_poll) = last_poll {
            if now.duration_since(last_poll) < Duration::from_secs(30) {
                continue;
            }
        }

        last_poll = Some(now);
        poll_bitcoind(&mut revaultd, &bitcoind)?;
        thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}
