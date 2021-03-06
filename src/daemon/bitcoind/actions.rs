use crate::{
    bitcoind::{
        interface::{BitcoinD, DepositInfo, SyncInfo},
        BitcoindError, MIN_CONF,
    },
    database::{
        actions::{
            db_confirm_deposit, db_insert_new_unconfirmed_vault, db_unconfirm_deposit_dbtx,
            db_unvault_deposit, db_update_deposit_index, db_update_tip, db_update_tip_dbtx,
        },
        interface::{db_deposits, db_exec, db_tip, db_vaults_dbtx, db_wallet},
    },
    revaultd::{RevaultD, VaultStatus},
    threadmessages::{BitcoindMessageOut, WalletTransaction},
};
use common::{assume_ok, assume_some, config::BitcoindConfig};
use revault_tx::{
    bitcoin::{Amount, Network, OutPoint, TxOut, Txid},
    transactions::{
        transaction_chain, transaction_chain_manager, CancelTransaction, EmergencyTransaction,
        UnvaultEmergencyTransaction, UnvaultTransaction,
    },
    txins::DepositTxIn,
    txouts::DepositTxOut,
};

use std::{
    collections::HashMap,
    path::PathBuf,
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Receiver,
        Arc, RwLock,
    },
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
            BitcoindError::Custom("No valid 'chain' in getblockchaininfo response?".to_owned())
        })?;
    let bip70_net = match config_network {
        Network::Bitcoin => "main",
        Network::Testnet => "test",
        Network::Regtest => "regtest",
    };

    if !bip70_net.eq(chain) {
        return Err(BitcoindError::Custom(format!(
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

/// Bitcoind uses a guess for the value of verificationprogress. It will eventually get to
/// be 1, but can take some time; when it's > 0.99999 we are synced anyways so use that.
fn roundup_progress(progress: f64) -> f64 {
    let precision = 10u64.pow(5);
    ((progress * precision as f64 + 1.0) as u64 / precision) as f64
}

/// Polls bitcoind to check if we are synced yet.
/// Tries to be smart with getblockchaininfo calls by adjsuting the sleep duration
/// between calls.
/// If sync_progress == 1.0, we are done.
fn bitcoind_sync_status(
    bitcoind: &BitcoinD,
    bitcoind_config: &BitcoindConfig,
    sleep_duration: &mut Option<Duration>,
    sync_progress: &mut f64,
) -> Result<(), BitcoindError> {
    let first_poll = sleep_duration.is_none();

    let SyncInfo {
        headers,
        blocks,
        ibd,
        progress,
    } = bitcoind.synchronization_info()?;
    *sync_progress = roundup_progress(progress);

    if first_poll {
        if ibd {
            log::info!(
                "Bitcoind is currently performing IBD, this is going to \
                        take some time."
            );

            // If it may not have received all headers, be conservative and wait
            // for that first. Let's assume it won't take longer than 5min from now
            // for mainnet.
            if progress < 0.01 {
                log::info!("Waiting for bitcoind to gather enough headers..");

                *sleep_duration = if bitcoind_config.network.to_string().eq("regtest") {
                    Some(Duration::from_secs(3))
                } else {
                    Some(Duration::from_secs(5 * 60))
                };

                return Ok(());
            }
        }

        if progress < 0.7 {
            log::info!(
                "Bitcoind is far behind network tip, this is going to \
                        take some time."
            );
        }
    }

    // Sleeping a second per 20 blocks seems a good upper bound estimation
    // (~7h for 500_000 blocks), so we divide it by 2 here in order to be
    // conservative. Eg if 10_000 are left to be downloaded we'll check back
    // in ~4min.
    let delta = if headers > blocks {
        headers - blocks
    } else {
        0
    };
    *sleep_duration = Some(std::cmp::max(
        Duration::from_secs(delta / 20 / 2),
        Duration::from_secs(5),
    ));

    log::info!("We'll poll bitcoind again in {:?} seconds", sleep_duration);

    Ok(())
}

// This creates the actual wallet file, and imports the descriptors
fn maybe_create_wallet(revaultd: &mut RevaultD, bitcoind: &BitcoinD) -> Result<(), BitcoindError> {
    let wallet = db_wallet(&revaultd.db_file())?;
    let bitcoind_wallet_path = revaultd
        .watchonly_wallet_file()
        .expect("Wallet id is set at startup in setup_db()");
    // Did we just create the wallet ?
    let curr_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_secs())
        .map_err(|e| {
            BitcoindError::Custom(format!("Computing time since epoch: {}", e.to_string()))
        })?;
    let fresh_wallet = (curr_timestamp - wallet.timestamp as u64) < 30;

    if !PathBuf::from(bitcoind_wallet_path.clone()).exists() {
        bitcoind.createwallet_startup(bitcoind_wallet_path)?;
        log::info!("Importing descriptors to bitcoind watchonly wallet.");

        // Now, import descriptors.
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
        // FIXME: maybe we actually have, with the derivation_index_map ?
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
    let bitcoind_wallet_path = revaultd
        .watchonly_wallet_file()
        .expect("Wallet id is set at startup in setup_db()");

    if !bitcoind.listwallets()?.contains(&bitcoind_wallet_path) {
        log::info!("Loading our watchonly wallet '{}'.", bitcoind_wallet_path);
        bitcoind.loadwallet_startup(bitcoind_wallet_path)?;
    }

    Ok(())
}

/// Connects to and sanity checks bitcoind.
pub fn start_bitcoind(revaultd: &mut RevaultD) -> Result<BitcoinD, BitcoindError> {
    let bitcoind = BitcoinD::new(
        &revaultd.bitcoind_config,
        revaultd
            .watchonly_wallet_file()
            .expect("Wallet id is set at startup in setup_db()"),
    )
    .map_err(|e| {
        BitcoindError::Custom(format!("Could not connect to bitcoind: {}", e.to_string()))
    })?;

    while let Err(e) = bitcoind_sanity_checks(&bitcoind, &revaultd.bitcoind_config) {
        if e.is_warming_up() {
            log::info!("Bitcoind is warming up. Waiting for it to be back up.");
            thread::sleep(Duration::from_secs(3))
        } else {
            return Err(e);
        }
    }

    Ok(bitcoind)
}

// Get our state up to date with bitcoind.
// - Drop vaults which deposit is not confirmed anymore
// - Drop presigned transactions if the vault is downgraded to 'unconfirmed'
// - (TODO) Downgrade our state if necessary (if another transaction was reorg'ed out)
//
// Note that we want this operation to be atomic: we don't want to be midly updating to the new
// tip. Either we are updated to the new tip or we roll back to the previous one in case of error.
fn comprehensive_rescan(
    db_tx: &rusqlite::Transaction,
    bitcoind: &BitcoinD,
    deposits_cache: &mut HashMap<OutPoint, DepositInfo>,
) -> Result<(), BitcoindError> {
    log::info!("Starting rescan of all vaults in db..");
    let mut vaults = db_vaults_dbtx(&db_tx)?;
    let mut tip = bitcoind.get_tip()?;

    // Try to get the last tip
    loop {
        thread::sleep(Duration::from_secs(1));
        let maybe_new_tip = bitcoind.get_tip()?;
        if tip == maybe_new_tip {
            break;
        }
        tip = maybe_new_tip;
        continue;
    }

    while let Some(vault) = vaults.pop() {
        if matches!(vault.status, VaultStatus::Unconfirmed) {
            log::debug!(
                "Vault deposit '{}' is already unconfirmed",
                vault.deposit_outpoint
            );
            continue;
        }

        // bitcoind's wallet will always keep track of our transaction, even in case of reorg.
        let (_, blockheight, _) = bitcoind.get_wallet_transaction(&vault.deposit_outpoint.txid)?;
        if let Some(height) = blockheight {
            // Edge case: what if our tip is actually not up to date anymore
            if height > tip.height {
                return comprehensive_rescan(db_tx, bitcoind, deposits_cache);
            }

            let deposit_conf = tip.height.checked_sub(height).expect("Checked above") + 1;
            if deposit_conf < MIN_CONF as u32 {
                log::warn!(
                    "Vault deposit '{}' ended up with '{}' confirmations (<{}), \
                     marking as unconfirmed",
                    vault.deposit_outpoint,
                    deposit_conf,
                    MIN_CONF,
                );
                db_unconfirm_deposit_dbtx(db_tx, vault.id)?;
                assume_some!(
                    deposits_cache.get_mut(&vault.deposit_outpoint),
                    "Db vault not in cache?"
                )
                .status = VaultStatus::Unconfirmed;
                continue;
            }

            // TODO: if secured, active, unvaulted, spent, emergencied check each transaction.

            log::debug!(
                "Vault deposit '{}' still has '{}' confirmations (>={}), not doing anything",
                vault.deposit_outpoint,
                deposit_conf,
                MIN_CONF
            );
        } else {
            log::warn!(
                "Vault deposit '{}' ended up without confirmation, marking as \
                 unconfirmed",
                vault.deposit_outpoint
            );
            db_unconfirm_deposit_dbtx(db_tx, vault.id)?;
            assume_some!(
                deposits_cache.get_mut(&vault.deposit_outpoint),
                "Db vault not in cache?"
            )
            .status = VaultStatus::Unconfirmed;
        }
    }

    db_update_tip_dbtx(db_tx, &tip)?;
    log::info!(
        "\n\nCurrent vaults: {:?}\n Current cache: {:?}\n\n",
        db_vaults_dbtx(db_tx),
        &deposits_cache
    );

    Ok(())
}

// Check the latest tip, if it does not change or moves forward just do nothing or
// update in in the database. However if it goes backward or the tip block hash changes
// resynchronize ourself with the Bitcoin network.
// Returns the new deposit cache up-to-date with the database
fn update_tip(
    revaultd: &mut Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
    deposits_cache: &mut HashMap<OutPoint, DepositInfo>,
) -> Result<(), BitcoindError> {
    let current_tip = db_tip(&revaultd.read().unwrap().db_file())?;
    let tip = bitcoind.get_tip()?;

    // Nothing changed, shortcut.
    if tip == current_tip {
        return Ok(());
    }

    if tip.height > current_tip.height {
        // May just be a new (set of) block(s), make sure we are on the same chain
        let bit_curr_hash = bitcoind.getblockhash(current_tip.height)?;
        if bit_curr_hash == current_tip.hash || current_tip.height == 0 {
            // We moved forward, everything is fine.
            db_update_tip(&revaultd.read().unwrap().db_file(), &tip)?;
            return Ok(());
        }
    }

    log::warn!(
        "Detected reorg: our current stored tip is '{:?}' but bitcoind's is '{:?}'",
        &current_tip,
        &tip
    );
    db_exec(&revaultd.read().unwrap().db_file(), |db_tx| {
        comprehensive_rescan(db_tx, bitcoind, deposits_cache).unwrap_or_else(|e| {
            log::error!("Error while rescaning vaults: '{}'", e);
            std::process::exit(1);
        });
        Ok(())
    })?;
    log::info!("Rescan of all vaults in db done.");

    Ok(())
}

// Get fresh to-be-presigned transactions for this deposit utxo
fn presigned_transactions(
    revaultd: &RevaultD,
    outpoint: &OutPoint,
    utxo: &DepositInfo,
) -> Result<
    (
        UnvaultTransaction,
        CancelTransaction,
        Option<EmergencyTransaction>,
        Option<UnvaultEmergencyTransaction>,
    ),
    BitcoindError,
> {
    // We use the same derivation index for all descriptors.
    let derivation_index = *revaultd
        .derivation_index_map
        .get(&utxo.txo.script_pubkey)
        .ok_or_else(|| {
            BitcoindError::Custom(format!("Unknown derivation index for: {:#?}", &utxo))
        })?;
    let deposit_descriptor = revaultd.deposit_descriptor.derive(derivation_index);
    let unvault_descriptor = revaultd.unvault_descriptor.derive(derivation_index);
    let cpfp_descriptor = revaultd.cpfp_descriptor.derive(derivation_index);

    // Reconstruct the deposit UTXO and derive all pre-signed transactions out of it
    // if we are a stakeholder, and only the Unvault and the Cancel if we are a manager.
    let deposit_txin = DepositTxIn::new(
        *outpoint,
        DepositTxOut::new(utxo.txo.value, &deposit_descriptor, revaultd.xpub_ctx()),
    );
    if revaultd.is_stakeholder() {
        let emer_address = assume_some!(revaultd.emergency_address.clone(), "We are a stakeholder");
        let (unvault_tx, cancel_tx, emer_tx, unemer_tx) = transaction_chain(
            deposit_txin,
            &deposit_descriptor,
            &unvault_descriptor,
            &cpfp_descriptor,
            emer_address,
            revaultd.xpub_ctx(),
            revaultd.lock_time,
        )?;
        Ok((unvault_tx, cancel_tx, Some(emer_tx), Some(unemer_tx)))
    } else {
        let (unvault_tx, cancel_tx) = transaction_chain_manager(
            deposit_txin,
            &deposit_descriptor,
            &unvault_descriptor,
            &cpfp_descriptor,
            revaultd.xpub_ctx(),
            revaultd.lock_time,
        )?;
        Ok((unvault_tx, cancel_tx, None, None))
    }
}

// Fill up the deposit UTXOs cache from db vaults
fn populate_deposit_cache(
    revaultd: &RevaultD,
) -> Result<HashMap<OutPoint, DepositInfo>, BitcoindError> {
    let db_vaults = db_deposits(&revaultd.db_file())?;
    let mut cache = HashMap::with_capacity(db_vaults.len());

    for db_vault in db_vaults.into_iter() {
        let script_pubkey = revaultd
            .vault_address(db_vault.derivation_index)
            .script_pubkey();
        let txo = TxOut {
            script_pubkey,
            value: db_vault.amount.as_sat(),
        };
        cache.insert(
            db_vault.deposit_outpoint,
            DepositInfo {
                txo,
                status: db_vault.status,
            },
        );
        log::debug!("Loaded deposit '{}' from db", db_vault.deposit_outpoint);
    }

    Ok(cache)
}

// This syncs with bitcoind our incoming deposits, and those that were spent.
fn update_deposits(
    revaultd: &mut Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
    deposits_cache: &mut HashMap<OutPoint, DepositInfo>,
) -> Result<(), BitcoindError> {
    // Sync deposit of vaults we know have an unspent deposit.
    let (new_deposits, conf_deposits, spent_deposits) = bitcoind.sync_deposits(&deposits_cache)?;

    for (outpoint, utxo) in new_deposits.into_iter() {
        let derivation_index = *revaultd
            .read()
            .unwrap()
            .derivation_index_map
            .get(&utxo.txo.script_pubkey)
            .ok_or_else(|| {
                BitcoindError::Custom(format!("Unknown derivation index for: {:#?}", &utxo))
            })?;

        let received_at = bitcoind.get_wallet_transaction(&outpoint.txid)?.2;
        // Note that the deposit *might* have already MIN_CONF confirmations, that's fine. We'll
        // confim it during the next poll.
        let amount = Amount::from_sat(utxo.txo.value);
        db_insert_new_unconfirmed_vault(
            &revaultd.read().unwrap().db_file(),
            revaultd
                .read()
                .unwrap()
                .wallet_id
                .expect("Wallet id is set at startup in setup_db()"),
            &utxo.status,
            &outpoint,
            &amount,
            derivation_index,
            received_at,
        )?;
        log::debug!(
            "Got a new unconfirmed deposit at {} for {} ({})",
            &outpoint,
            &utxo.txo.script_pubkey,
            &amount
        );
        deposits_cache.insert(outpoint, utxo);

        // Mind the gap! https://www.youtube.com/watch?v=UOPyGKDQuRk
        // FIXME: of course, that's rudimentary
        let current_first_index = revaultd.read().unwrap().current_unused_index;
        if derivation_index >= current_first_index {
            let new_index = revaultd
                .read()
                .unwrap()
                .current_unused_index
                .increment()
                .map_err(|e| {
                    // FIXME: we should probably go back to 0 at this point.
                    BitcoindError::Custom(format!("Deriving next index: {}", e))
                })?;
            db_update_deposit_index(&revaultd.read().unwrap().db_file(), new_index)?;
            revaultd.write().unwrap().current_unused_index = new_index;
            let next_addr = bitcoind
                .addr_descriptor(&revaultd.read().unwrap().last_deposit_address().to_string())?;
            bitcoind.import_fresh_deposit_descriptor(next_addr)?;
            let next_addr = bitcoind
                .addr_descriptor(&revaultd.read().unwrap().last_unvault_address().to_string())?;
            bitcoind.import_fresh_unvault_descriptor(next_addr)?;

            log::debug!(
                "Incremented deposit derivation index from {}",
                current_first_index
            );
        }
    }

    for (outpoint, utxo) in conf_deposits.into_iter() {
        let blockheight = bitcoind
            .get_wallet_transaction(&outpoint.txid)?
            .1
            .ok_or_else(|| {
                BitcoindError::Custom("Deposit transaction isn't confirmed!".to_string())
            })?;
        // emer_tx and unemer_tx are None for managers
        let (unvault_tx, cancel_tx, emer_tx, unemer_tx) =
            presigned_transactions(&revaultd.read().unwrap(), &outpoint, &utxo)?;
        db_confirm_deposit(
            &revaultd.read().unwrap().db_file(),
            &outpoint,
            blockheight,
            &unvault_tx,
            &cancel_tx,
            emer_tx.as_ref(),
            unemer_tx.as_ref(),
        )?;
        deposits_cache
            .get_mut(&outpoint)
            .ok_or_else(|| BitcoindError::Custom("An unknown vault got confirmed?".to_string()))?
            .status = VaultStatus::Funded;

        log::debug!("Vault at {} is now confirmed", &outpoint);
    }

    for (outpoint, utxo) in spent_deposits.into_iter() {
        let deriv_index = *revaultd.read().unwrap()
            .derivation_index_map
            .get(&utxo.txo.script_pubkey)
            .ok_or_else(|| BitcoindError::Custom(
                    format!("A deposit was spent for which we don't know the corresponding xpub derivation. Outpoint: '{}'\nUtxo: '{:#?}'",
                        &outpoint,
                        &utxo)))?;
        let unvault_addr = revaultd
            .read()
            .unwrap()
            .unvault_address(deriv_index)
            .to_string();

        if let Some(unvault_outpoint) = bitcoind.unvault_from_vault(&outpoint, unvault_addr)? {
            // Note that it *might* have actually been confirmed during the last 30s, but it's not
            // a big deal to have it marked as unconfirmed for the next 30s..
            db_unvault_deposit(&revaultd.read().unwrap().db_file(), &outpoint)?;
            deposits_cache
                .get_mut(&outpoint)
                .expect("We just checked it")
                .status = VaultStatus::Unvaulting;
            log::debug!(
                "The deposit utxo created via '{}' was unvaulted via '{}'",
                &outpoint,
                &unvault_outpoint
            );
        } else if false {
            // TODO: handle bypass and emergency
        } else {
            match utxo.status {
                // Fine.
                VaultStatus::Unconfirmed => log::debug!(
                    "The unconfirmed deposit utxo created via '{}' just vanished",
                    &outpoint
                ),
                // Bad.
                VaultStatus::Funded | VaultStatus::Secured => log::warn!(
                    "The deposit utxo created via '{}' just vanished. Maybe a reorg is ongoing?",
                    &outpoint
                ),
                // Impossible.
                _ => unreachable!(),
            }
        }
    }

    // TODO: keep track of unconfirmed unvaults and eventually mark them as confirmed

    Ok(())
}

fn poller_main(
    mut revaultd: Arc<RwLock<RevaultD>>,
    bitcoind: Arc<RwLock<BitcoinD>>,
    sync_progress: Arc<RwLock<f64>>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), BitcoindError> {
    let mut last_poll = None;
    let mut sync_waittime = None;
    // We use a cache for maintaining our deposits' state up-to-date by polling `listunspent`
    let mut deposits_cache = populate_deposit_cache(&revaultd.read().unwrap())?;
    // When bitcoind is synced, we poll each 30s. On regtest we speed it up for testing.
    let poll_interval = revaultd.read().unwrap().bitcoind_config.poll_interval_secs;

    while !shutdown.load(Ordering::Relaxed) {
        let now = Instant::now();

        if (*sync_progress.read().unwrap() as u32) < 1 {
            // While waiting for bitcoind to be synced, guesstimate how much time of block
            // connection we have left to not harass it with `getblockchaininfo`.
            if let Some(last) = last_poll {
                if let Some(waittime) = sync_waittime {
                    if now.duration_since(last) < waittime {
                        continue;
                    }
                }
            }

            bitcoind_sync_status(
                &bitcoind.read().unwrap(),
                &revaultd.read().unwrap().bitcoind_config,
                &mut sync_waittime,
                &mut sync_progress.write().unwrap(),
            )?;

            // Ok. Sync, done. Now just be sure the watchonly wallet is properly loaded, and
            // to create it if it's first run.
            if *sync_progress.read().unwrap() as u32 >= 1 {
                let mut revaultd = revaultd.write().unwrap();
                let bitcoind = bitcoind.read().unwrap();
                maybe_create_wallet(&mut revaultd, &bitcoind).map_err(|e| {
                    BitcoindError::Custom(format!("Error while creating wallet: {}", e.to_string()))
                })?;
                maybe_load_wallet(&revaultd, &bitcoind).map_err(|e| {
                    BitcoindError::Custom(format!("Error while loading wallet: {}", e.to_string()))
                })?;

                log::info!("bitcoind now synced.");
            }

            last_poll = Some(now);
            continue;
        }

        if let Some(last_poll) = last_poll {
            if now.duration_since(last_poll) < poll_interval {
                thread::sleep(Duration::from_millis(500));
                continue;
            }
        }

        last_poll = Some(now);
        update_tip(
            &mut revaultd,
            &bitcoind.read().unwrap(),
            &mut deposits_cache,
        )?;
        update_deposits(
            &mut revaultd,
            &bitcoind.read().unwrap(),
            &mut deposits_cache,
        )?;
    }

    Ok(())
}

fn wallet_transaction(bitcoind: &BitcoinD, txid: Txid) -> Option<WalletTransaction> {
    let res = bitcoind.get_wallet_transaction(&txid);
    if let Ok((hex, blockheight, received_time)) = res {
        Some(WalletTransaction {
            hex,
            blockheight,
            received_time,
        })
    } else {
        log::trace!(
            "Got '{:?}' from bitcoind when requesting wallet transaction '{}'",
            res,
            txid
        );
        None
    }
}

/// The bitcoind event loop.
/// Listens for bitcoind requests (wallet / chain) and poll bitcoind every 30 seconds,
/// updating our state accordingly.
pub fn bitcoind_main_loop(
    rx: Receiver<BitcoindMessageOut>,
    revaultd: Arc<RwLock<RevaultD>>,
    bitcoind: Arc<RwLock<BitcoinD>>,
) -> Result<(), BitcoindError> {
    // The verification progress announced by bitcoind *at startup* thus won't be updated
    // after startup check. Should be *exactly* 1.0 when synced, but hey, floats so we are
    // careful.
    let sync_progress = Arc::new(RwLock::new(0.0f64));
    // Used to shutdown the poller thread
    let shutdown = Arc::new(AtomicBool::new(false));

    // We use a thread to 1) wait for bitcoind to be synced 2) poll listunspent
    let poller_thread = std::thread::spawn({
        let _revaultd = revaultd.clone();
        let _bitcoind = bitcoind.clone();
        let _sync_progress = sync_progress.clone();
        let _shutdown = shutdown.clone();
        move || poller_main(_revaultd, _bitcoind, _sync_progress, _shutdown)
    });

    for msg in rx {
        match msg {
            BitcoindMessageOut::Shutdown => {
                log::info!("Bitcoind received shutdown from main. Exiting.");
                shutdown.store(true, Ordering::Relaxed);
                assume_ok!(
                    assume_ok!(poller_thread.join(), "Joining bitcoind poller thread"),
                    "Error in bitcoind poller thread"
                );
                return Ok(());
            }
            BitcoindMessageOut::SyncProgress(resp_tx) => {
                resp_tx.send(*sync_progress.read().unwrap()).map_err(|e| {
                    BitcoindError::Custom(format!(
                        "Sending synchronization progress to main thread: {}",
                        e
                    ))
                })?;
            }
            BitcoindMessageOut::WalletTransaction(txid, resp_tx) => {
                log::trace!("Received 'wallettransaction' from main thread");
                resp_tx
                    .send(wallet_transaction(&bitcoind.read().unwrap(), txid))
                    .map_err(|e| {
                        BitcoindError::Custom(format!(
                            "Sending wallet transaction to main thread: {}",
                            e
                        ))
                    })?;
            }
        }
    }

    Ok(())
}
