use crate::{
    bitcoind::{
        interface::{BitcoinD, OnchainDescriptorState, SyncInfo, UtxoInfo},
        utils::{
            cancel_txid, emer_txid, populate_deposit_cache, populate_unvaults_cache,
            presigned_transactions, unemer_txid, unvault_txin_from_deposit,
        },
        BitcoindError,
    },
    database::{
        actions::{
            db_cancel_unvault, db_confirm_deposit, db_confirm_unvault, db_emer_unvault,
            db_insert_new_unconfirmed_vault, db_mark_broadcasted_spend, db_mark_canceled_unvault,
            db_mark_emergencied_unvault, db_mark_emergencied_vault, db_mark_emergencying_vault,
            db_mark_rebroadcastable_spend, db_mark_spent_unvault, db_spend_unvault,
            db_unconfirm_cancel_dbtx, db_unconfirm_deposit_dbtx, db_unconfirm_emer_dbtx,
            db_unconfirm_spend_dbtx, db_unconfirm_unemer_dbtx, db_unconfirm_unvault_dbtx,
            db_unvault_deposit, db_update_deposit_index, db_update_tip, db_update_tip_dbtx,
        },
        interface::{
            db_broadcastable_spend_transactions, db_cancel_dbtx, db_canceling_vaults,
            db_emering_vaults, db_exec, db_spending_vaults, db_tip, db_unemering_vaults,
            db_unvault_dbtx, db_unvault_transaction, db_vault_by_deposit, db_vault_by_unvault_txid,
            db_vaults_dbtx, db_wallet,
        },
        schema::DbVault,
    },
    revaultd::{BlockchainTip, RevaultD, VaultStatus},
};
use common::config::BitcoindConfig;
use revault_tx::{
    bitcoin::{Amount, OutPoint, Txid},
    transactions::{RevaultTransaction, UnvaultTransaction},
    txins::RevaultTxIn,
    txouts::RevaultTxOut,
};

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// Try to broadcast fully signed spend transactions, only mature ones will get through
fn maybe_broadcast_spend_transactions(
    revaultd: &Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
) -> Result<(), BitcoindError> {
    let db_path = revaultd.read().unwrap().db_file();

    for db_spendtx in db_broadcastable_spend_transactions(&db_path)? {
        let mut psbt = db_spendtx.psbt;
        let txid = psbt.txid();
        log::debug!("Trying to broadcast Spend tx '{}'", &txid);

        match psbt.finalize(&revaultd.read().unwrap().secp_ctx) {
            Ok(()) => {}
            Err(e) => {
                log::debug!("Error finalizing Spend '{}': '{}'", &txid, e);
                continue;
            }
        }

        let tx = psbt.into_psbt().extract_tx();
        match bitcoind.broadcast_transaction(&tx) {
            Ok(()) => {
                log::info!("Succesfully broadcasted Spend tx '{}'", txid);
                // FIXME: that's not so robust as we'll never try it again. Better tracking should
                // be part of the CPFP wallet work.
                db_mark_broadcasted_spend(&db_path, &txid)?;
            }
            Err(e) => {
                // This should not happen if it was succesfully finalized!
                log::error!("Error broadcasting Spend tx '{}': '{}'", txid, e);
            }
        }
    }

    Ok(())
}

fn maybe_confirm_spend(
    db_path: &Path,
    bitcoind: &BitcoinD,
    db_vault: &DbVault,
    spend_txid: &Txid,
) -> Result<bool, BitcoindError> {
    if let (_, Some(height), _) = bitcoind.get_wallet_transaction(spend_txid)? {
        db_mark_spent_unvault(&db_path, db_vault.id)?;
        log::debug!(
            "Spend tx '{}', spending vault {:x?} was confirmed at height '{}'",
            &spend_txid,
            db_vault,
            height
        );

        return Ok(true);
    }

    Ok(false)
}

// Check if some Spend transaction that were marked as broadcasted were confirmed, if so upgrade
// the vault state to 'spent'.
fn mark_confirmed_spends(
    revaultd: &Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
) -> Result<(), BitcoindError> {
    let db_path = revaultd.read().unwrap().db_file();

    for (db_vault, unvault_tx) in db_spending_vaults(&db_path)? {
        let der_unvault_descriptor = revaultd
            .read()
            .unwrap()
            .derived_unvault_descriptor(db_vault.derivation_index);
        let unvault_txin = unvault_tx.revault_unvault_txin(&der_unvault_descriptor);
        let unvault_outpoint = unvault_txin.outpoint();
        let spend_txid = &db_vault.spend_txid.expect("Must be set for 'spending'");

        match maybe_confirm_spend(&db_path, bitcoind, &db_vault, &spend_txid) {
            Ok(false) => {}
            Ok(true) => continue,
            Err(e) => {
                log::error!(
                    "Error checking if Spend '{}' is confirmed: '{}'",
                    &spend_txid,
                    e
                );
                continue;
            }
        };

        if !bitcoind.is_in_mempool(spend_txid)? {
            // At least, is this transaction still in mempool?
            // If it was evicted, downgrade it to `unvaulted`, the listunspent polling loop will
            // take care of checking its new state immediately.
            db_confirm_unvault(&db_path, &unvault_tx.txid())?;

            let txo = unvault_txin.into_txout().into_txout();
            unvaults_cache.insert(
                unvault_outpoint,
                UtxoInfo {
                    txo,
                    is_confirmed: true,
                },
            );

            log::debug!(
                "Spend tx '{}', spending Unvault '{}' was evicted from mempool.",
                spend_txid,
                unvault_outpoint
            );
        } else {
            log::trace!(
                "Spend tx '{}', spending Unvault '{}' is still unconfirmed",
                spend_txid,
                unvault_outpoint
            );
        }
    }

    Ok(())
}

// The below procedures may set a vault as Unvaulted if the unconfirmed transaction spending the
// Unvault is dropped from the mempool. This groups the code for doing so.
fn mark_unvaulted(
    revaultd: &Arc<RwLock<RevaultD>>,
    db_path: &Path,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
    db_vault: &DbVault,
) -> Result<(), BitcoindError> {
    let (_, unvault_tx) = db_unvault_transaction(&db_path, db_vault.id)?;
    let unvault_descriptor = revaultd.read().unwrap().unvault_descriptor.derive(
        db_vault.derivation_index,
        &revaultd.read().unwrap().secp_ctx,
    );
    let unvault_txin = unvault_tx.revault_unvault_txin(&unvault_descriptor);
    let unvault_outpoint = unvault_txin.outpoint();

    db_confirm_unvault(&db_path, &unvault_tx.tx().txid())?;

    let txo = unvault_txin.into_txout().into_txout();
    unvaults_cache.insert(
        unvault_outpoint,
        UtxoInfo {
            txo,
            is_confirmed: true,
        },
    );
    log::debug!(
        "Transaction spending Unvault '{}' was evicted from mempool. Downgrading vault at \
         '{}' from '{}' to 'Unvaulted'",
        unvault_outpoint,
        &db_vault.deposit_outpoint,
        db_vault.status,
    );

    Ok(())
}

fn maybe_confirm_cancel(
    db_path: &Path,
    bitcoind: &BitcoinD,
    db_vault: &DbVault,
    cancel_txid: &Txid,
) -> Result<bool, BitcoindError> {
    if let (_, Some(height), _) = bitcoind.get_wallet_transaction(cancel_txid)? {
        db_mark_canceled_unvault(&db_path, db_vault.id)?;
        log::debug!(
            "Cancel tx '{}', spending vault {:x?} was confirmed at height '{}'",
            &cancel_txid,
            db_vault,
            height
        );

        return Ok(true);
    }

    Ok(false)
}

fn mark_confirmed_cancels(
    revaultd: &Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
) -> Result<(), BitcoindError> {
    let db_path = revaultd.read().unwrap().db_file();

    for (db_vault, cancel_tx) in db_canceling_vaults(&db_path)? {
        let cancel_txid = cancel_tx.txid();
        match maybe_confirm_cancel(&db_path, bitcoind, &db_vault, &cancel_txid) {
            Ok(false) => {}
            Ok(true) => continue,
            Err(e) => {
                log::error!(
                    "Error checking if Cancel '{}' is confirmed: '{}'",
                    &cancel_txid,
                    e
                );
                continue;
            }
        };

        if !bitcoind.is_in_mempool(&cancel_tx.txid())? {
            // At least, is this transaction still in mempool?
            // If it was evicted, downgrade it to `unvaulted`, the listunspent polling loop will
            // take care of checking its new state immediately.
            mark_unvaulted(revaultd, &db_path, unvaults_cache, &db_vault)?;
        } else {
            log::trace!("Cancel tx '{}' is still unconfirmed", cancel_txid);
        }
    }

    Ok(())
}

fn maybe_confirm_unemer(
    db_path: &Path,
    bitcoind: &BitcoinD,
    db_vault: &DbVault,
    unemer_txid: &Txid,
) -> Result<bool, BitcoindError> {
    if let (_, Some(height), _) = bitcoind.get_wallet_transaction(unemer_txid)? {
        db_mark_emergencied_unvault(&db_path, db_vault.id)?;
        log::warn!(
            "UnvaultEmergency tx '{}', spending vault {:x?} was confirmed at height '{}'",
            &unemer_txid,
            db_vault,
            height
        );

        return Ok(true);
    }

    Ok(false)
}

fn mark_confirmed_unemers(
    revaultd: &Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
) -> Result<(), BitcoindError> {
    let db_path = revaultd.read().unwrap().db_file();

    for (db_vault, unemer_tx) in db_unemering_vaults(&db_path)? {
        let unemer_txid = unemer_tx.txid();
        match maybe_confirm_unemer(&db_path, bitcoind, &db_vault, &unemer_txid) {
            Ok(false) => {}
            Ok(true) => continue,
            Err(e) => {
                log::error!(
                    "Error checking if UnvaultEmergency '{}' is confirmed: '{}'",
                    &unemer_txid,
                    e
                );
                continue;
            }
        };

        if !bitcoind.is_in_mempool(&unemer_txid)? {
            // At least, is this transaction still in mempool?
            // If it was evicted, downgrade it to `unvaulted`, the listunspent polling loop will
            // take care of checking its new state immediately.
            mark_unvaulted(revaultd, &db_path, unvaults_cache, &db_vault)?;
            log::warn!(
                "UnvaultEmergency tx '{}' was evicted from mempool.",
                &unemer_txid,
            );

            // TODO: broadcast it again, as well as the other Emergency txs in this case!!
        } else {
            log::trace!("UnvaultEmergency tx '{}' is still unconfirmed", unemer_txid);
        }
    }

    Ok(())
}

fn maybe_confirm_emer(
    db_path: &Path,
    bitcoind: &BitcoinD,
    db_vault: &DbVault,
    emer_txid: &Txid,
) -> Result<bool, BitcoindError> {
    if let (_, Some(height), _) = bitcoind.get_wallet_transaction(emer_txid)? {
        db_mark_emergencied_vault(&db_path, db_vault.id)?;
        log::warn!(
            "Emergency tx '{}', spending vault {:x?} was confirmed at height '{}'",
            &emer_txid,
            db_vault,
            height
        );

        return Ok(true);
    }

    Ok(false)
}

fn mark_confirmed_emers(
    revaultd: &Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
) -> Result<(), BitcoindError> {
    let db_path = revaultd.read().unwrap().db_file();

    for (db_vault, emer_tx) in db_emering_vaults(&db_path)? {
        let emer_txid = emer_tx.txid();
        match maybe_confirm_emer(&db_path, bitcoind, &db_vault, &emer_txid) {
            Ok(false) => {}
            Ok(true) => continue,
            Err(e) => {
                log::error!(
                    "Error checking if UnvaultEmergency '{}' is confirmed: '{}'",
                    &emer_txid,
                    e
                );
                continue;
            }
        };

        if !bitcoind.is_in_mempool(&emer_txid)? {
            // At least, is this transaction still in mempool?
            // If it was evicted, downgrade it to `unvaulted`, the listunspent polling loop will
            // take care of checking its new state immediately.
            mark_unvaulted(revaultd, &db_path, unvaults_cache, &db_vault)?;
            log::warn!("Emergency tx '{}' was evicted from mempool.", &emer_txid,);

            // TODO: broadcast it again, as well as the other Emergency txs in this case!!
        } else {
            log::trace!("Emergency tx '{}' is still unconfirmed", emer_txid);
        }
    }

    Ok(())
}

// Everything we do when the chain moves forward
fn new_tip_event(
    revaultd: &Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
    new_tip: &BlockchainTip,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
) -> Result<(), BitcoindError> {
    let db_path = revaultd.read().unwrap().db_file();

    // First we update it in DB
    db_update_tip(&db_path, new_tip)?;

    // Then we check if any Spend became mature yet
    maybe_broadcast_spend_transactions(revaultd, bitcoind)?;

    // Did some Spend transaction confirmed?
    mark_confirmed_spends(revaultd, bitcoind, unvaults_cache)?;

    // Did some Cancel transaction get confirmed?
    mark_confirmed_cancels(revaultd, bitcoind, unvaults_cache)?;

    // Did some Emergency got confirmed?
    mark_confirmed_emers(revaultd, bitcoind, unvaults_cache)?;
    mark_confirmed_unemers(revaultd, bitcoind, unvaults_cache)?;

    Ok(())
}

// Rewind the state of a vault for which the Unvault transaction was already broadcast
fn unconfirm_unvault(
    revaultd: &Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
    db_tx: &rusqlite::Transaction,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
    vault: &DbVault,
    unvault_tx: &UnvaultTransaction,
) -> Result<(), BitcoindError> {
    let unvault_txid = unvault_tx.txid();

    // Mark it as 'unvaulting', note however that if it was Spent or Canceled it will be marked as
    // 'spending' or 'canceling' right away by the bitcoind polling loop as `listunspent` will
    // consider the Unvault transaction as spent if a wallet transaction was recorded spending it
    // **even if it becomes invalid**.
    db_unconfirm_unvault_dbtx(db_tx, vault.id)?;

    // bitcoind's wallet may need a small kick-in for large reorgs (which won't happen on mainnet
    // but hey).
    match bitcoind.rebroadcast_wallet_tx(&unvault_txid) {
        Ok(()) => {}
        Err(e) => log::debug!(
            "Error re-broadcasting Unvault tx '{}': '{}'",
            unvault_txid,
            e
        ),
    }

    // Then either repopulate the cache (we remove the entry on spend) or update the
    // cache accordingly.
    let der_unvault_descriptor = revaultd
        .read()
        .unwrap()
        .unvault_descriptor
        .derive(vault.derivation_index, &revaultd.read().unwrap().secp_ctx);
    let unvault_txin = unvault_tx.revault_unvault_txin(&der_unvault_descriptor);
    let unvault_outpoint = unvault_txin.outpoint();
    let txo = unvault_txin.into_txout().into_txout();
    if matches!(vault.status, VaultStatus::Spent | VaultStatus::Spending) {
        // Don't forget rebroadcast the Spend transaction at the next tip update!
        // NOTE: it won't do anything if there is no spend_transaction awaiting (eg for a
        // stakeholder).
        db_mark_rebroadcastable_spend(db_tx, &unvault_txid)?;

        // Still re-insert it, even if it'll be removed at the next `listunspent` poll
        unvaults_cache.insert(
            unvault_outpoint,
            UtxoInfo {
                txo,
                is_confirmed: false,
            },
        );
    } else if matches!(vault.status, VaultStatus::Unvaulted) {
        // If it was only 'unvaulted', we still have it in the cache. (as conf'ed, so mark it as
        // unconf'ed now)
        unvaults_cache
            .get_mut(&unvault_outpoint)
            .expect("Db unvault not in cache for 'unvaulted'?")
            .is_confirmed = false;
    } else if matches!(vault.status, VaultStatus::Canceled | VaultStatus::Canceling) {
        // Just in case, rebroadcast it.
        let cancel_tx = match db_cancel_dbtx(&db_tx, vault.id)? {
            Some(tx) => tx,
            None => {
                log::error!(
                    "Vault '{}' has status '{}' but no Cancel in database!",
                    vault.deposit_outpoint,
                    vault.status
                );
                return Ok(());
            }
        };
        let cancel_txid = cancel_tx.txid();
        match bitcoind.rebroadcast_wallet_tx(&cancel_txid) {
            Ok(()) => {}
            Err(e) => log::debug!("Error re-broadcasting Cancel tx '{}': '{}'", cancel_txid, e),
        }

        // Still re-insert it, even if it'll be removed at the next `listunspent` poll
        unvaults_cache.insert(
            unvault_outpoint,
            UtxoInfo {
                txo,
                is_confirmed: false,
            },
        );
    }

    Ok(())
}

// Rewind the state of a vault for which the Unvault transaction was never broadcast.
// Will panic if called for an unconfirmed vault.
fn unconfirm_vault(
    revaultd: &Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
    db_tx: &rusqlite::Transaction,
    deposits_cache: &mut HashMap<OutPoint, UtxoInfo>,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
    vault: &DbVault,
) -> Result<(), BitcoindError> {
    // Just in case, rebroadcast the deposit transaction anyways
    let deposit_txid = vault.deposit_outpoint.txid;
    match bitcoind.rebroadcast_wallet_tx(&deposit_txid) {
        Ok(()) => {}
        Err(e) => log::debug!(
            "Error re-broadcasting Deposit tx '{}': '{}'",
            deposit_txid,
            e
        ),
    }

    match vault.status {
        VaultStatus::Unconfirmed => unreachable!("Unconfirming a confirmed vault"),
        VaultStatus::Unvaulting
        | VaultStatus::Unvaulted
        | VaultStatus::Spending
        | VaultStatus::Spent
        | VaultStatus::Canceling
        | VaultStatus::Canceled
        | VaultStatus::UnvaultEmergencyVaulting
        | VaultStatus::UnvaultEmergencyVaulted => {
            // If it was already at the 'second layer' (in the transaction chain, post Unvault
            // broadcast), just rewind the state to this point. This is tremendously unlikely in
            // real conditions (min conf for the deposits + say, X blocks of CSV if Spent already
            // so that'd be a reorg of several dozens of blocks).
            let unvault_tx = db_unvault_dbtx(db_tx, vault.id)?.ok_or_else(|| {
                BitcoindError::Custom(format!(
                    "Vault '{}' has status '{}' but no Unvault in database!",
                    vault.deposit_outpoint, vault.status
                ))
            })?;
            unconfirm_unvault(
                revaultd,
                bitcoind,
                db_tx,
                unvaults_cache,
                vault,
                &unvault_tx,
            )?;

            // TODO: if it was in UnvaultEmergency, re-broadcast all the Emergency transactions

            Ok(())
        }
        VaultStatus::Funded
        | VaultStatus::Securing
        | VaultStatus::Secured
        | VaultStatus::Activating
        | VaultStatus::Active
        | VaultStatus::EmergencyVaulting
        | VaultStatus::EmergencyVaulted => {
            // If it was still at the 'first layer', just mark it as unconfirmed.
            db_unconfirm_deposit_dbtx(db_tx, vault.id)?;
            deposits_cache
                .get_mut(&vault.deposit_outpoint)
                .expect("Not unvaulted yet")
                .is_confirmed = false;

            // TODO: If it was in Emergency, re-broadcast all the Emergency transactions

            Ok(())
        }
    }
}

// Get our state up to date with bitcoind.
// - Drop vaults which deposit is not confirmed anymore
// - Drop presigned transactions if the vault is downgraded to 'unconfirmed'
// - Downgrade our state if necessary (if a transaction of the chain was reorg'ed out)
//
// Note that we want this operation to be atomic: we don't want to be midly updating to the new
// tip. Either we are updated to the new tip or we roll back to the previous one in case of error.
fn comprehensive_rescan(
    revaultd: &Arc<RwLock<RevaultD>>,
    db_tx: &rusqlite::Transaction,
    bitcoind: &BitcoinD,
    deposits_cache: &mut HashMap<OutPoint, UtxoInfo>,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
) -> Result<(), BitcoindError> {
    log::info!("Starting rescan of all vaults in db..");
    let mut vaults = db_vaults_dbtx(&db_tx)?;
    let mut tip = bitcoind.get_tip()?;

    // Try to get the last tip
    loop {
        thread::sleep(Duration::from_secs(5));
        let maybe_new_tip = bitcoind.get_tip()?;
        if tip == maybe_new_tip {
            break;
        }
        tip = maybe_new_tip;
    }

    while let Some(vault) = vaults.pop() {
        if matches!(vault.status, VaultStatus::Unconfirmed) {
            log::debug!(
                "Vault deposit '{}' is already unconfirmed",
                vault.deposit_outpoint
            );
            continue;
        }

        if bitcoind.get_tip()? != tip {
            return comprehensive_rescan(revaultd, db_tx, bitcoind, deposits_cache, unvaults_cache);
        }

        // bitcoind's wallet will always keep track of our transaction, even in case of reorg.
        let (_, blockheight, _) = bitcoind.get_wallet_transaction(&vault.deposit_outpoint.txid)?;
        let dep_height = if let Some(height) = blockheight {
            height
        } else {
            unconfirm_vault(
                revaultd,
                bitcoind,
                db_tx,
                deposits_cache,
                unvaults_cache,
                &vault,
            )?;
            log::warn!(
                "Vault deposit '{}' ended up without confirmation",
                vault.deposit_outpoint
            );
            continue;
        };

        if bitcoind.get_tip()? != tip {
            return comprehensive_rescan(revaultd, db_tx, bitcoind, deposits_cache, unvaults_cache);
        }

        // First layer: if the deposit itself becomes unconfirmed, no need to go further: mark the
        // vault as unconfirmed and be done.
        let deposit_conf = tip.height.checked_sub(dep_height).expect("Checked above") + 1;
        let min_conf = revaultd.read().unwrap().min_conf;
        if deposit_conf < min_conf as u32 {
            unconfirm_vault(
                revaultd,
                bitcoind,
                db_tx,
                deposits_cache,
                unvaults_cache,
                &vault,
            )?;
            log::warn!(
                "Vault deposit '{}' ended up with '{}' confirmations (<{})",
                vault.deposit_outpoint,
                deposit_conf,
                min_conf,
            );
            continue;
        }

        log::debug!(
            "Vault deposit '{}' still has '{}' confirmations (>={}), not doing anything",
            vault.deposit_outpoint,
            deposit_conf,
            min_conf
        );

        // Now, if the Emergency transaction got unconfirmed mark the vault as such.
        if matches!(vault.status, VaultStatus::EmergencyVaulted) {
            let emer_txid = match emer_txid(revaultd, &vault)? {
                Some(txid) => txid,
                None => {
                    log::error!(
                        "Vault was marked as EmergencyVaulted but we are \
                         not a stakeholder"
                    );
                    continue;
                }
            };

            if bitcoind.get_tip()? != tip {
                return comprehensive_rescan(
                    revaultd,
                    db_tx,
                    bitcoind,
                    deposits_cache,
                    unvaults_cache,
                );
            }
            let (_, blockheight, _) = bitcoind.get_wallet_transaction(&emer_txid)?;
            if let Some(height) = blockheight {
                log::debug!(
                    "Vault {}'s Emeregency transaction is still confirmed (height '{}')",
                    vault.deposit_outpoint,
                    height
                );
            } else {
                db_unconfirm_emer_dbtx(db_tx, vault.id)?;
                log::debug!(
                    "Vault {}'s Emergency transaction {} got unconfirmed.",
                    vault.deposit_outpoint,
                    emer_txid
                );
                continue;
            }
        }

        // Second layer: if the Unvault was confirmed and becomes unconfirmed, we mark it as such
        // and make sure to rebroadcast the transaction that were depending on it.
        if matches!(
            vault.status,
            VaultStatus::Unvaulted
                | VaultStatus::Spending
                | VaultStatus::Spent
                | VaultStatus::Canceling
                | VaultStatus::Canceled
                | VaultStatus::UnvaultEmergencyVaulting
                | VaultStatus::UnvaultEmergencyVaulted
        ) {
            let unvault_tx = match db_unvault_dbtx(db_tx, vault.id)? {
                Some(tx) => tx,
                None => {
                    log::error!(
                        "Vault '{}' has status '{}' but no Unvault in database!",
                        vault.deposit_outpoint,
                        vault.status
                    );
                    continue;
                }
            };
            let unvault_txid = unvault_tx.txid();

            if bitcoind.get_tip()? != tip {
                return comprehensive_rescan(
                    revaultd,
                    db_tx,
                    bitcoind,
                    deposits_cache,
                    unvaults_cache,
                );
            }
            let (_, blockheight, _) = bitcoind.get_wallet_transaction(&unvault_txid)?;

            let unv_height = if let Some(height) = blockheight {
                height
            } else {
                unconfirm_unvault(
                    revaultd,
                    bitcoind,
                    db_tx,
                    unvaults_cache,
                    &vault,
                    &unvault_tx,
                )?;

                // And finally hook the tests (and the eyeballs)
                log::debug!(
                    "Vault {}'s Unvault transaction {} got unconfirmed.",
                    vault.deposit_outpoint,
                    unvault_txid
                );
                continue;
            };

            log::debug!(
                "Vault {}'s Unvault transaction is still confirmed (height '{}')",
                vault.deposit_outpoint,
                unv_height
            );

            // Third layer: if the Spend transaction *only* was confirmed and becomes unconfirmed,
            // we just mark it as such. The bitcoind wallet will take care of the rebroadcast.
            if matches!(vault.status, VaultStatus::Spent) {
                let spend_txid = &vault.spend_txid.expect("Must be Some in 'spent'");

                if bitcoind.get_tip()? != tip {
                    return comprehensive_rescan(
                        revaultd,
                        db_tx,
                        bitcoind,
                        deposits_cache,
                        unvaults_cache,
                    );
                }
                let (_, blockheight, _) = bitcoind.get_wallet_transaction(spend_txid)?;
                if let Some(height) = blockheight {
                    log::debug!(
                        "Vault {}'s Spend transaction is still confirmed (height '{}')",
                        vault.deposit_outpoint,
                        height
                    );
                } else {
                    db_unconfirm_spend_dbtx(db_tx, vault.id)?;
                    log::debug!(
                        "Vault {}'s Spend transaction {} got unconfirmed.",
                        vault.deposit_outpoint,
                        spend_txid
                    );
                    continue;
                }
            }

            // Same for the Cancel transaction
            if matches!(vault.status, VaultStatus::Canceled) {
                let cancel_txid = cancel_txid(revaultd, &vault)?;

                if bitcoind.get_tip()? != tip {
                    return comprehensive_rescan(
                        revaultd,
                        db_tx,
                        bitcoind,
                        deposits_cache,
                        unvaults_cache,
                    );
                }
                let (_, blockheight, _) = bitcoind.get_wallet_transaction(&cancel_txid)?;
                if let Some(height) = blockheight {
                    log::debug!(
                        "Vault {}'s Cancel transaction is still confirmed (height '{}')",
                        vault.deposit_outpoint,
                        height
                    );
                } else {
                    db_unconfirm_cancel_dbtx(db_tx, vault.id)?;
                    log::debug!(
                        "Vault {}'s Cancel transaction {} got unconfirmed.",
                        vault.deposit_outpoint,
                        cancel_txid
                    );
                    continue;
                }
            }

            // Same for the UnvaultEmergency
            if matches!(vault.status, VaultStatus::UnvaultEmergencyVaulted) {
                let unemer_txid = match unemer_txid(revaultd, &vault)? {
                    Some(txid) => txid,
                    None => {
                        log::error!(
                            "Vault was marked as UnvaultEmergencyVaulted but we are \
                                     not a stakeholder"
                        );
                        continue;
                    }
                };

                if bitcoind.get_tip()? != tip {
                    return comprehensive_rescan(
                        revaultd,
                        db_tx,
                        bitcoind,
                        deposits_cache,
                        unvaults_cache,
                    );
                }
                let (_, blockheight, _) = bitcoind.get_wallet_transaction(&unemer_txid)?;
                if let Some(height) = blockheight {
                    log::debug!(
                        "Vault {}'s UnvaultEmeregency transaction is still confirmed (height '{}')",
                        vault.deposit_outpoint,
                        height
                    );
                } else {
                    db_unconfirm_unemer_dbtx(db_tx, vault.id)?;
                    log::debug!(
                        "Vault {}'s UnvaultEmergency transaction {} got unconfirmed.",
                        vault.deposit_outpoint,
                        unemer_txid
                    );
                    continue;
                }
            }
        }
    }

    db_update_tip_dbtx(db_tx, &tip)?;

    Ok(())
}

// Check the latest tip, if it does not change or moves forward just do nothing or
// update in in the database. However if it goes backward or the tip block hash changes
// resynchronize ourself with the Bitcoin network.
// Returns the previous tip.
fn update_tip(
    revaultd: &mut Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
    deposits_cache: &mut HashMap<OutPoint, UtxoInfo>,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
) -> Result<BlockchainTip, BitcoindError> {
    let current_tip = db_tip(&revaultd.read().unwrap().db_file())?;
    let tip = bitcoind.get_tip()?;

    // Nothing changed, shortcut.
    if tip == current_tip {
        return Ok(tip);
    }

    if tip.height > current_tip.height {
        // May just be a new (set of) block(s), make sure we are on the same chain
        let bit_curr_hash = bitcoind.getblockhash(current_tip.height)?;
        if bit_curr_hash == current_tip.hash || current_tip.height == 0 {
            // We moved forward, everything is fine.
            new_tip_event(&revaultd, bitcoind, &tip, unvaults_cache)?;
            return Ok(current_tip);
        }
    }

    log::warn!(
        "Detected reorg: our current stored tip is '{:?}' but bitcoind's is '{:?}'",
        &current_tip,
        &tip
    );
    db_exec(&revaultd.read().unwrap().db_file(), |db_tx| {
        comprehensive_rescan(revaultd, db_tx, bitcoind, deposits_cache, unvaults_cache)
            .unwrap_or_else(|e| {
                log::error!("Error while rescaning vaults: '{}'", e);
                std::process::exit(1);
            });
        Ok(())
    })?;
    log::info!("Rescan of all vaults in db done.");

    Ok(current_tip)
}

// Which kind of transaction may spend the Unvault transaction.
#[derive(Debug)]
enum UnvaultSpender {
    // The Cancel, spending via the stakeholders path to a new deposit
    Cancel(Txid),
    // The Spend, any transaction spending via the managers path
    Spend(Txid),
    // The Emergency, spending via the stakeholders path to the EDV
    Emergency(Txid),
}

// Retrieve the transaction kind (and its txid) that spent an Unvault
fn unvault_spender(
    revaultd: &mut Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
    previous_tip: &BlockchainTip,
    unvault_outpoint: &OutPoint,
) -> Result<Option<UnvaultSpender>, BitcoindError> {
    let db_path = revaultd.read().unwrap().db_file();

    let (vault, _) =
        db_vault_by_unvault_txid(&db_path, &unvault_outpoint.txid)?.ok_or_else(|| {
            BitcoindError::Custom(format!(
                "No vault for {}, but it *is* being spent",
                unvault_outpoint
            ))
        })?;

    // First, check if it was spent by a Cancel, it's cheaper.
    let cancel_txid = cancel_txid(revaultd, &vault)?;
    if bitcoind.is_current(&cancel_txid)? {
        return Ok(Some(UnvaultSpender::Cancel(cancel_txid)));
    }

    // Second, check if it was spent by an UnvaultEmergency if we are able to, it's as cheap.
    let unemer_txid = unemer_txid(revaultd, &vault)?;
    if let Some(unemer_txid) = unemer_txid {
        if bitcoind.is_current(&unemer_txid)? {
            return Ok(Some(UnvaultSpender::Emergency(unemer_txid)));
        }
    }

    // Finally, fetch the spending transaction
    if let Some(spender_txid) = bitcoind.get_spender_txid(&unvault_outpoint, &previous_tip.hash)? {
        // FIXME: be smarter, all the information are in the previous call, no need for a
        // second one.

        // Let's double-check that we didn't fetch the cancel, nor the unemer
        // In theory (read edge cases), the Cancel and UnEmer could have not been
        // current at the last bitcoind poll but could be now.
        // Be sure to not wrongly mark a Cancel or UnEmer as a Spend!
        if spender_txid == cancel_txid || Some(spender_txid) == unemer_txid {
            // Alright, the spender is the cancel or the unemer,
            // but we just checked and they weren't current. We'll return None
            // so the checker will call this function again.
            return Ok(None);
        }

        if bitcoind.is_current(&spender_txid)? {
            return Ok(Some(UnvaultSpender::Spend(spender_txid)));
        }
    }

    Ok(None)
}

// Update the state of a vault whose Unvault txo was spent.
fn handle_spent_unvault(
    revaultd: &mut Arc<RwLock<RevaultD>>,
    db_path: &Path,
    bitcoind: &BitcoinD,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
    previous_tip: &BlockchainTip,
    unvault_outpoint: &OutPoint,
) -> Result<(), BitcoindError> {
    match unvault_spender(revaultd, bitcoind, previous_tip, &unvault_outpoint)? {
        Some(UnvaultSpender::Cancel(txid)) => {
            db_cancel_unvault(&db_path, &unvault_outpoint.txid)?;
            unvaults_cache
                .remove(&unvault_outpoint)
                .expect("An unknown unvault got spent?");
            log::debug!(
                "Unvault transaction at {} is now being canceled",
                &unvault_outpoint
            );

            // Immediately check if it was confirmed, just in case
            let (db_vault, _) = db_vault_by_unvault_txid(&db_path, &unvault_outpoint.txid)?
                .ok_or_else(|| {
                    BitcoindError::Custom(format!(
                        "No vault for Unvault '{}'",
                        &unvault_outpoint.txid
                    ))
                })?;
            match maybe_confirm_cancel(&db_path, bitcoind, &db_vault, &txid) {
                Ok(_) => {}
                Err(e) => {
                    log::error!("Error checking if Cancel '{}' is confirmed: '{}'", &txid, e);
                }
            }
        }
        Some(UnvaultSpender::Spend(txid)) => {
            db_spend_unvault(&db_path, &unvault_outpoint.txid, &txid)?;
            unvaults_cache.remove(&unvault_outpoint).ok_or_else(|| {
                BitcoindError::Custom("An unknown unvault got spent?".to_string())
            })?;
            log::debug!(
                "Unvault transaction at {} is now being spent",
                &unvault_outpoint
            );

            // Immediately check if it was confirmed, just in case
            let (db_vault, _) = db_vault_by_unvault_txid(&db_path, &unvault_outpoint.txid)?
                .ok_or_else(|| {
                    BitcoindError::Custom(format!(
                        "No vault for Unvault '{}'",
                        &unvault_outpoint.txid
                    ))
                })?;
            match maybe_confirm_spend(&db_path, bitcoind, &db_vault, &txid) {
                Ok(_) => {}
                Err(e) => {
                    log::error!("Error checking if Spend '{}' is confirmed: '{}'", &txid, e);
                }
            }
        }
        Some(UnvaultSpender::Emergency(txid)) => {
            db_emer_unvault(&db_path, &unvault_outpoint.txid)?;
            unvaults_cache.remove(&unvault_outpoint).ok_or_else(|| {
                BitcoindError::Custom("An unknown unvault got spent?".to_string())
            })?;
            log::warn!(
                "Unvault transaction at {} is now being emergencied",
                &unvault_outpoint
            );

            // Immediately check if it was confirmed, just in case
            let (db_vault, _) = db_vault_by_unvault_txid(&db_path, &unvault_outpoint.txid)?
                .ok_or_else(|| {
                    BitcoindError::Custom(format!(
                        "No vault for Unvault '{}'",
                        &unvault_outpoint.txid
                    ))
                })?;
            match maybe_confirm_unemer(&db_path, bitcoind, &db_vault, &txid) {
                Ok(_) => {}
                Err(e) => {
                    log::error!(
                        "Error checking if UnvaultEmergency '{}' is confirmed: '{}'",
                        &txid,
                        e
                    );
                }
            }
        }
        None => {
            // We don't remove it from the cache, so we'll check this outpoint at the next poll
            log::info!(
                "Could not find a current transaction spending the Unvault txo at '{}', will check again at next poll",
                unvault_outpoint
            );

            // TODO: we should probably remove it from the DB once its spender is deeply
            // confirmed..
        }
    };

    Ok(())
}

// Update our state when a new UTXO appears that is paying to the Deposit descriptor
fn handle_new_deposit(
    revaultd: &mut Arc<RwLock<RevaultD>>,
    db_path: &Path,
    bitcoind: &BitcoinD,
    deposits_cache: &mut HashMap<OutPoint, UtxoInfo>,
    outpoint: OutPoint,
    utxo: UtxoInfo,
) -> Result<(), BitcoindError> {
    if utxo.txo.value <= revault_tx::transactions::DUST_LIMIT {
        log::info!(
            "Received a deposit that we considered being dust. Ignoring it. \
                 Outpoint: '{}', amount: '{}'",
            outpoint,
            utxo.txo.value
        );
        return Ok(());
    }

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
        db_path,
        revaultd
            .read()
            .unwrap()
            .wallet_id
            .expect("Wallet id is set at startup in setup_db()"),
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

    Ok(())
}

// Update our state when we notice a deeply-enough confirmed deposit UTXO
fn handle_confirmed_deposit(
    revaultd: &mut Arc<RwLock<RevaultD>>,
    db_path: &Path,
    bitcoind: &BitcoinD,
    deposits_cache: &mut HashMap<OutPoint, UtxoInfo>,
    outpoint: OutPoint,
    utxo: UtxoInfo,
) -> Result<(), BitcoindError> {
    let blockheight =
        if let (_, Some(height), _) = bitcoind.get_wallet_transaction(&outpoint.txid)? {
            height
        } else {
            // This is theoretically possible if it gets unconfirmed in between the call to
            // listunspent and this one. This was actually encountered by the reorg tests.
            log::error!(
                "Deposit transaction for '{}' isn't confirmed but it's part of the \
                         confirmed deposits returned by listunspent.",
                outpoint
            );
            return Ok(());
        };

    let txo_value = utxo.txo.value;
    // emer_tx and unemer_tx are None for managers
    let (unvault_tx, cancel_tx, emer_tx, unemer_tx) =
        match presigned_transactions(&revaultd.read().unwrap(), outpoint, utxo) {
            Ok(txs) => txs,
            Err(e) => {
                log::error!(
                    "Unexpected error deriving transaction for '{}', amount: '{}': '{}'",
                    outpoint,
                    txo_value,
                    e
                );
                return Ok(());
            }
        };

    db_confirm_deposit(
        db_path,
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
        .is_confirmed = true;

    log::debug!("Vault at {} is now confirmed", &outpoint);

    Ok(())
}

// Called when a deposit UTXO disappears from the listunspent result, ie it was spent. This tries
// to figure out where it went.
fn handle_spent_deposit(
    revaultd: &mut Arc<RwLock<RevaultD>>,
    db_path: &Path,
    bitcoind: &BitcoinD,
    deposits_cache: &mut HashMap<OutPoint, UtxoInfo>,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
    deposit_outpoint: OutPoint,
    utxo: UtxoInfo,
) -> Result<(), BitcoindError> {
    let unvault_txin = match unvault_txin_from_deposit(&revaultd, &deposit_outpoint, utxo.txo) {
        Ok(txin) => txin,
        Err(e) => {
            log::error!(
                "Error while getting Unvault txin for deposit '{}': '{}'",
                &deposit_outpoint,
                e
            );
            return Ok(());
        }
    };
    let unvault_outpoint = unvault_txin.outpoint();

    // Was it spent by an Unvault tx? No worry if the Unvault txo was spent too, it'll be
    // noticed when we poll them next.
    if bitcoind.is_current(&unvault_outpoint.txid)? {
        log::debug!(
            "Found Unvault transaction '{}' in wallet for vault at '{}'",
            &unvault_outpoint.txid,
            &deposit_outpoint
        );

        db_unvault_deposit(&db_path, &unvault_outpoint.txid)?;
        unvaults_cache.insert(
            unvault_outpoint,
            UtxoInfo {
                is_confirmed: false,
                txo: unvault_txin.into_txout().into_txout(),
            },
        );
        deposits_cache
            .remove(&deposit_outpoint)
            .expect("It was in spent_deposits, it must still be here.");

        return Ok(());
    }

    // Was it spent by the Emergency transaction?
    let db_vault =
        db_vault_by_deposit(&db_path, &deposit_outpoint)?.expect("Spent deposit doesn't exist?");
    if let Some(emer_txid) = emer_txid(revaultd, &db_vault)? {
        if bitcoind.is_current(&emer_txid)? {
            db_mark_emergencying_vault(&db_path, db_vault.id)?;
            deposits_cache
                .remove(&deposit_outpoint)
                .expect("It was in spent_deposits, it must still be here.");
        }
    }

    // TODO: handle bypass

    // Only remove the deposit from the cache if it's not in mempool nor in block chain.
    if bitcoind.is_current(&deposit_outpoint.txid)? {
        log::error!(
            "Deposit at '{}' is still current but is not returned by listunspent and \
             Unvault/Emer transactions aren't seen",
            &deposit_outpoint,
        );
    } else {
        log::error!(
            "The deposit utxo created via '{}' just vanished",
            &deposit_outpoint
        );
        deposits_cache
            .remove(&deposit_outpoint)
            .expect("It was in spent_deposits, it must still be here.");
        // TODO: we should probably remove it from db too, but do some more reasearch about
        // where it went first.
    }

    Ok(())
}

// This syncs with bitcoind our onchain utxos. We track the deposits and unvaults ones, and react
// to their creation, confirmation, and spending. We are then tracking their spending depending on
// their kind. Pretty much like a tree, for which we actively track the trunk with the watchonly
// wallet and then keep track of the leaves as they happen onchain:
//             _ Bypass             __ UnvaultEmergency
//           /                    /
// Deposit  +-------> Unvault ---+- Spend
//          \__ Emergency         \__ Cancel
fn update_utxos(
    revaultd: &mut Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
    deposits_cache: &mut HashMap<OutPoint, UtxoInfo>,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
    previous_tip: &BlockchainTip,
) -> Result<(), BitcoindError> {
    let db_path = revaultd.read().unwrap().db_file();

    // First, let's check our deposits.
    let OnchainDescriptorState {
        new_unconf: new_deposits,
        new_conf: conf_deposits,
        new_spent: spent_deposits,
    } = bitcoind.sync_deposits(&deposits_cache, revaultd.read().unwrap().min_conf)?;

    for (outpoint, utxo) in new_deposits {
        handle_new_deposit(revaultd, &db_path, bitcoind, deposits_cache, outpoint, utxo)?;
    }

    for (outpoint, utxo) in conf_deposits {
        handle_confirmed_deposit(revaultd, &db_path, bitcoind, deposits_cache, outpoint, utxo)?;
    }

    for (outpoint, utxo) in spent_deposits {
        handle_spent_deposit(
            revaultd,
            &db_path,
            bitcoind,
            deposits_cache,
            unvaults_cache,
            outpoint,
            utxo,
        )?;
    }

    // Now, check the Unvault utxos.
    let OnchainDescriptorState {
        new_unconf: new_unvaults,
        new_conf: conf_unvaults,
        new_spent: spent_unvaults,
    } = bitcoind.sync_unvaults(&unvaults_cache)?;

    for (outpoint, utxo) in new_unvaults {
        // Note that it *might* have actually been confirmed in-between the last poll, but we keep
        // single transitions, and it's no big deal to mark it confirmed during the next poll.
        db_unvault_deposit(&revaultd.read().unwrap().db_file(), &outpoint.txid)?;
        unvaults_cache.insert(outpoint, utxo);
        log::debug!("Got a new unconfirmed unvault utxo at {} ", outpoint);
    }

    for (outpoint, _) in conf_unvaults {
        db_confirm_unvault(&db_path, &outpoint.txid)?;
        unvaults_cache
            .get_mut(&outpoint)
            .ok_or_else(|| BitcoindError::Custom("An unknown unvault got confirmed?".to_string()))?
            .is_confirmed = true;
        log::debug!("Unvault transaction at {} is now confirmed", &outpoint);
    }

    for (unvault_outpoint, _) in spent_unvaults {
        handle_spent_unvault(
            revaultd,
            &db_path,
            bitcoind,
            unvaults_cache,
            previous_tip,
            &unvault_outpoint,
        )?;
    }

    Ok(())
}

/// Bitcoind uses a guess for the value of verificationprogress. It will eventually get to
/// be 1, but can take some time; when it's > 0.99999 we are synced anyways so use that.
fn roundup_progress(progress: f64) -> f64 {
    let precision = 10u64.pow(5) as f64;
    let progress_rounded = (progress * precision + 1.0) as u64;

    if progress_rounded >= precision as u64 {
        1.0
    } else {
        (progress_rounded as f64 / precision) as f64
    }
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
    let delta = headers.checked_sub(blocks).unwrap_or(0);
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

    // TODO: sanity check descriptors are imported when migrating to 0.22

    if !PathBuf::from(bitcoind_wallet_path.clone()).exists() {
        // Remove any leftover. This can happen if we delete the watchonly wallet but don't restart
        // bitcoind.
        while bitcoind.listwallets()?.contains(&bitcoind_wallet_path) {
            log::info!("Found a leftover watchonly wallet loaded on bitcoind. Removing it.");
            if let Err(e) = bitcoind.unloadwallet(bitcoind_wallet_path.clone()) {
                log::error!("Unloading wallet '{}': '{}'", &bitcoind_wallet_path, e);
            }
        }

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

    match bitcoind
        .listwallets()?
        .into_iter()
        .filter(|path| path == &bitcoind_wallet_path)
        .count()
    {
        0 => {
            log::info!("Loading our watchonly wallet '{}'.", bitcoind_wallet_path);
            bitcoind.loadwallet_startup(bitcoind_wallet_path)?;
            Ok(())
        }
        1 => {
            log::info!(
                "Watchonly wallet '{}' already loaded.",
                bitcoind_wallet_path
            );
            Ok(())
        }
        n => Err(BitcoindError::Custom(format!(
            "{} watchonly wallet '{}' are loaded on bitcoind.",
            n, bitcoind_wallet_path
        ))),
    }
}

// Update the progress made by bitcoind toward the tip.
fn update_sync_status(
    revaultd: &Arc<RwLock<RevaultD>>,
    bitcoind: &Arc<RwLock<BitcoinD>>,
    sync_progress: &Arc<RwLock<f64>>,
    now: Instant,
    last_poll: &mut Option<Instant>,
    sync_waittime: &mut Option<Duration>,
) -> Result<(), BitcoindError> {
    // While waiting for bitcoind to be synced, guesstimate how much time of block
    // connection we have left to not harass it with `getblockchaininfo`.
    if let Some(last) = last_poll {
        if let Some(waittime) = sync_waittime {
            if now.duration_since(*last) < *waittime {
                return Ok(());
            }
        }
    }

    bitcoind_sync_status(
        &bitcoind.read().unwrap(),
        &revaultd.read().unwrap().bitcoind_config,
        sync_waittime,
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

    *last_poll = Some(now);
    Ok(())
}

pub fn poller_main(
    mut revaultd: Arc<RwLock<RevaultD>>,
    bitcoind: Arc<RwLock<BitcoinD>>,
    sync_progress: Arc<RwLock<f64>>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), BitcoindError> {
    let mut last_poll = None;
    let mut sync_waittime = None;
    // We use a cache for maintaining our deposits' state up-to-date by polling `listunspent`
    let mut deposits_cache = populate_deposit_cache(&revaultd.read().unwrap())?;
    // Same for the unvaults
    let mut unvaults_cache = populate_unvaults_cache(&revaultd.read().unwrap())?;
    // When bitcoind is synced, we poll each 30s. On regtest we speed it up for testing.
    let poll_interval = revaultd.read().unwrap().bitcoind_config.poll_interval_secs;

    while !shutdown.load(Ordering::Relaxed) {
        let now = Instant::now();

        if (*sync_progress.read().unwrap() as u32) < 1 {
            update_sync_status(
                &revaultd,
                &bitcoind,
                &sync_progress,
                now,
                &mut last_poll,
                &mut sync_waittime,
            )?;
            continue;
        }

        if let Some(last_poll) = last_poll {
            if now.duration_since(last_poll) < poll_interval {
                thread::sleep(Duration::from_millis(500));
                continue;
            }
        }

        last_poll = Some(now);
        let previous_tip = update_tip(
            &mut revaultd,
            &bitcoind.read().unwrap(),
            &mut deposits_cache,
            &mut unvaults_cache,
        )?;
        update_utxos(
            &mut revaultd,
            &bitcoind.read().unwrap(),
            &mut deposits_cache,
            &mut unvaults_cache,
            &previous_tip,
        )?;
    }

    Ok(())
}
