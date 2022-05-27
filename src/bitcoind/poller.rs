use crate::config::BitcoindConfig;
use crate::{
    bitcoind::{
        interface::{BitcoinD, DepositsState, SyncInfo, UnvaultsState, UtxoInfo},
        utils::{
            cancel_txids, emer_txid, populate_deposit_cache, populate_unvaults_cache,
            presigned_transactions, unemer_txid, unvault_txid, unvault_txin_from_deposit,
            vault_deposit_utxo,
        },
        BitcoindError,
    },
    database::{
        actions::{
            db_cancel_unvault, db_confirm_deposit, db_confirm_unvault, db_downgrade_unvaulted,
            db_emer_unvault, db_insert_new_unconfirmed_vault, db_mark_broadcasted_spend,
            db_mark_canceled_unvault, db_mark_emergencied_unvault, db_mark_emergencied_vault,
            db_mark_emergencying_vault, db_mark_rebroadcastable_spend, db_mark_spent_unvault,
            db_spend_unvault, db_unconfirm_cancel_dbtx, db_unconfirm_deposit_dbtx,
            db_unconfirm_emer_dbtx, db_unconfirm_spend_dbtx, db_unconfirm_unemer_dbtx,
            db_unconfirm_unvault_dbtx, db_unvault_deposit, db_update_deposit_index,
            db_update_first_stage_blockheight_from_unvault_txid, db_update_tip,
        },
        interface::{
            db_broadcastable_spend_transactions, db_cpfpable_spends, db_cpfpable_unvaults,
            db_emering_vaults, db_exec, db_spending_vaults, db_tip, db_txids_unvaulted_no_bh,
            db_unemering_vaults, db_unvault_dbtx, db_unvault_transaction, db_vault_by_deposit,
            db_vault_by_unvault_txid, db_vaults_by_status, db_vaults_dbtx, db_wallet,
        },
        schema::DbVault,
    },
    revaultd::{BlockchainTip, RevaultD, VaultStatus},
};
use revault_tx::{
    bitcoin::{consensus::encode, secp256k1, Amount, OutPoint, Txid},
    error::TransactionCreationError,
    miniscript::descriptor::{DescriptorSecretKey, DescriptorXKey, KeyMap, Wildcard},
    scripts::CpfpDescriptor,
    transactions::{
        CpfpTransaction, CpfpableTransaction, RevaultTransaction, SpendTransaction,
        UnvaultTransaction,
    },
    txins::{CpfpTxIn, RevaultTxIn},
    txouts::{CpfpTxOut, RevaultTxOut},
};

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// At how many sats/kWU below the target feerate do we CPFP a transaction.
const CPFP_THRESHOLD: u64 = 1_000;

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
                log::error!("Error broadcasting Spend tx '{}': '{}'", txid, e);
            }
        }
    }

    Ok(())
}

// Set the blockheight of the Unvault tx if it confirmed for vaults that are "more than unvaulting"
fn mark_confirmed_unvaults(
    revaultd: &Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
) -> Result<(), BitcoindError> {
    let db_path = revaultd.read().unwrap().db_file();

    for txid in db_txids_unvaulted_no_bh(&db_path)? {
        if let Some(bh) = bitcoind.get_wallet_transaction(&txid)?.blockheight {
            db_update_first_stage_blockheight_from_unvault_txid(&db_path, &txid, bh)?;
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
    let tx = bitcoind.get_wallet_transaction(spend_txid)?;
    if let (Some(height), Some(time)) = (tx.blockheight, tx.blocktime) {
        db_mark_spent_unvault(db_path, db_vault.id, time, height)?;
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
        let spend_txid = &db_vault.final_txid.expect("Must be set for 'spending'");

        match maybe_confirm_spend(&db_path, bitcoind, &db_vault, spend_txid) {
            Ok(false) => {}
            Ok(true) => continue,
            Err(e) => {
                log::error!(
                    "Error checking if Spend '{}' is confirmed: '{}'",
                    &spend_txid,
                    e
                );
            }
        };

        if !bitcoind.is_in_mempool(spend_txid)? {
            // At least, is this transaction still in mempool?
            // If it was evicted, downgrade it to `unvaulted`, the polling loop will
            // take care of checking its new state immediately.
            db_downgrade_unvaulted(&db_path, &unvault_tx.txid())?;

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
    // FIXME: remove this unwrap in favour of an Error enum variant for txs not found
    let unvault_tx = db_unvault_transaction(db_path, db_vault.id)?
        .unwrap()
        .psbt
        .assert_unvault();
    let unvault_descriptor = revaultd.read().unwrap().unvault_descriptor.derive(
        db_vault.derivation_index,
        &revaultd.read().unwrap().secp_ctx,
    );
    let unvault_txin = unvault_tx.revault_unvault_txin(&unvault_descriptor);
    let unvault_outpoint = unvault_txin.outpoint();

    db_downgrade_unvaulted(db_path, &unvault_tx.tx().txid())?;

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
    let tx = bitcoind.get_wallet_transaction(cancel_txid)?;
    if let (Some(height), Some(time)) = (tx.blockheight, tx.blocktime) {
        db_mark_canceled_unvault(db_path, db_vault.id, time, height)?;
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

    for db_vault in db_vaults_by_status(&db_path, VaultStatus::Canceling)? {
        let cancel_txid = &db_vault
            .final_txid
            .expect("Must be there in Canceling state");
        match maybe_confirm_cancel(&db_path, bitcoind, &db_vault, cancel_txid) {
            Ok(false) => {}
            Ok(true) => continue,
            Err(e) => {
                log::error!(
                    "Error checking if Cancel '{}' is confirmed: '{}'",
                    &cancel_txid,
                    e
                );
            }
        };

        if !bitcoind.is_in_mempool(cancel_txid)? {
            // At least, is this transaction still in mempool?
            // If it was evicted, downgrade it to `unvaulted`, the polling loop will
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
    let transaction = bitcoind.get_wallet_transaction(unemer_txid)?;
    if let (Some(height), Some(blocktime)) = (transaction.blockheight, transaction.blocktime) {
        db_mark_emergencied_unvault(db_path, db_vault.id, blocktime, height)?;
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
            }
        };

        if !bitcoind.is_in_mempool(&unemer_txid)? {
            // At least, is this transaction still in mempool?
            // If it was evicted, downgrade it to `unvaulted`, the polling loop will
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
    let transaction = bitcoind.get_wallet_transaction(emer_txid)?;
    if let (Some(height), Some(blocktime)) = (transaction.blockheight, transaction.blocktime) {
        db_mark_emergencied_vault(db_path, db_vault.id, blocktime, height)?;
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
            }
        };

        if !bitcoind.is_in_mempool(&emer_txid)? {
            log::warn!("Emergency tx '{}' was evicted from mempool.", &emer_txid,);
            // TODO: broadcast it again, as well as the other Emergency txs in this case!!
        } else {
            log::trace!("Emergency tx '{}' is still unconfirmed", emer_txid);
        }
    }

    Ok(())
}

pub enum ToBeCpfped {
    Spend(SpendTransaction),
    Unvault(UnvaultTransaction),
}

impl ToBeCpfped {
    pub fn txid(&self) -> Txid {
        match self {
            Self::Spend(s) => s.txid(),
            Self::Unvault(u) => u.txid(),
        }
    }

    pub fn cpfp_txin(
        &self,
        desc: &CpfpDescriptor,
        secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    ) -> Option<CpfpTxIn> {
        match self {
            Self::Spend(s) => s.cpfp_txin(desc, secp),
            Self::Unvault(u) => u.cpfp_txin(desc, secp),
        }
    }

    pub fn max_weight(&self) -> u64 {
        match self {
            Self::Spend(s) => s.max_weight(),
            Self::Unvault(u) => u.max_weight(),
        }
    }

    pub fn fees(&self) -> Amount {
        match self {
            Self::Spend(s) => s.fees(),
            Self::Unvault(u) => u.fees(),
        }
    }
}

// CPFP a bunch of transactions, bumping their feerate by at least `target_feerate`.
// `target_feerate` is expressed in sat/kWU.
// All the transactions' feerate MUST be below `target_feerate`.
pub fn cpfp_package(
    revaultd: &Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
    to_be_cpfped: Vec<ToBeCpfped>,
    target_feerate: u64,
) -> Result<(), BitcoindError> {
    let revaultd = revaultd.read().unwrap();
    let cpfp_descriptor = &revaultd.cpfp_descriptor;

    // First of all, compute all the information we need from the to-be-cpfped transactions.
    let mut txids = HashSet::with_capacity(to_be_cpfped.len());
    let mut package_weight = 0;
    let mut package_fees = Amount::from_sat(0);
    let mut txins = Vec::with_capacity(to_be_cpfped.len());
    for tx in to_be_cpfped.iter() {
        txids.insert(tx.txid());
        package_weight += tx.max_weight();
        package_fees += tx.fees();
        assert!(((package_fees.as_sat() * 1000 / package_weight) as u64) < target_feerate);
        match tx.cpfp_txin(cpfp_descriptor, &revaultd.secp_ctx) {
            Some(txin) => txins.push(txin),
            None => {
                log::error!("No CPFP txin for tx '{}'", tx.txid());
                return Ok(());
            }
        }
    }
    let tx_feerate = (package_fees.as_sat() * 1_000 / package_weight) as u64; // to sats/kWU
    assert!(tx_feerate < target_feerate);
    let added_feerate = target_feerate - tx_feerate;

    // Then construct the child PSBT
    let confirmed_cpfp_utxos: Vec<_> = bitcoind
        .list_unspent_cpfp()?
        .into_iter()
        .filter_map(|l| {
            // Not considering our own outputs nor UTXOs still in mempool
            if txids.contains(&l.outpoint.txid) || l.confirmations < 1 {
                None
            } else {
                let txout = CpfpTxOut::new(
                    Amount::from_sat(l.txo.value),
                    &revaultd.derived_cpfp_descriptor(l.derivation_index.expect("Must be here")),
                );
                Some(CpfpTxIn::new(l.outpoint, txout))
            }
        })
        .collect();
    let psbt = match CpfpTransaction::from_txins(
        txins,
        package_weight,
        package_fees,
        added_feerate,
        confirmed_cpfp_utxos,
    ) {
        Ok(tx) => tx,
        Err(TransactionCreationError::InsufficientFunds) => {
            // Well, we're poor.
            log::error!(
                "We wanted to feebump transactions '{:?}', but we don't have enough funds!",
                txids
            );
            return Ok(());
        }
        Err(e) => {
            log::error!("Error while creating CPFP transaction: '{}'", e);
            return Ok(());
        }
    };

    // Finally, sign and (try to) broadcast the CPFP transaction
    let (complete, psbt_signed) = bitcoind.sign_psbt(psbt.psbt())?;
    if !complete {
        log::error!(
            "Bitcoind returned a non-finalized CPFP PSBT: {}",
            base64::encode(encode::serialize(&psbt_signed))
        );
        return Ok(());
    }

    let final_tx = psbt_signed.extract_tx();
    if let Err(e) = bitcoind.broadcast_transaction(&final_tx) {
        log::error!("Error broadcasting '{:?}' CPFP tx: {}", txids, e);
    } else {
        log::info!("CPFPed transactions with ids '{:?}'", txids);
    }

    Ok(())
}

// `target_feerate` is in sats/kWU
pub fn should_cpfp(
    bitcoind: &BitcoinD,
    tx: &impl CpfpableTransaction,
    target_feerate: u64,
) -> bool {
    bitcoind
        .get_wallet_transaction(&tx.txid())
        // In the unlikely (actually, shouldn't happen but hey) case where
        // the transaction isn't part of our wallet, default to feebumping
        // it since the user explicitly marked it as high prio.
        .map(|w| w.blockheight.is_none())
        .unwrap_or(true)
        // * 1000 for kWU
        && tx.max_feerate() * 1_000 + CPFP_THRESHOLD < target_feerate
}

fn maybe_cpfp_txs(
    revaultd: &Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
) -> Result<(), BitcoindError> {
    let db_path = revaultd.read().unwrap().db_file();
    log::debug!("Checking if transactions need CPFP...");

    if revaultd.read().unwrap().cpfp_key.is_none() {
        log::warn!("We should CPFP transactions, but we don't have a cpfp key!");
        return Ok(());
    }

    let current_feerate = match bitcoind.estimate_feerate()? {
        Some(f) => f,
        None => {
            log::warn!("Fee estimation not available, skipping CPFP");
            return Ok(());
        }
    };

    // We feebump all the spends and unvaults that are still unconfirmed.
    let to_cpfp: Vec<_> = db_cpfpable_spends(&db_path)?
        .into_iter()
        .filter_map(|spend| {
            if should_cpfp(bitcoind, &spend, current_feerate) {
                Some(ToBeCpfped::Spend(spend))
            } else {
                None
            }
        })
        .chain(
            db_cpfpable_unvaults(&db_path)?
                .into_iter()
                .filter_map(|unvault| {
                    if should_cpfp(bitcoind, &unvault, current_feerate) {
                        Some(ToBeCpfped::Unvault(unvault))
                    } else {
                        None
                    }
                }),
        )
        .collect();

    // TODO: std transaction max size check and split
    // TODO: smarter RBF (especially opportunistically with the fee delta)
    if !to_cpfp.is_empty() {
        cpfp_package(revaultd, bitcoind, to_cpfp, current_feerate)?;
    } else {
        log::debug!("Nothing to CPFP");
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
    log::debug!("New tip: {:?}", new_tip);
    let db_path = revaultd.read().unwrap().db_file();

    // First we update it in DB
    db_update_tip(&db_path, new_tip)?;

    // Then we CPFP our spends/unvaults, if we can
    if revaultd.read().unwrap().is_manager() {
        maybe_cpfp_txs(revaultd, bitcoind)?;
    }

    // Then we check if any Spend became mature yet
    maybe_broadcast_spend_transactions(revaultd, bitcoind)?;

    // Did some Unvault transaction confirmed that we haven't noticed yet?
    // This check is necessary because:
    //  - We need the blockheight at which it confirmed for reorg handling
    //  - We don't have a strict unvaulting->unvaulted->[spending/canceling] state
    //    transition as we have for deposits, for a smoother UX.
    mark_confirmed_unvaults(revaultd, bitcoind)?;

    // Did some Spend transaction confirmed?
    mark_confirmed_spends(revaultd, bitcoind, unvaults_cache)?;

    // Did some Cancel transaction get confirmed?
    mark_confirmed_cancels(revaultd, bitcoind, unvaults_cache)?;

    // Did some Emergency got confirmed?
    mark_confirmed_emers(revaultd, bitcoind)?;
    mark_confirmed_unemers(revaultd, bitcoind, unvaults_cache)?;

    Ok(())
}

// Rewind the state of a vault whose Unvault transaction got unconfirmed.
// Panics if the status of the vault isn't at the "second stage".
fn unconfirm_unvault(
    revaultd: &RevaultD,
    db_tx: &rusqlite::Transaction,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
    vault: &DbVault,
    unvault_tx: &UnvaultTransaction,
) -> Result<(), BitcoindError> {
    assert!(matches!(
        vault.status,
        VaultStatus::Unvaulted
            | VaultStatus::Spending
            | VaultStatus::Spent
            | VaultStatus::Canceling
            | VaultStatus::Canceled
            | VaultStatus::UnvaultEmergencyVaulting
            | VaultStatus::UnvaultEmergencyVaulted
    ));
    let unvault_txid = unvault_tx.txid();

    // First of all, downgrade the vault back to 'unvaulting' in DB.
    db_unconfirm_unvault_dbtx(db_tx, vault.id)?;
    // Then repopulate the cache (we remove the entry on spend) accordingly. This replaces
    // the entry if the status is 'unvaulted'.
    let der_unvault_descriptor = revaultd
        .unvault_descriptor
        .derive(vault.derivation_index, &revaultd.secp_ctx);
    let unvault_txin = unvault_tx.revault_unvault_txin(&der_unvault_descriptor);
    let unvault_outpoint = unvault_txin.outpoint();
    let txo = unvault_txin.into_txout().into_txout();
    unvaults_cache.insert(
        unvault_outpoint,
        UtxoInfo {
            txo,
            is_confirmed: false,
        },
    );

    // If there is any, don't forget to rebroadcast the Spend transaction at the next tip update!
    // NOTE: it's a NOP if there is no Spend tx (eg if we are a stakeholder)
    db_mark_rebroadcastable_spend(db_tx, &unvault_txid)?;

    Ok(())
}

// Mark a vault as unconfirmed in DB, and update the caches accordingly.
// Will panic if called for an unconfirmed vault.
fn unconfirm_vault(
    revaultd: &RevaultD,
    db_tx: &rusqlite::Transaction,
    deposits_cache: &mut HashMap<OutPoint, UtxoInfo>,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
    vault: &DbVault,
) -> Result<(), BitcoindError> {
    let unvault_tx = db_unvault_dbtx(db_tx, vault.id)?;

    // If it was at the second stage, unconfirm the Unvault first. It will re-broadcast
    // the necessary transactions
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
        unconfirm_unvault(
            revaultd,
            db_tx,
            unvaults_cache,
            vault,
            unvault_tx
                .as_ref()
                .expect("Must be in DB for these statuses"),
        )?;
    }

    // In any case, it must not stay in the unvaults cache
    if let Some(ref unvault_tx) = unvault_tx {
        let der_unvault_descriptor = revaultd
            .unvault_descriptor
            .derive(vault.derivation_index, &revaultd.secp_ctx);
        let unvault_txin = unvault_tx.revault_unvault_txin(&der_unvault_descriptor);
        let unvault_outpoint = unvault_txin.outpoint();
        unvaults_cache.remove(&unvault_outpoint);
    };

    // Insert it in the deposit cache as unconfirmed, equivalent to update it to
    // unconfirmed if already present.
    let mut utxo = vault_deposit_utxo(revaultd, vault);
    utxo.is_confirmed = false;
    deposits_cache.insert(vault.deposit_outpoint, utxo);

    // Finally unconfirm it from DB and wipe all associated transactions
    db_unconfirm_deposit_dbtx(db_tx, vault.id)?;

    Ok(())
}

// Rebroadcast the onchain transactions for these vaults according to their status.
fn rebroadcast_transactions(
    revaultd: &Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
    db_vaults: &[DbVault],
) {
    for db_vault in db_vaults {
        // Re-broadcast the deposit tx no matter the state of the vault
        if let Err(e) = bitcoind.rebroadcast_wallet_tx(&db_vault.deposit_outpoint.txid) {
            log::debug!(
                "Error re-broadcasting deposit tx for vault {}: '{}'",
                &db_vault.deposit_outpoint,
                e
            );
        }

        // If it was emergencied, re-broadcast that too.
        if matches!(
            db_vault.status,
            VaultStatus::EmergencyVaulting | VaultStatus::EmergencyVaulted
        ) {
            if let Some(emer_txid) =
                emer_txid(revaultd, &db_vault).expect("Must be able to derive emer txid")
            {
                if let Err(e) = bitcoind.rebroadcast_wallet_tx(&emer_txid) {
                    log::debug!(
                        "Error re-broadcasting Emergency tx for vault {}: '{}'",
                        &db_vault.deposit_outpoint,
                        e
                    );
                }
            }
        }

        // If no other transaction was previously broadcast, stop there.
        if matches!(
            db_vault.status,
            VaultStatus::Unconfirmed
                | VaultStatus::Funded
                | VaultStatus::Securing
                | VaultStatus::Secured
                | VaultStatus::Activating
                | VaultStatus::Active
                | VaultStatus::EmergencyVaulting
                | VaultStatus::EmergencyVaulted
        ) {
            continue;
        }

        // It was necessarily unvaulted.
        let unvault_txid = unvault_txid(&revaultd.read().unwrap(), &db_vault)
            .expect("Must be able to derive Unvault txid");
        if let Err(e) = bitcoind.rebroadcast_wallet_tx(&unvault_txid) {
            log::debug!(
                "Error re-broadcasting Unvault tx for vault {}: '{}'",
                &db_vault.deposit_outpoint,
                e
            );
        }

        // If it was emergencied at the unvault level, re-broadcast that too.
        if matches!(
            db_vault.status,
            VaultStatus::UnvaultEmergencyVaulting | VaultStatus::UnvaultEmergencyVaulted
        ) {
            if let Some(unemer_txid) =
                unemer_txid(revaultd, &db_vault).expect("Must be able to derive unvault emer txid")
            {
                if let Err(e) = bitcoind.rebroadcast_wallet_tx(&unemer_txid) {
                    log::debug!(
                        "Error re-broadcasting Unvault Emergency tx for vault {}: '{}'",
                        &db_vault.deposit_outpoint,
                        e
                    );
                }
            }
        }

        // And same if it was canceled.
        if matches!(
            db_vault.status,
            VaultStatus::Canceling | VaultStatus::Canceled
        ) {
            let cancel_txid = &db_vault
                .final_txid
                .expect("Must be there for canceling/canceled");
            if let Err(e) = bitcoind.rebroadcast_wallet_tx(cancel_txid) {
                log::debug!(
                    "Error re-broadcasting Cancel tx for vault {}: '{}'",
                    &db_vault.deposit_outpoint,
                    e
                );
            }
        }
    }
}

// Find the common ancestor between the given tip and bitcoind's tip.
fn common_ancestor(
    bitcoind: &BitcoinD,
    tip: BlockchainTip,
) -> Result<BlockchainTip, BitcoindError> {
    let mut stats = bitcoind.get_block_stats(tip.hash)?;
    let mut ancestor = tip;

    log::info!("Looking for the common ancestor with the disconnected chain");
    while stats.confirmations == -1 {
        stats = bitcoind.get_block_stats(stats.previous_blockhash)?;
        ancestor = BlockchainTip {
            hash: stats.blockhash,
            height: stats.height,
        };
    }
    log::info!(
        "Found common ancestor at height {}: '{}'",
        ancestor.height,
        ancestor.hash
    );

    Ok(ancestor)
}

// This handles a block chain reorganization by rewinding our state to the latest common ancestor
// between the new chain and the fork we were on.
fn rewind_state(
    revaultd: &RevaultD,
    db_tx: &rusqlite::Transaction,
    ancestor: &BlockchainTip,
    deposits_cache: &mut HashMap<OutPoint, UtxoInfo>,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
    to_rebroadcast: &mut Vec<DbVault>,
) -> Result<(), BitcoindError> {
    log::info!("Starting to rewind our state..");

    for vault in db_vaults_dbtx(db_tx)? {
        // First, check the deposit transaction.

        // If it's already unconfirmed, no need to process it.
        // TODO: don't query them to the DB!
        let deposit_blockheight = match vault.deposit_blockheight {
            Some(bh) => bh,
            None => {
                if !matches!(vault.status, VaultStatus::Unconfirmed) {
                    log::error!(
                        "Transaction is not unconfirmed but we don't have the deposit_blockheight?"
                    );
                }
                log::debug!(
                    "Vault deposit '{}' is already unconfirmed",
                    vault.deposit_outpoint
                );
                continue;
            }
        };

        // If it got confirmed (according to our minimum number of confs) in our fork, mark the
        // vault as unconfirmed.
        let min_conf = revaultd.min_conf;
        let deposit_conf = ancestor
            .height
            .checked_add(1)
            .unwrap()
            .checked_sub(deposit_blockheight)
            .unwrap_or(0);
        if deposit_conf < min_conf {
            // FIXME: should we instead only wipe it if it was completely unconfirmed? That's
            // kinda the point of having a minimum number of confs.
            unconfirm_vault(&revaultd, db_tx, deposits_cache, unvaults_cache, &vault)?;
            to_rebroadcast.push(vault);
            log::warn!(
                "Vault deposit '{}' has {} confirmations at common ancestor height (< {})",
                vault.deposit_outpoint,
                deposit_conf,
                min_conf,
            );
            continue;
        }

        log::debug!(
            "Vault deposit '{}' still has {} confirmations at common ancestor height (>= {})",
            vault.deposit_outpoint,
            deposit_conf,
            min_conf
        );

        // Now, check the first stage transactions (which can be an Unvault, and Emergency, or a
        // Bypass which would be anything else).

        // If there is no stored first stage blockheight, no need to check for it. And there must
        // not be any second stage blockheight, so we can cut-through.
        let first_stage_bh = match vault.first_stage_tx_blockheight {
            Some(bh) => bh,
            None => {
                continue;
            }
        };

        // If the first stage transaction got confirmed within our fork, revert the state of the
        // vault to its previous one ('ed' -> 'ing')
        if first_stage_bh > ancestor.height {
            if matches!(vault.status, VaultStatus::EmergencyVaulted) {
                db_unconfirm_emer_dbtx(db_tx, vault.id)?;
                log::debug!(
                    "Vault {}'s Emergency transaction got unconfirmed.",
                    vault.deposit_outpoint,
                );
            } else if matches!(
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

                unconfirm_unvault(&revaultd, db_tx, unvaults_cache, &vault, &unvault_tx)?;
                to_rebroadcast.push(vault);

                log::debug!(
                    "Vault {}'s Unvault transaction {} got unconfirmed.",
                    vault.deposit_outpoint,
                    unvault_txid
                );
            }
            // TODO: bypass

            continue;
        } else {
            log::debug!(
                "Vault {}'s First Stage transaction is still confirmed (height '{}')",
                vault.deposit_outpoint,
                first_stage_bh,
            );
        }

        // Finally, if nothing got reorged out up to here, check the second-stage transaction
        // (which can be an UnvaultEmergency, a Cancel, or a Spend which is anything else)

        // If none was confirmed at all, don't bother.
        let second_stage_bh = match vault.second_stage_tx_blockheight {
            Some(bh) => bh,
            None => continue,
        };

        // If it was confirmed in our fork, revert to the previous state.
        if second_stage_bh > ancestor.height {
            if matches!(vault.status, VaultStatus::Spent) {
                db_unconfirm_spend_dbtx(db_tx, vault.id)?;
                log::debug!(
                    "Vault {}'s Spend transaction got unconfirmed.",
                    vault.deposit_outpoint,
                );
            } else if matches!(vault.status, VaultStatus::Canceled) {
                db_unconfirm_cancel_dbtx(db_tx, vault.id)?;
                log::debug!(
                    "Vault {}'s Cancel transaction got unconfirmed.",
                    vault.deposit_outpoint,
                );
            } else if matches!(vault.status, VaultStatus::UnvaultEmergencyVaulted) {
                db_unconfirm_unemer_dbtx(db_tx, vault.id)?;
                log::debug!(
                    "Vault {}'s UnvaultEmergency transaction got unconfirmed.",
                    vault.deposit_outpoint,
                );
            } else {
                log::error!("Second stage blockheight is set but vault isn't spent canceled nor unemervaulted?");
            }

            to_rebroadcast.push(vault);
            continue;
        } else {
            log::debug!(
                "Vault {}'s Second Stage transaction is still confirmed.",
                &vault.deposit_outpoint
            );
        }
    }

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
    let db_path = revaultd.read().unwrap().db_file();
    let current_tip = db_tip(&db_path).expect("Database must be accessible");
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
            new_tip_event(revaultd, bitcoind, &tip, unvaults_cache)?;
            return Ok(current_tip);
        }
    }

    log::warn!(
        "Detected reorg: our current stored tip is '{:?}' but bitcoind's is '{:?}'",
        &current_tip,
        &tip
    );
    let mut to_rebroadcast = vec![];
    // First of all, find the common ancestor between our saved tip and the mainchain.
    let common_ancestor =
        common_ancestor(bitcoind, current_tip).expect("Looking up common ancestor after reorg");
    // Then rewind our state down to this block.
    db_exec(&db_path, |db_tx| {
        rewind_state(
            &revaultd.read().unwrap(),
            db_tx,
            &common_ancestor,
            deposits_cache,
            unvaults_cache,
            &mut to_rebroadcast,
        )
        .expect("Error while rewinding state");
        Ok(())
    })
    .expect("Database must be accessible");
    // And save the ancestor's next block, so we'll rescan starting from there.
    let ancestor_next = BlockchainTip {
        hash: bitcoind.getblockhash(common_ancestor.height)?,
        height: common_ancestor.height,
    };
    db_update_tip(&db_path, &ancestor_next).expect("Updating tip after reorg");
    // Rebroadcast the transactions of the vaults whose state was reverted.
    rebroadcast_transactions(&revaultd, bitcoind, &to_rebroadcast);
    log::info!("Rescan of all vaults in db done.");

    Ok(current_tip)
}

// Which kind of transaction may spend the Unvault transaction.
#[derive(Debug)]
enum UnvaultSpender {
    // A Cancel, spending via the stakeholders path to a new deposit
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

    // First, check if it was spent by a Cancel, it's cheaper than the Spend and more likely than
    // the UnvaultEmergency.
    let cancel_txids = cancel_txids(revaultd, &vault)?;
    for txid in cancel_txids.iter() {
        if bitcoind.is_current(&txid)? {
            return Ok(Some(UnvaultSpender::Cancel(*txid)));
        }
    }

    // Second, check if it was spent by an UnvaultEmergency if we are able to, it's cheaper than
    // the Spend.
    let unemer_txid = unemer_txid(revaultd, &vault)?;
    if let Some(unemer_txid) = unemer_txid {
        if bitcoind.is_current(&unemer_txid)? {
            return Ok(Some(UnvaultSpender::Emergency(unemer_txid)));
        }
    }

    // Finally, fetch the spending transaction
    if let Some(spender_txid) = bitcoind.get_spender_txid(unvault_outpoint)? {
        // FIXME: be smarter, all the information are in the previous call, no need for a
        // second one.

        // Let's double-check that we didn't fetch a cancel, nor the unemer
        // In theory (read edge cases), a Cancel and UnEmer could have not been
        // current at the last bitcoind poll but could be now.
        // Be sure to not wrongly mark a Cancel or UnEmer as a Spend!
        if cancel_txids.contains(&spender_txid) || Some(spender_txid) == unemer_txid {
            // Alright, the spender is a cancel or the unemer,
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
    unvault_outpoint: &OutPoint,
) -> Result<(), BitcoindError> {
    match unvault_spender(revaultd, bitcoind, unvault_outpoint)? {
        Some(UnvaultSpender::Cancel(txid)) => {
            db_cancel_unvault(db_path, &unvault_outpoint.txid, &txid)?;
            unvaults_cache
                .remove(unvault_outpoint)
                .expect("An unknown unvault got spent?");
            log::debug!(
                "Unvault transaction at {} is now being canceled",
                &unvault_outpoint
            );

            // Immediately check if it was confirmed, just in case
            let (db_vault, _) = db_vault_by_unvault_txid(db_path, &unvault_outpoint.txid)?
                .ok_or_else(|| {
                    BitcoindError::Custom(format!(
                        "No vault for Unvault '{}'",
                        &unvault_outpoint.txid
                    ))
                })?;
            match maybe_confirm_cancel(db_path, bitcoind, &db_vault, &txid) {
                Ok(_) => {}
                Err(e) => {
                    log::error!("Error checking if Cancel '{}' is confirmed: '{}'", &txid, e);
                }
            }
        }
        Some(UnvaultSpender::Spend(txid)) => {
            db_spend_unvault(db_path, &unvault_outpoint.txid, &txid)?;
            unvaults_cache.remove(unvault_outpoint).ok_or_else(|| {
                BitcoindError::Custom("An unknown unvault got spent?".to_string())
            })?;
            log::debug!(
                "Unvault transaction at {} is now being spent",
                &unvault_outpoint
            );

            // Immediately check if it was confirmed, just in case
            let (db_vault, _) = db_vault_by_unvault_txid(db_path, &unvault_outpoint.txid)?
                .ok_or_else(|| {
                    BitcoindError::Custom(format!(
                        "No vault for Unvault '{}'",
                        &unvault_outpoint.txid
                    ))
                })?;
            match maybe_confirm_spend(db_path, bitcoind, &db_vault, &txid) {
                Ok(_) => {}
                Err(e) => {
                    log::error!("Error checking if Spend '{}' is confirmed: '{}'", &txid, e);
                }
            }
        }
        Some(UnvaultSpender::Emergency(txid)) => {
            db_emer_unvault(db_path, &unvault_outpoint.txid)?;
            unvaults_cache.remove(unvault_outpoint).ok_or_else(|| {
                BitcoindError::Custom("An unknown unvault got spent?".to_string())
            })?;
            log::warn!(
                "Unvault transaction at {} is now being emergencied",
                &unvault_outpoint
            );

            // Immediately check if it was confirmed, just in case
            let (db_vault, _) = db_vault_by_unvault_txid(db_path, &unvault_outpoint.txid)?
                .ok_or_else(|| {
                    BitcoindError::Custom(format!(
                        "No vault for Unvault '{}'",
                        &unvault_outpoint.txid
                    ))
                })?;
            match maybe_confirm_unemer(db_path, bitcoind, &db_vault, &txid) {
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
    // TODO: don't ignore those with the deposit split
    if utxo.txo.value <= revault_tx::transactions::DEPOSIT_MIN_SATS {
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
    let tx = bitcoind.get_wallet_transaction(&outpoint.txid)?;
    let (blockheight, blocktime) =
        if let (Some(height), Some(blocktime)) = (tx.blockheight, tx.blocktime) {
            (height, blocktime)
        } else {
            // This is theoretically possible if it gets unconfirmed in between the polling
            // and here. This was actually encountered by the reorg tests.
            log::error!(
                "Deposit transaction for '{}' isn't confirmed but it's part of the \
                 confirmed deposits returned by listsinceblock.",
                outpoint
            );
            return Ok(());
        };

    let txo_value = utxo.txo.value;
    // emer_tx and unemer_tx are None for managers
    let (unvault_tx, cancel_batch, emer_tx, unemer_tx) =
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
        blocktime,
        &unvault_tx,
        &cancel_batch,
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

// Called when we notice that a deposit txo isn't unspent (anymore).
fn handle_spent_deposit(
    revaultd: &mut Arc<RwLock<RevaultD>>,
    db_path: &Path,
    bitcoind: &BitcoinD,
    deposits_cache: &mut HashMap<OutPoint, UtxoInfo>,
    unvaults_cache: &mut HashMap<OutPoint, UtxoInfo>,
    deposit_outpoint: OutPoint,
    utxo: UtxoInfo,
) -> Result<(), BitcoindError> {
    let unvault_txin = match unvault_txin_from_deposit(revaultd, &deposit_outpoint, utxo.txo) {
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
        // Edge case: on reorg, we might note a deposit as spent and whatever second stage status
        // afterward before it goes through all the regular stages. Then the sigfetcher might overwrite
        // this state when it fetches the signatures from the coordinator.
        // In order to keep the reorg logic contained in the bitcoind module, temporarily refuse to
        // notice the spend until we are back to active.
        // Note this holds in regular cases (assuming signatures availability for managers).
        if !matches!(
            db_vault_by_deposit(db_path, &deposit_outpoint)?
                .unwrap()
                .status,
            VaultStatus::Active
        ) {
            log::warn!("Noticing a not-active vault as being spent.");
            return Ok(());
        }

        log::debug!(
            "Found Unvault transaction '{}' in wallet for vault at '{}'",
            &unvault_outpoint.txid,
            &deposit_outpoint
        );

        db_unvault_deposit(db_path, &unvault_outpoint.txid)?;
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
        db_vault_by_deposit(db_path, &deposit_outpoint)?.expect("Spent deposit doesn't exist?");
    if let Some(emer_txid) = emer_txid(revaultd, &db_vault)? {
        if bitcoind.is_current(&emer_txid)? {
            db_mark_emergencying_vault(db_path, db_vault.id)?;
            deposits_cache
                .remove(&deposit_outpoint)
                .expect("It was in spent_deposits, it must still be here.");

            log::debug!(
                "Found Emergency transaction spending deposit '{}'",
                &deposit_outpoint
            );
            return Ok(());
        }
    }

    // TODO: handle bypass

    // Only remove the deposit from the cache if it's not in mempool nor in block chain.
    if bitcoind.is_current(&deposit_outpoint.txid)? {
        log::error!(
            "Deposit at '{}' is still current but is spent and Unvault/Emer \
             transactions aren't seen",
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
    let DepositsState {
        new_unconf: new_deposits,
        new_conf: conf_deposits,
        new_spent: spent_deposits,
    } = bitcoind.sync_deposits(
        deposits_cache,
        previous_tip,
        revaultd.read().unwrap().min_conf,
    )?;

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
    let UnvaultsState {
        new_conf: conf_unvaults,
        new_spent: spent_unvaults,
    } = bitcoind.sync_unvaults(unvaults_cache)?;

    for outpoint in conf_unvaults {
        if let Some(bh) = bitcoind.get_wallet_transaction(&outpoint.txid)?.blockheight {
            db_confirm_unvault(&db_path, &outpoint.txid, bh)?;
            unvaults_cache
                .get_mut(&outpoint)
                .expect("An unknown unvault got confirmed?")
                .is_confirmed = true;
            log::debug!("Unvault transaction at {} is now confirmed", &outpoint);
        } else {
            log::error!(
                "Unvault at {} was marked confirmed but actually isn't",
                &outpoint
            );
        }
    }

    for outpoint in spent_unvaults {
        // If the unvault was still marked as unconfirmed, check whether it confirmed first.
        if !unvaults_cache[&outpoint].is_confirmed {
            if let Some(bh) = bitcoind.get_wallet_transaction(&outpoint.txid)?.blockheight {
                db_confirm_unvault(&db_path, &outpoint.txid, bh)?;
                unvaults_cache
                    .get_mut(&outpoint)
                    .expect("An unknown unvault got confirmed?")
                    .is_confirmed = true;
                log::debug!("Unvault transaction at {} is now confirmed", &outpoint);
            }
        }

        handle_spent_unvault(revaultd, &db_path, bitcoind, unvaults_cache, &outpoint)?;
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
    let delta = headers.saturating_sub(blocks);
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

        bitcoind.createwallet_startup(bitcoind_wallet_path, true)?;
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
        let addresses: Vec<_> = revaultd
            .all_deposit_addresses()
            .into_iter()
            .map(|a| bitcoind.addr_descriptor(&a))
            .collect::<Result<Vec<_>, _>>()?;
        log::trace!("Importing deposit descriptors '{:?}'", &addresses);
        bitcoind.startup_import_deposit_descriptors(addresses, wallet.timestamp, fresh_wallet)?;

        // As a consequence, we don't have enough information to opportunistically import a
        // descriptor at the reception of a deposit anymore. Thus we need to blindly import *both*
        // deposit and unvault descriptors..
        // FIXME: maybe we actually have, with the derivation_index_map ?
        let addresses: Vec<_> = revaultd
            .all_unvault_addresses()
            .into_iter()
            .map(|a| bitcoind.addr_descriptor(&a))
            .collect::<Result<Vec<_>, _>>()?;
        log::trace!("Importing unvault descriptors '{:?}'", &addresses);
        bitcoind.startup_import_unvault_descriptors(addresses, wallet.timestamp, fresh_wallet)?;
    }

    if let Some(cpfp_key) = revaultd.cpfp_key {
        let cpfp_wallet_path = revaultd
            .cpfp_wallet_file()
            .expect("Wallet id is set at startup in setup_db()");

        if !PathBuf::from(cpfp_wallet_path.clone()).exists() {
            log::info!("Creating the CPFP wallet");
            // Remove any leftover. This can happen if we delete the cpfp wallet but don't restart
            // bitcoind.
            while bitcoind.listwallets()?.contains(&cpfp_wallet_path) {
                log::info!("Found a leftover cpfp wallet loaded on bitcoind. Removing it.");
                if let Err(e) = bitcoind.unloadwallet(cpfp_wallet_path.clone()) {
                    log::error!("Unloading wallet '{}': '{}'", &cpfp_wallet_path, e);
                }
            }

            bitcoind.createwallet_startup(cpfp_wallet_path, false)?;
            log::info!("Importing descriptors to bitcoind cpfp wallet.");

            // Now, import descriptors.
            let mut keymap: KeyMap = KeyMap::new();
            let cpfp_private_key = DescriptorSecretKey::XPrv(DescriptorXKey {
                xkey: cpfp_key,
                origin: None,
                derivation_path: Default::default(),
                wildcard: Wildcard::Unhardened,
            });
            let sign_ctx = secp256k1::Secp256k1::signing_only();
            let cpfp_public_key = cpfp_private_key
                .as_public(&sign_ctx)
                .expect("We never use hardened");
            keymap.insert(cpfp_public_key, cpfp_private_key);
            let cpfp_desc = revaultd
                .cpfp_descriptor
                .inner()
                .to_string_with_secret(&keymap);

            bitcoind.startup_import_cpfp_descriptor(cpfp_desc, wallet.timestamp, fresh_wallet)?;
        }
    } else {
        log::info!("Not creating the CPFP wallet, as we don't have a CPFP key");
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
) {
    let mut last_poll = None;
    let mut sync_waittime = None;
    // We use a cache for maintaining our deposits' state up-to-date by polling `listsinceblock`
    let mut deposits_cache = populate_deposit_cache(&revaultd.read().unwrap())
        .expect("Error while populating deposit cache");
    // Same for the unvaults
    let mut unvaults_cache = populate_unvaults_cache(&revaultd.read().unwrap())
        .expect("Error while populating unvault cache");
    // When bitcoind is synced, we poll each 30s. On regtest we speed it up for testing.
    let poll_interval = revaultd.read().unwrap().bitcoind_config.poll_interval_secs;

    // Note that polling bitcoind is inherently racy. For instance if you get the height of the
    // current tip with `getblockcount`, you can't assume `getblockhash` on this height will not
    // fail as the tip might have been reorg'ed out.
    // Instead of having error handling code all around this module, we propagate the errors and
    // retry here.
    while !shutdown.load(Ordering::Relaxed) {
        let now = Instant::now();

        if (*sync_progress.read().unwrap() as u32) < 1 {
            if let Err(e) = update_sync_status(
                &revaultd,
                &bitcoind,
                &sync_progress,
                now,
                &mut last_poll,
                &mut sync_waittime,
            ) {
                log::error!("Error updating sync status: '{}'", e);
            }
            continue;
        }

        if let Some(last_poll) = last_poll {
            if now.duration_since(last_poll) < poll_interval {
                thread::sleep(Duration::from_millis(500));
                continue;
            }
        }

        let previous_tip = match update_tip(
            &mut revaultd,
            &bitcoind.read().unwrap(),
            &mut deposits_cache,
            &mut unvaults_cache,
        ) {
            Ok(tip) => tip,
            Err(e) => {
                log::error!("Error while updating tip: '{}'", e);
                continue;
            }
        };
        if let Err(e) = update_utxos(
            &mut revaultd,
            &bitcoind.read().unwrap(),
            &mut deposits_cache,
            &mut unvaults_cache,
            &previous_tip,
        ) {
            log::error!("Error while updating utxos: '{}'", e);
            continue;
        }
        last_poll = Some(now);
    }
}
