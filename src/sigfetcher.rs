///! Background thread that will poll the coordinator for signatures
use crate::{
    communication::{
        get_presigs, send_coord_sig_msg, wts_share_rev_signatures, CommunicationError,
    },
    database::{
        actions::{db_update_presigned_txs, db_update_vault_status},
        bitcointx::RevaultTx,
        interface::{
            db_cancel_transaction_by_txid, db_emer_transaction, db_sig_missing,
            db_unvault_emer_transaction,
        },
        schema::{DbTransaction, DbVault},
        DatabaseError,
    },
    revaultd::RevaultD,
    threadmessages::SigFetcherMessageOut,
};
use revault_net::transport::KKTransport;
use revault_tx::{
    bitcoin::{secp256k1, PublicKey as BitcoinPubKey},
    transactions::{transaction_chain_manager, RevaultTransaction},
};

use std::{
    collections::{BTreeMap, HashMap},
    path,
    sync::mpsc,
    sync::{Arc, RwLock},
    thread, time,
};

#[derive(Debug)]
pub enum SignatureFetcherError {
    DbError(DatabaseError),
    Communication(CommunicationError),
    ChannelDisconnected,
    MissingTransaction,
}

impl std::fmt::Display for SignatureFetcherError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::DbError(ref s) => write!(f, "Database error in sig fetcher thread: '{}'", s),
            Self::Communication(ref e) => {
                write!(f, "Communication error in sig fetcher thread: '{}'", e)
            }
            Self::ChannelDisconnected => {
                write!(f, "Channel disconnected error in sig fetcher thread")
            }
            Self::MissingTransaction => {
                write!(f, "Race: a presigned transaction is missing in DB")
            }
        }
    }
}

impl std::error::Error for SignatureFetcherError {}

impl From<DatabaseError> for SignatureFetcherError {
    fn from(e: DatabaseError) -> Self {
        Self::DbError(e)
    }
}

impl From<CommunicationError> for SignatureFetcherError {
    fn from(e: CommunicationError) -> Self {
        Self::Communication(e)
    }
}

impl From<revault_net::Error> for SignatureFetcherError {
    fn from(e: revault_net::Error) -> Self {
        Self::Communication(e.into())
    }
}

// Send a `get_sigs` message to the Coordinator to fetch other stakeholders' signatures for this
// transaction (https://github.com/revault/practical-revault/blob/master/messages.md#get_sigs).
// If the Coordinator hands us some new signatures, update the transaction we are passed.
// If we are a stakeholder and our signature is missing, we send it to the coordinator
fn sync_sigs<C: secp256k1::Verification>(
    transport: &mut KKTransport,
    stk_keys: &[BitcoinPubKey],
    our_stk_key: &Option<BitcoinPubKey>,
    tx: &mut RevaultTx,
    secp: &secp256k1::Secp256k1<C>,
) -> Result<(), SignatureFetcherError> {
    let signatures = get_presigs(transport, tx.txid())?;
    let mut contains_our_signature = false;
    let our_stk_key = our_stk_key.map(|k| k.key);

    for (key, sig) in signatures {
        let pubkey = BitcoinPubKey {
            compressed: true,
            key,
        };
        if !stk_keys.contains(&pubkey) {
            // FIXME: should we loudly fail instead ? If the coordinator is sending us bad
            // keys something dodgy's happening.
            log::warn!(
                "Coordinator answered to 'getsigs' for tx '{}' with a key '{}' that is \
                 not part of the stakeholders pubkeys '{:?}'",
                tx.txid(),
                key,
                stk_keys
            );
            continue;
        }
        contains_our_signature |= Some(key) == our_stk_key;

        if tx.signatures().contains_key(&pubkey.key) {
            continue;
        }

        log::debug!(
            "Adding revocation signature '{:?}' for pubkey '{}' for ({:?})",
            sig,
            pubkey,
            tx.txid()
        );
        if let Err(e) = tx.add_signature(pubkey.key, sig, secp) {
            // FIXME: should we loudly fail instead ? If the coordinator is sending us bad
            // signatures something shady's happening.
            log::error!("Error while adding signature for presigned tx: '{}'", e);
            continue;
        }
    }

    if let Some(our_stk_key) = our_stk_key {
        if !contains_our_signature {
            // Oh, the coordinator didn't have our signature. Here it is!
            if let Some(our_sig) = tx.signatures().remove(&our_stk_key) {
                log::info!(
                    "Coordinator didn't have our signature for transaction '{}', sending",
                    tx.txid()
                );
                let mut map = BTreeMap::new();
                map.insert(our_stk_key, our_sig);
                send_coord_sig_msg(transport, tx.txid(), map)?;
            }
        }
    }

    Ok(())
}

// If we are a stakeholder, share the signatures for our revocation transactions
// with all our watchtowers.
fn maybe_wt_share_signatures(
    revaultd: &RevaultD,
    db_path: &path::Path,
    db_vault: &DbVault,
) -> Result<(), SignatureFetcherError> {
    let watchtowers = match revaultd.watchtowers {
        Some(ref wt) => wt,
        None => return Ok(()),
    };

    // The revocation txs should always be there, apart from a very edgy race condition.
    let emer_tx = db_emer_transaction(db_path, db_vault.id)?
        .ok_or(SignatureFetcherError::MissingTransaction)?;
    if !emer_tx
        .psbt
        .unwrap_emer()
        .is_finalizable(&revaultd.secp_ctx)
    {
        return Ok(());
    }

    let (_, cancel_batch) = transaction_chain_manager(
        db_vault.deposit_outpoint,
        db_vault.amount,
        &revaultd.deposit_descriptor,
        &revaultd.unvault_descriptor,
        &revaultd.cpfp_descriptor,
        db_vault.derivation_index,
        &revaultd.secp_ctx,
    )
    .expect("We wouldn't have put a vault with an invalid chain in DB");
    let mut cancel_txs = BTreeMap::new();
    for (amount, cancel_tx) in cancel_batch.feerates_map() {
        let cancel_tx = db_cancel_transaction_by_txid(db_path, &cancel_tx.txid())
            .expect("Database must always be available")
            .ok_or(SignatureFetcherError::MissingTransaction)?;
        if !cancel_tx
            .psbt
            .unwrap_cancel()
            .is_finalizable(&revaultd.secp_ctx)
        {
            return Ok(());
        }
        cancel_txs.insert(amount, cancel_tx);
    }

    let unemer_tx = db_unvault_emer_transaction(db_path, db_vault.id)?
        .ok_or(SignatureFetcherError::MissingTransaction)?;
    if !unemer_tx
        .psbt
        .unwrap_unvault_emer()
        .is_finalizable(&revaultd.secp_ctx)
    {
        return Ok(());
    }

    log::debug!(
        "Sharing revocation signatures with watchtowers for vault at '{}'",
        &db_vault.deposit_outpoint
    );
    wts_share_rev_signatures(
        &revaultd.noise_secret,
        watchtowers,
        db_vault.deposit_outpoint,
        db_vault.derivation_index,
        &emer_tx,
        &cancel_txs,
        &unemer_tx,
    )?;

    Ok(())
}

// Sequentially poll the coordinator for all the `txs` signatures.
// TODO: consider polling in parallel.
// TODO: consider only polling for the rev signatures if we are "securing" and for
// unvault signatures if we are "activating" (ie make this poll indirectly user-triggered,
// not something we unconditionally do in the background). Wouldn't work for managers.
fn fetch_all_signatures(
    revaultd: &RevaultD,
    vault_txs: HashMap<DbVault, Vec<DbTransaction>>,
) -> Result<(), SignatureFetcherError> {
    let db_path = &revaultd.db_file();
    let mut transport = KKTransport::connect(
        revaultd.coordinator_host,
        &revaultd.noise_secret,
        &revaultd.coordinator_noisekey,
    )?;

    for (db_vault, mut db_txs) in vault_txs {
        let stk_keys = revaultd.stakeholders_xpubs_at(db_vault.derivation_index);
        let our_stk_key = revaultd.our_stk_xpub_at(db_vault.derivation_index);

        for db_tx in &mut db_txs {
            if matches!(
                db_tx.psbt,
                RevaultTx::Emergency(_) | RevaultTx::UnvaultEmergency(_)
            ) {
                assert!(revaultd.is_stakeholder())
            }
            log::debug!(
                "Syncing {} signatures for {}",
                &db_tx.psbt.type_str(),
                &db_vault.deposit_outpoint
            );
            let before_sync = time::Instant::now();
            sync_sigs(
                &mut transport,
                &stk_keys,
                &our_stk_key,
                &mut db_tx.psbt,
                &revaultd.secp_ctx,
            )?;
            log::debug!(
                "Syncing sigs for vault at '{}' took {} seconds",
                db_vault.deposit_outpoint,
                time::Instant::now().duration_since(before_sync).as_secs(),
            );
        }

        // NOTE: In theory, the deposit could have been reorged out and the presigned
        // transactions wiped from the database. Would be a quite edgy case though.
        if let Err(e) = db_update_presigned_txs(db_path, &db_vault, db_txs, &revaultd.secp_ctx) {
            log::error!("Error while updating presigned tx: '{}'", e);
            continue;
        }
        // Check if we can share the Emer signature with the watchtowers
        if let Err(e) = maybe_wt_share_signatures(revaultd, db_path, &db_vault) {
            log::error!(
                "Error sharing emergency signatures with watchtowers: '{}'",
                e
            );
            // FIXME: we should not discard those new signatures, but still retry
            // to send them to the watchtowers.
            continue;
        }
        db_update_vault_status(db_path, &db_vault)?;
    }

    Ok(())
}

// Poll the Coordinator for revocation transactions signatures indefinitely.
pub fn signature_fetcher_loop(
    rx: mpsc::Receiver<SigFetcherMessageOut>,
    revaultd: Arc<RwLock<RevaultD>>,
) -> Result<(), SignatureFetcherError> {
    let mut last_poll = time::Instant::now();
    let poll_interval = revaultd.read().unwrap().coordinator_poll_interval;

    log::info!("Signature fetcher thread started.");

    loop {
        // Process any message from master first
        match rx.try_recv() {
            Ok(SigFetcherMessageOut::Shutdown) => {
                log::info!("Signature fetcher thread received shutdown. Exiting.");
                return Ok(());
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(SignatureFetcherError::ChannelDisconnected);
            }
        }

        let elapsed = last_poll.elapsed();
        // If enough time has elapsed, poll the sigs
        if elapsed >= poll_interval {
            log::debug!("Starting to poll for new signatures.");
            let before_polling = time::Instant::now();

            // This will ignore emergency transactions if we are manager-only
            let vaults_txs = db_sig_missing(&revaultd.read().unwrap().db_file())?;
            fetch_all_signatures(&revaultd.read().unwrap(), vaults_txs).unwrap_or_else(|e| {
                log::warn!("Error while fetching signatures: '{}'", e);
            });

            last_poll = time::Instant::now();
            log::debug!(
                "Polling signatures took {} seconds.",
                last_poll.duration_since(before_polling).as_secs()
            );
        }

        // Avoid clogging the CPU by sleeping for a while
        thread::sleep(time::Duration::from_millis(500));
    }
}
