///! Background thread that will poll the coordinator for signatures
use crate::daemon::{
    control::{get_presigs, wts_share_emer_signatures, CommunicationError},
    database::{
        actions::{db_mark_emer_shared, db_update_presigned_txs, db_update_vault_status},
        bitcointx::RevaultTx,
        interface::{db_emer_transaction, db_sig_missing},
        schema::{DbTransaction, DbVault},
        DatabaseError,
    },
    revaultd::RevaultD,
    threadmessages::SigFetcherMessageOut,
};
use revault_net::transport::KKTransport;
use revault_tx::{
    bitcoin::{secp256k1, PublicKey as BitcoinPubKey},
    transactions::RevaultTransaction,
};

use std::{
    collections::HashMap,
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
fn get_sigs<C: secp256k1::Verification>(
    transport: &mut KKTransport,
    stk_keys: &[BitcoinPubKey],
    tx: &mut impl RevaultTransaction,
    secp: &secp256k1::Secp256k1<C>,
) -> Result<(), SignatureFetcherError> {
    let signatures = get_presigs(transport, tx.txid())?;

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

        // FIXME: don't blindly assume 0 here..
        if tx.psbt().inputs[0].partial_sigs.contains_key(&pubkey) {
            continue;
        }

        log::debug!(
            "Adding revocation signature '{:?}' for pubkey '{}' for ({:?})",
            sig,
            pubkey,
            tx.txid()
        );
        if let Err(e) = tx.add_signature(0, pubkey.key, sig, secp) {
            // FIXME: should we loudly fail instead ? If the coordinator is sending us bad
            // signatures something shady's happening.
            log::error!("Error while adding signature for presigned tx: '{}'", e);
            continue;
        }
    }

    Ok(())
}

// If we are a stakeholder, share the signatures for the Emergency transaction
// with all our watchtowers.
fn maybe_wt_share_signatures(
    revaultd: &RevaultD,
    db_path: &path::Path,
    db_vault: &DbVault,
) -> Result<(), SignatureFetcherError> {
    if db_vault.emer_shared {
        return Ok(());
    }
    let watchtowers = match revaultd.watchtowers {
        Some(ref wt) => wt,
        None => return Ok(()),
    };

    // It should always be here, apart from a very edgy race condition.
    let emer_tx = db_emer_transaction(db_path, db_vault.id)?
        .ok_or(SignatureFetcherError::MissingTransaction)?;
    if emer_tx
        .psbt
        .unwrap_emer()
        .is_finalizable(&revaultd.secp_ctx)
    {
        log::debug!(
            "Sharing emergency signatures with watchtowers for vault at '{}'",
            &db_vault.deposit_outpoint
        );
        wts_share_emer_signatures(
            &revaultd.noise_secret,
            &watchtowers,
            db_vault.deposit_outpoint,
            db_vault.derivation_index,
            &emer_tx,
        )?;
        // FIXME: what if only part of the watchtowers got the sig? The WT should
        // be less strict on that..
        db_mark_emer_shared(db_path, db_vault)?;
    }

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

        for db_tx in &mut db_txs {
            match db_tx.psbt {
                RevaultTx::Unvault(ref mut unvault_tx) => {
                    log::debug!("Fetching Unvault signature");
                    get_sigs(&mut transport, &stk_keys, unvault_tx, &revaultd.secp_ctx)?;
                }
                RevaultTx::Cancel(ref mut cancel_tx) => {
                    log::debug!("Fetching Cancel signature");
                    get_sigs(&mut transport, &stk_keys, cancel_tx, &revaultd.secp_ctx)?;
                }
                RevaultTx::Emergency(ref mut emer_tx) => {
                    log::debug!("Fetching Emergency signature");
                    debug_assert!(revaultd.is_stakeholder());
                    get_sigs(&mut transport, &stk_keys, emer_tx, &revaultd.secp_ctx)?;
                }
                RevaultTx::UnvaultEmergency(ref mut unemer_tx) => {
                    log::debug!("Fetching Unvault Emergency signature");
                    debug_assert!(revaultd.is_stakeholder());
                    get_sigs(&mut transport, &stk_keys, unemer_tx, &revaultd.secp_ctx)?;
                }
            };
        }

        // NOTE: In theory, the deposit could have been reorged out and the presigned
        // transactions wiped from the database. Would be a quite edgy case though.
        if let Err(e) = db_update_presigned_txs(db_path, &db_vault, db_txs, &revaultd.secp_ctx) {
            log::error!("Error while updating presigned tx: '{}'", e);
            continue;
        }
        // Check if we can share the Emer signature with the watchtowers
        if let Err(e) = maybe_wt_share_signatures(revaultd, &db_path, &db_vault) {
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
            // This will ignore emergency transactions if we are manager-only
            let vaults_txs = db_sig_missing(&revaultd.read().unwrap().db_file())?;
            fetch_all_signatures(&revaultd.read().unwrap(), vaults_txs).unwrap_or_else(|e| {
                log::warn!("Error while fetching signatures: '{}'", e);
            });

            last_poll = time::Instant::now();
        }

        // Avoid clogging the CPU by sleeping for a while
        thread::sleep(time::Duration::from_millis(500));
    }
}
