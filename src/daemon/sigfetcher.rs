///! Background thread that will poll the coordinator for signatures
use crate::{
    control::{get_presigs, CommunicationError},
    database::{
        actions::db_update_presigned_tx,
        interface::{db_transactions_sig_missing, db_vault},
        schema::{DbTransaction, RevaultTx, TransactionType},
        DatabaseError,
    },
    revaultd::RevaultD,
    threadmessages::SigFetcherMessageOut,
};
use revault_tx::{bitcoin::PublicKey as BitcoinPubKey, transactions::RevaultTransaction};

use std::{
    sync::mpsc,
    sync::{Arc, RwLock},
    thread, time,
};

#[derive(Debug)]
pub enum SignatureFetcherError {
    DbError(DatabaseError),
    Communication(CommunicationError),
    ChannelDisconnected,
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
// If the Coordinator hands us some new signatures, update the transaction in DB.
// If this made the transaction valid, maybe update the vault state.
// NOTE: the vault state update assumes that we will never have all unvault signatures before
// having all revocation transaction signatures (in which case the vault would get back from
// 'active' to 'secured'). This assumptions holds as we are never accepting the user to provide
// their own signature until we gathered all revocation signatures (therefore even if all our peers
// are sending their unvault transaction to the coordinator and we fetch them, we would never have
// a fully-valid Unvault transaction until all other signatures have been stored in db).
fn get_sigs(
    revaultd: &RevaultD,
    tx_db_id: u32,
    vault_id: u32,
    mut tx: impl RevaultTransaction,
    tx_type: TransactionType,
) -> Result<(), SignatureFetcherError> {
    let db_path = &revaultd.db_file();
    let secp_ctx = &revaultd.secp_ctx;
    let db_vault = db_vault(&db_path, vault_id)?.expect("Presigned transactions without vault?");
    let stk_keys = revaultd.stakeholders_xpubs_at(db_vault.derivation_index);

    let signatures = get_presigs(revaultd, tx.txid())?;
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
            tx_type
        );
        if let Err(e) = tx.add_signature(0, pubkey.key, sig, secp_ctx) {
            // FIXME: should we loudly fail instead ? If the coordinator is sending us bad
            // signatures something shady's happening.
            log::error!("Error while adding signature for presigned tx: '{}'", e);
            continue;
        }
        // This will atomically set the vault as 'Secured' if all revocations transactions
        // were signed, and as 'Active' if the Unvault transaction was.
        // NOTE: In theory, the deposit could have been reorged out and the presigned
        // transactions wiped from the database. Would be a quite edgy case though.
        if let Err(e) = db_update_presigned_tx(
            db_path,
            vault_id,
            tx_db_id,
            tx.psbt().inputs[0].partial_sigs.clone(),
            secp_ctx,
        ) {
            log::error!("Error while updating presigned tx: '{}'", e);
        }
    }

    Ok(())
}

// Sequentially poll the coordinator for all the `txs` signatures.
// TODO: poll in parallel, it's worthwile as we are going to proxy the communications
// through Tor.
fn fetch_all_signatures(
    revaultd: &RevaultD,
    mut txs: Vec<DbTransaction>,
) -> Result<(), SignatureFetcherError> {
    while let Some(tx) = txs.pop() {
        match tx.psbt {
            RevaultTx::Unvault(unvault_tx) => {
                log::debug!("Fetching Unvault signature");
                get_sigs(revaultd, tx.id, tx.vault_id, unvault_tx, tx.tx_type)?;
            }
            RevaultTx::Cancel(cancel_tx) => {
                log::debug!("Fetching Cancel signature");
                get_sigs(revaultd, tx.id, tx.vault_id, cancel_tx, tx.tx_type)?;
            }
            RevaultTx::Emergency(emer_tx) => {
                log::debug!("Fetching Emergency signature");
                debug_assert!(revaultd.is_stakeholder());
                get_sigs(revaultd, tx.id, tx.vault_id, emer_tx, tx.tx_type)?;
            }
            RevaultTx::UnvaultEmergency(unemer_tx) => {
                log::debug!("Fetching Unvault Emergency signature");
                debug_assert!(revaultd.is_stakeholder());
                get_sigs(revaultd, tx.id, tx.vault_id, unemer_tx, tx.tx_type)?;
            }
        };
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
            let txs = db_transactions_sig_missing(&revaultd.read().unwrap().db_file())?;
            log::trace!("Fetching transactions for {:#?}", txs);
            fetch_all_signatures(&revaultd.read().unwrap(), txs).unwrap_or_else(|e| {
                log::warn!("Error while fetching signatures: '{}'", e);
            });

            last_poll = time::Instant::now();
        }

        // Avoid clogging the CPU by sleeping for a while
        thread::sleep(time::Duration::from_millis(500));
    }
}
