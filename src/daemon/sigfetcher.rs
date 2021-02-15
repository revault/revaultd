///! Background thread that will poll the coordinator for signatures
use crate::{
    database::{
        actions::db_update_presigned_tx,
        interface::db_transactions_sig_missing,
        schema::{DbTransaction, RevaultTx},
        DatabaseError,
    },
    revaultd::RevaultD,
    threadmessages::SigFetcherMessageOut,
};
use revault_net::{
    message::server::{GetSigs, Sigs},
    transport::KKTransport,
};
use revault_tx::{
    bitcoin::{secp256k1, PublicKey as BitcoinPubKey, SigHashType},
    transactions::RevaultTransaction,
};

use std::{
    sync::mpsc,
    sync::{Arc, RwLock},
    thread, time,
};

#[derive(Debug)]
pub enum SignatureFetcherError {
    DbError(DatabaseError),
    NetError(revault_net::Error),
    // FIXME: we should probably upstream this to revault_net ?
    SerializationError(serde_json::Error),
    ChannelDisconnected,
}

impl std::fmt::Display for SignatureFetcherError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::DbError(ref s) => write!(f, "Database error in sig fetcher thread: '{}'", s),
            Self::NetError(ref s) => {
                write!(f, "Communication error in sig fetcher thread: '{}'", s)
            }
            Self::SerializationError(ref s) => {
                write!(f, "Encoding error in sig fetcher thread: '{}'", s)
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

impl From<revault_net::Error> for SignatureFetcherError {
    fn from(e: revault_net::Error) -> Self {
        Self::NetError(e)
    }
}

impl From<serde_json::Error> for SignatureFetcherError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerializationError(e)
    }
}

/// The signature hash of a revocation transaction (ie Cancel, Emergency, or UnvaultEmergency)
pub fn revocation_tx_sighash(tx: &impl RevaultTransaction) -> secp256k1::Message {
    // Revocation transactions only have one input when handled by revaultd.
    // If we were passed a >1 input transaction, something went really bad and it's better to
    // crash.
    assert!(tx.inner_tx().global.unsigned_tx.input.len() == 1);

    tx.signature_hash_internal_input(0, SigHashType::AllPlusAnyoneCanPay)
        .map(|sighash| {
            secp256k1::Message::from_slice(&sighash).expect("sighash is a 32 bytes hash")
        })
        .expect("Asserted above, input exists")
}

// Check a raw (without SIGHASH type) revocation tx (ie Cancel, Emergency, or
// UnvaultEmergency) signature
pub fn check_revocation_signature(
    secp: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    tx: &impl RevaultTransaction,
    pubkey: BitcoinPubKey,
    sig: &secp256k1::Signature,
) -> Result<(), secp256k1::Error> {
    let sighash = revocation_tx_sighash(tx);

    secp.verify(&sighash, sig, &pubkey.key)?;

    Ok(())
}

// Send a `get_sigs` message to the Coordinator to fetch other stakeholders' signatures for this
// transaction (https://github.com/re-vault/practical-revault/blob/master/messages.md#get_sigs).
// If the Coordinator hands us some new signatures, update the presigned transaction in DB.
// If this made the transaction valid, check if there are remaining unsigned presigned transactions
// for this vault and if not update the vault status.
fn get_sigs(
    revaultd: &RevaultD,
    tx_db_id: u32,
    vault_id: u32,
    mut tx: impl RevaultTransaction,
) -> Result<(), SignatureFetcherError> {
    let db_path = &revaultd.db_file();
    let secp_ctx = &revaultd.secp_ctx;
    let id = tx.inner_tx().global.unsigned_tx.txid();
    let getsigs_msg = GetSigs { id };
    let mut transport = KKTransport::connect(
        revaultd.coordinator_host,
        &revaultd.noise_secret,
        &revaultd.coordinator_noisekey,
    )?;

    log::trace!(
        "Sending to sync server: '{}'",
        serde_json::to_string(&getsigs_msg)?,
    );
    transport.write(&serde_json::to_vec(&getsigs_msg)?)?;
    let recvd_raw = transport.read()?;
    log::trace!(
        "Received from sync server: '{}'",
        &String::from_utf8_lossy(&recvd_raw)
    );
    let Sigs { signatures } = serde_json::from_slice(&recvd_raw)?;

    for (key, sig) in signatures {
        let pubkey = BitcoinPubKey {
            compressed: true,
            key,
        };
        if tx.inner_tx().inputs[0].partial_sigs.contains_key(&pubkey) {
            continue;
        }

        log::debug!(
            "Adding signature '{:?}' for pubkey '{}' for tx '{}'",
            sig,
            pubkey,
            id
        );
        if check_revocation_signature(secp_ctx, &tx, pubkey, &sig).is_err() {
            // FIXME: should we loudly fail instead ? If the coordinator is sending us bad
            // signatures something shady's happening.
            log::warn!("Invalid signature sent by coordinator: '{:?}'", sig);
            continue;
        }
        tx.add_signature(0, pubkey, (sig, SigHashType::AllPlusAnyoneCanPay))
            .expect("Can not fail, as we are never passed a Spend transaction.");
        // Note: this will atomically set the vault as 'Secured' if all revocations transactions
        // were signed
        // TODO: mark it as 'Active' if Unvault
        db_update_presigned_tx(
            db_path,
            vault_id,
            tx_db_id,
            tx.inner_tx().inputs[0].partial_sigs.clone(),
            secp_ctx,
        )?;
    }

    Ok(())
}

// Sequentially poll the coordinator for all the `txs` signatures.
// TODO: poll in parallel, it's worthwile as we are going to proxy the communications
// through tor.
fn fetch_all_signatures(
    revaultd: &RevaultD,
    mut txs: Vec<DbTransaction>,
) -> Result<(), SignatureFetcherError> {
    while let Some(tx) = txs.pop() {
        match tx.psbt {
            RevaultTx::Unvault(unvault_tx) => {
                log::debug!("Fetching Unvault signature");
                get_sigs(revaultd, tx.id, tx.vault_id, unvault_tx)?;
            }
            RevaultTx::Cancel(cancel_tx) => {
                log::debug!("Fetching Cancel signature");
                get_sigs(revaultd, tx.id, tx.vault_id, cancel_tx)?;
            }
            RevaultTx::Emergency(emer_tx) => {
                log::debug!("Fetching Emergency signature");
                debug_assert!(revaultd.is_stakeholder());
                get_sigs(revaultd, tx.id, tx.vault_id, emer_tx)?;
            }
            RevaultTx::UnvaultEmergency(unemer_tx) => {
                log::debug!("Fetching Unvault Emergency signature");
                debug_assert!(revaultd.is_stakeholder());
                get_sigs(revaultd, tx.id, tx.vault_id, unemer_tx)?;
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

        // This will ignore emergency transactions if we are manager-only
        let txs = db_transactions_sig_missing(&revaultd.read().unwrap().db_file())?;
        log::trace!("Fetching transactions for {:#?}", txs);
        fetch_all_signatures(&revaultd.read().unwrap(), txs).unwrap_or_else(|e| {
            log::warn!("Error while fetching signatures: '{}'", e);
        });

        let elapsed = last_poll.elapsed();
        if elapsed < poll_interval {
            thread::sleep(poll_interval - elapsed);
        }
        last_poll = time::Instant::now();
    }
}
