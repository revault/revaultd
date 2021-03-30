///! Background thread that will poll the coordinator for signatures
use crate::{
    control::send_sig_msg,
    database::{
        actions::db_update_presigned_tx,
        interface::{db_transactions_current_vaults, db_transactions_sig_missing},
        schema::{DbTransaction, RevaultTx, TransactionType},
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

// TODO (module organization): with the upcoming move of JSONRPC commands to the jsonrpc module we
// should move the send / get sig msg routines to control.

fn send_sig(transport: &mut KKTransport, tx: &impl RevaultTransaction) {
    let txid = tx.txid();

    for input in tx.inner_tx().inputs.iter() {
        if let Err(e) = send_sig_msg(transport, txid, input.partial_sigs.clone()) {
            log::error!("Error sharing signatures for '{}': '{}'", txid, e);
        }
    }
}

fn share_all_signatures(revaultd: &RevaultD) -> Result<(), SignatureFetcherError> {
    let db_path = revaultd.db_file();
    let mut transport = KKTransport::connect(
        revaultd.coordinator_host,
        &revaultd.noise_secret,
        &revaultd.coordinator_noisekey,
    )?;

    for db_tx in db_transactions_current_vaults(&db_path)? {
        match db_tx.psbt {
            RevaultTx::Unvault(tx) => send_sig(&mut transport, &tx),
            RevaultTx::Cancel(tx) => send_sig(&mut transport, &tx),
            RevaultTx::Emergency(tx) => send_sig(&mut transport, &tx),
            RevaultTx::UnvaultEmergency(tx) => send_sig(&mut transport, &tx),
        };
    }

    Ok(())
}

/// The signature hash of a presigned transaction (ie Unvault, Cancel, Emergency, or
/// UnvaultEmergency)
pub fn presigned_tx_sighash(
    tx: &impl RevaultTransaction,
    hashtype: SigHashType,
) -> secp256k1::Message {
    // Presigned transactions only have one input when handled by revaultd.
    // If we were passed a >1 input transaction, something went really bad and it's better to
    // crash.
    assert!(tx.inner_tx().global.unsigned_tx.input.len() == 1);
    assert!(hashtype == SigHashType::All || hashtype == SigHashType::AllPlusAnyoneCanPay);

    tx.signature_hash_internal_input(0, hashtype)
        .map(|sighash| {
            secp256k1::Message::from_slice(&sighash).expect("sighash is a 32 bytes hash")
        })
        .expect("Asserted above, input exists")
}

// Check a raw (without SIGHASH type) presigned tx (ie Unvault, Cancel, Emergency, or
// UnvaultEmergency) signature
pub fn check_signature(
    secp: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    tx: &impl RevaultTransaction,
    pubkey: BitcoinPubKey,
    sig: &secp256k1::Signature,
    hashtype: SigHashType,
) -> Result<(), secp256k1::Error> {
    let sighash = presigned_tx_sighash(tx, hashtype);

    secp.verify(&sighash, sig, &pubkey.key)?;

    Ok(())
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
    let id = tx.txid();
    let getsigs_msg = GetSigs { id };
    let mut transport = KKTransport::connect(
        revaultd.coordinator_host,
        &revaultd.noise_secret,
        &revaultd.coordinator_noisekey,
    )?;

    log::debug!(
        "Sending to sync server: '{}'",
        serde_json::to_string(&getsigs_msg)?,
    );
    transport.write(&serde_json::to_vec(&getsigs_msg)?)?;
    let recvd_raw = transport.read()?;
    log::debug!(
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
            "Adding revocation signature '{:?}' for pubkey '{}' for tx '{}' ({:?})",
            sig,
            pubkey,
            id,
            tx_type
        );
        let hashtype = match tx_type {
            TransactionType::Unvault => SigHashType::All,
            TransactionType::Cancel
            | TransactionType::Emergency
            | TransactionType::UnvaultEmergency => SigHashType::AllPlusAnyoneCanPay,
        };
        if let Err(e) = check_signature(secp_ctx, &tx, pubkey, &sig, hashtype) {
            // FIXME: should we loudly fail instead ? If the coordinator is sending us bad
            // signatures something shady's happening.
            log::warn!(
                "Invalid revocation signature '{:?}' sent by coordinator: '{}'",
                sig,
                e
            );
            continue;
        }
        tx.add_signature(0, pubkey, (sig, hashtype))
            .expect("Can not fail, as we are never passed a Spend transaction.");
        // This will atomically set the vault as 'Secured' if all revocations transactions
        // were signed, and as 'Active' if the Unvault transaction was.
        // NOTE: In theory, the deposit could have been reorged out and the presigned
        // transactions wiped from the database. Would be a quite edgy case though.
        if let Err(e) = db_update_presigned_tx(
            db_path,
            vault_id,
            tx_db_id,
            tx.inner_tx().inputs[0].partial_sigs.clone(),
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

    // Make sure the coordinator has got all our signatures for current vaults.
    // FIXME: this is bulk, be smarter (may just be checking it has got it after sharing it in the
    // first place, or mark it as shared in DB).
    if let Err(e) = share_all_signatures(&revaultd.read().unwrap()) {
        log::error!("Error sharing all our signatures: '{}'", e);
    }

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
