//! By itself, the daemon is not doing much: it basically just keeps its database updated with the
//! chain events in the bitcoind thread.
//! Any process is at first initiated by a manual interaction. This interaction is possible using the
//! JSONRPC api, which events are handled in the RPC thread.
//!
//! The main thread handles and coordinates all processes, which (for now) all originates from a
//! command sent to the RPC server. This control handling is what happens here.

use crate::{
    bitcoind::BitcoindError,
    database::{
        actions::{
            db_delete_spend, db_insert_spend, db_mark_activating_vault,
            db_mark_broadcastable_spend, db_mark_securing_vault, db_update_presigned_tx,
            db_update_spend,
        },
        interface::{
            db_cancel_transaction, db_emer_transaction, db_list_spends, db_spend_transaction,
            db_tip, db_unvault_emer_transaction, db_unvault_transaction, db_vault_by_deposit,
            db_vault_by_unvault_txid, db_vaults, db_vaults_from_spend, db_vaults_min_status,
        },
        schema::DbVault,
        DatabaseError,
    },
    revaultd::{BlockchainTip, RevaultD, VaultStatus},
    sigfetcher::presigned_tx_sighash,
    threadmessages::*,
};
use common::assume_ok;

use revault_net::{
    message::{
        cosigner::{SignRequest, SignResponse},
        server::{SetSpendTx, Sig},
    },
    transport::KKTransport,
};
use revault_tx::{
    bitcoin::{
        secp256k1::{self, Signature},
        util::bip32::ChildNumber,
        Network, OutPoint, PublicKey as BitcoinPubKey, SigHashType, TxOut, Txid,
    },
    miniscript::descriptor::DescriptorPublicKey,
    transactions::{
        spend_tx_from_deposits, transaction_chain, CancelTransaction, EmergencyTransaction,
        RevaultTransaction, SpendTransaction, UnvaultEmergencyTransaction, UnvaultTransaction,
    },
    txins::DepositTxIn,
    txouts::{DepositTxOut, ExternalTxOut, SpendTxOut},
};

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    path::PathBuf,
    process,
    sync::{
        mpsc::{self, Receiver, RecvError, SendError, Sender},
        Arc, RwLock,
    },
    thread::JoinHandle,
};

/// Any error that could arise during the process of executing the user's will.
/// Usually fatal.
#[derive(Debug)]
pub enum ControlError {
    ChannelCommunication(String),
    Database(String),
    Bitcoind(String),
    TransactionManagement(String),
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::ChannelCommunication(s) => write!(f, "Channel communication error: '{}'", s),
            Self::Database(s) => write!(f, "Database error: '{}'", s),
            Self::Bitcoind(s) => write!(f, "Bitcoind error: '{}'", s),
            Self::TransactionManagement(s) => write!(f, "Transaction management error: '{}'", s),
        }
    }
}

impl std::error::Error for ControlError {}

impl<T> From<SendError<T>> for ControlError {
    fn from(e: SendError<T>) -> Self {
        Self::ChannelCommunication(format!("Sending to channel: '{}'", e))
    }
}

impl From<RecvError> for ControlError {
    fn from(e: RecvError) -> Self {
        Self::ChannelCommunication(format!("Receiving from channel: '{}'", e))
    }
}

impl From<DatabaseError> for ControlError {
    fn from(e: DatabaseError) -> Self {
        Self::Database(format!("Database error: {}", e))
    }
}

impl From<BitcoindError> for ControlError {
    fn from(e: BitcoindError) -> Self {
        Self::Bitcoind(format!("Bitcoind error: {}", e))
    }
}

impl From<revault_tx::Error> for ControlError {
    fn from(e: revault_tx::Error) -> Self {
        Self::TransactionManagement(format!("Revault transaction error: {}", e))
    }
}

impl From<revault_tx::error::TransactionCreationError> for ControlError {
    fn from(e: revault_tx::error::TransactionCreationError) -> Self {
        Self::TransactionManagement(format!("Revault transaction creation error: {}", e))
    }
}

// Ask bitcoind for a wallet transaction
fn bitcoind_wallet_tx(
    bitcoind_tx: &Sender<BitcoindMessageOut>,
    txid: Txid,
) -> Result<Option<WalletTransaction>, ControlError> {
    log::trace!("Sending WalletTx to bitcoind thread for {}", txid);

    let (bitrep_tx, bitrep_rx) = mpsc::sync_channel(0);
    bitcoind_tx.send(BitcoindMessageOut::WalletTransaction(txid, bitrep_tx))?;
    bitrep_rx.recv().map_err(|e| e.into())
}

// Tell bitcoind to broadcast the Unvault transactions of all these vaults.
// The vaults must be active for the Unvault to be finalizable.
fn bitcoind_broadcast_unvaults(
    bitcoind_tx: &Sender<BitcoindMessageOut>,
    db_path: &PathBuf,
    secp: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    db_vaults: &HashMap<Txid, DbVault>,
) -> Result<(), ControlError> {
    log::debug!(
        "Broadcasting Unvault transactions with ids '{:?}'",
        db_vaults.keys()
    );

    // For each vault, get the Unvault transaction, finalize it, and tell bitcoind to broadcast it
    let (bitrep_tx, bitrep_rx) = mpsc::sync_channel(0);
    for db_vault in db_vaults.values() {
        let (_, mut unvault_tx) = db_unvault_transaction(db_path, db_vault.id)?;
        unvault_tx.finalize(secp)?;
        let transaction = unvault_tx.into_psbt().extract_tx();

        bitcoind_tx.send(BitcoindMessageOut::BroadcastTransaction(
            transaction,
            bitrep_tx.clone(),
        ))?;
        bitrep_rx.recv()??;
    }

    Ok(())
}

// Tell bitcoind to broadcast the Cancel transactions of this vault.
fn bitcoind_broadcast_cancel(
    bitcoind_tx: &Sender<BitcoindMessageOut>,
    db_path: &PathBuf,
    secp: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    vault: DbVault,
) -> Result<(), ControlError> {
    let (bitrep_tx, bitrep_rx) = mpsc::sync_channel(0);
    // FIXME: this may not hold true in all cases, see https://github.com/revault/revaultd/issues/145
    let (_, mut cancel_tx) =
        db_cancel_transaction(&db_path, vault.id)?.expect("Must be in DB post 'Secured' status");

    cancel_tx.finalize(secp)?;
    let transaction = cancel_tx.into_psbt().extract_tx();
    log::debug!(
        "Broadcasting Cancel transactions with id '{:?}'",
        transaction.txid()
    );

    bitcoind_tx.send(BitcoindMessageOut::BroadcastTransaction(
        transaction,
        bitrep_tx.clone(),
    ))?;

    bitrep_rx.recv()??;

    Ok(())
}

// List the vaults from DB, and filter out the info the RPC wants
// FIXME: we could make this more efficient with smarter SQL queries
fn listvaults_from_db(
    revaultd: &RevaultD,
    statuses: Option<Vec<VaultStatus>>,
    outpoints: Option<Vec<OutPoint>>,
) -> Result<Vec<ListVaultsEntry>, DatabaseError> {
    db_vaults(&revaultd.db_file()).map(|db_vaults| {
        db_vaults
            .into_iter()
            .filter_map(|db_vault| {
                if let Some(ref statuses) = statuses {
                    if !statuses.contains(&db_vault.status) {
                        return None;
                    }
                }

                if let Some(ref outpoints) = &outpoints {
                    if !outpoints.contains(&db_vault.deposit_outpoint) {
                        return None;
                    }
                }

                let address = revaultd.vault_address(db_vault.derivation_index);
                Some(ListVaultsEntry {
                    amount: db_vault.amount,
                    blockheight: db_vault.blockheight,
                    status: db_vault.status,
                    deposit_outpoint: db_vault.deposit_outpoint,
                    derivation_index: db_vault.derivation_index,
                    received_at: db_vault.received_at,
                    updated_at: db_vault.updated_at,
                    address,
                })
            })
            .collect()
    })
}

// List all the presigned transactions from these confirmed vaults.
fn presigned_txs_list_from_outpoints(
    revaultd: &RevaultD,
    outpoints: Option<Vec<OutPoint>>,
) -> Result<Result<Vec<VaultPresignedTransactions>, RpcControlError>, ControlError> {
    let db_path = &revaultd.db_file();

    // If they didn't provide us with a list of outpoints, catch'em all!
    let db_vaults = if let Some(outpoints) = outpoints {
        // FIXME: we can probably make this more efficient with some SQL magic
        let mut vaults = Vec::with_capacity(outpoints.len());
        for outpoint in outpoints.iter() {
            if let Some(vault) = db_vault_by_deposit(db_path, &outpoint)? {
                // If it's unconfirmed, the presigned transactions are not in db!
                match vault.status {
                    VaultStatus::Unconfirmed => {
                        return Ok(Err(RpcControlError::InvalidStatus((
                            vault.status,
                            VaultStatus::Funded,
                        ))))
                    }
                    _ => vaults.push(vault),
                }
            } else {
                return Ok(Err(RpcControlError::UnknownOutpoint(*outpoint)));
            }
        }
        vaults
    } else {
        db_vaults_min_status(db_path, VaultStatus::Funded)?
    };

    // For each presigned transaction, append it as well as its extracted version if it's final.
    let mut tx_list = Vec::with_capacity(db_vaults.len());
    for db_vault in db_vaults {
        let outpoint = db_vault.deposit_outpoint;

        let (_, unvault_psbt) = db_unvault_transaction(db_path, db_vault.id)?;
        let mut finalized_unvault = unvault_psbt.clone();
        let unvault = VaultPresignedTransaction {
            transaction: if finalized_unvault.finalize(&revaultd.secp_ctx).is_ok() {
                Some(finalized_unvault.into_psbt().extract_tx())
            } else {
                None
            },
            psbt: unvault_psbt,
        };

        // FIXME: this may not hold true in all cases, see https://github.com/revault/revaultd/issues/145
        let (_, cancel_psbt) =
            db_cancel_transaction(db_path, db_vault.id)?.expect("Must be here post 'Funded' state");
        let mut finalized_cancel = cancel_psbt.clone();
        let cancel = VaultPresignedTransaction {
            transaction: if finalized_cancel.finalize(&revaultd.secp_ctx).is_ok() {
                Some(finalized_cancel.into_psbt().extract_tx())
            } else {
                None
            },
            psbt: cancel_psbt,
        };

        let mut emergency = None;
        let mut unvault_emergency = None;
        if revaultd.is_stakeholder() {
            let (_, emer_psbt) = db_emer_transaction(db_path, db_vault.id)?;
            let mut finalized_emer = emer_psbt.clone();
            emergency = Some(VaultPresignedTransaction {
                transaction: if finalized_emer.finalize(&revaultd.secp_ctx).is_ok() {
                    Some(finalized_emer.into_psbt().extract_tx())
                } else {
                    None
                },
                psbt: emer_psbt,
            });

            let (_, unemer_psbt) = db_unvault_emer_transaction(db_path, db_vault.id)?;
            let mut finalized_unemer = unemer_psbt.clone();
            unvault_emergency = Some(VaultPresignedTransaction {
                transaction: if finalized_unemer.finalize(&revaultd.secp_ctx).is_ok() {
                    Some(finalized_unemer.into_psbt().extract_tx())
                } else {
                    None
                },
                psbt: unemer_psbt,
            });
        }

        tx_list.push(VaultPresignedTransactions {
            outpoint,
            unvault,
            cancel,
            emergency,
            unvault_emergency,
        });
    }

    Ok(Ok(tx_list))
}

// List all the onchain transactions from these vaults.
fn onchain_txs_list_from_outpoints(
    revaultd: &RevaultD,
    bitcoind_tx: &Sender<BitcoindMessageOut>,
    outpoints: Option<Vec<OutPoint>>,
) -> Result<Result<Vec<VaultOnchainTransactions>, RpcControlError>, ControlError> {
    let db_path = &revaultd.db_file();

    // If they didn't provide us with a list of outpoints, catch'em all!
    let db_vaults = if let Some(outpoints) = outpoints {
        // FIXME: we can probably make this more efficient with some SQL magic
        let mut vaults = Vec::with_capacity(outpoints.len());
        for outpoint in outpoints.iter() {
            if let Some(vault) = db_vault_by_deposit(db_path, &outpoint)? {
                // Note that we accept any status
                vaults.push(vault);
            } else {
                return Ok(Err(RpcControlError::UnknownOutpoint(*outpoint)));
            }
        }
        vaults
    } else {
        db_vaults(db_path)?
    };

    let mut tx_list = Vec::with_capacity(db_vaults.len());
    for db_vault in db_vaults {
        let outpoint = db_vault.deposit_outpoint;

        // If the vault exist, there must always be a deposit transaction available.
        let deposit = bitcoind_wallet_tx(bitcoind_tx, db_vault.deposit_outpoint.txid)?
            .expect("Vault exists but not deposit tx?");

        // For the other transactions, it depends on the status of the vault. For the sake of
        // simplicity bitcoind will tell us (but we could have some optimisation eventually here,
        // eg returning None early on Funded vaults).
        let (unvault, cancel, emergency, unvault_emergency, spend) = match db_vault.status {
            // We allow the unconfirmed status, for which we don't have any presigned tx in db!
            VaultStatus::Unconfirmed => (None, None, None, None, None),
            _ => {
                let (_, unvault) = db_unvault_transaction(db_path, db_vault.id)?;
                let unvault =
                    bitcoind_wallet_tx(bitcoind_tx, unvault.into_psbt().extract_tx().txid())?;
                // FIXME: this may not hold true in all cases, see https://github.com/revault/revaultd/issues/145
                let (_, cancel) = db_cancel_transaction(db_path, db_vault.id)?
                    .expect("Must be here if not 'unconfirmed'");
                let cancel =
                    bitcoind_wallet_tx(bitcoind_tx, cancel.into_psbt().extract_tx().txid())?;

                // Emergencies are only for stakeholders!
                let mut emergency = None;
                let mut unvault_emergency = None;
                if revaultd.is_stakeholder() {
                    let emer = db_emer_transaction(db_path, db_vault.id)?.1;
                    emergency =
                        bitcoind_wallet_tx(bitcoind_tx, emer.into_psbt().extract_tx().txid())?;

                    let unemer = db_unvault_emer_transaction(db_path, db_vault.id)?.1;
                    unvault_emergency =
                        bitcoind_wallet_tx(bitcoind_tx, unemer.into_psbt().extract_tx().txid())?;
                }
                let spend = None; // TODO!

                (unvault, cancel, emergency, unvault_emergency, spend)
            }
        };

        tx_list.push(VaultOnchainTransactions {
            outpoint,
            deposit,
            unvault,
            cancel,
            emergency,
            unvault_emergency,
            spend,
        });
    }

    Ok(Ok(tx_list))
}

/// An error thrown when the verification of a signature fails
#[derive(Debug)]
enum SigError {
    InvalidLength,
    InvalidSighash,
    VerifError(secp256k1::Error),
    MissingSignature(BitcoinPubKey),
}

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "Invalid length of signature"),
            Self::InvalidSighash => write!(f, "Invalid SIGHASH type"),
            Self::VerifError(e) => write!(f, "Signature verification error: '{}'", e),
            Self::MissingSignature(pk) => write!(f, "Missing signature for '{}'", pk),
        }
    }
}

impl std::error::Error for SigError {}

impl From<secp256k1::Error> for SigError {
    fn from(e: secp256k1::Error) -> Self {
        Self::VerifError(e)
    }
}

// Check all complete signatures for revocation transactions (ie Cancel, Emergency,
// or UnvaultEmergency)
fn check_revocation_signatures(
    secp: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    tx: &impl RevaultTransaction,
    sigs: &BTreeMap<BitcoinPubKey, Vec<u8>>,
) -> Result<(), SigError> {
    let sighash_type = SigHashType::AllPlusAnyoneCanPay;
    let sighash = presigned_tx_sighash(tx, sighash_type);

    for (pubkey, sig) in sigs {
        let (sighash_type, sig) = sig.split_last().unwrap();
        if *sighash_type != SigHashType::AllPlusAnyoneCanPay as u8 {
            return Err(SigError::InvalidSighash);
        }
        secp.verify(&sighash, &Signature::from_der(&sig)?, &pubkey.key)?;
    }

    Ok(())
}

fn check_unvault_signatures(
    secp: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    tx: &UnvaultTransaction,
) -> Result<(), SigError> {
    let sighash_type = SigHashType::All;
    let sighash = presigned_tx_sighash(tx, sighash_type);
    let sigs = &tx
        .inner_tx()
        .inputs
        .get(0)
        .expect("Unvault always has 1 input")
        .partial_sigs;

    for (pubkey, sig) in sigs.iter() {
        let (sighash_type, sig) = sig.split_last().unwrap();
        if *sighash_type != SigHashType::All as u8 {
            return Err(SigError::InvalidSighash);
        }
        secp.verify(&sighash, &Signature::from_der(&sig)?, &pubkey.key)?;
    }

    Ok(())
}

// Check that all the managers provided a valid signature for all the Spend transaction inputs.
// Will panic if db_vaults does not contain an entry for each input or if the Spend transaction is
// already finalized.
fn check_spend_signatures(
    secp: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    psbt: &SpendTransaction,
    managers_pubkeys: Vec<DescriptorPublicKey>,
    db_vaults: &HashMap<Txid, DbVault>,
) -> Result<(), SigError> {
    let sighash_type = SigHashType::All;
    let unsigned_tx = &psbt.inner_tx().global.unsigned_tx;

    for (i, psbtin) in psbt.inner_tx().inputs.iter().enumerate() {
        let sighash = psbt
            .signature_hash_internal_input(i, sighash_type)
            .expect("In bounds, and no finalized PSBT in db");
        let sighash = secp256k1::Message::from_slice(&sighash).expect("sighash is a 32 bytes hash");

        // Fetch the appropriate derivation index used for this Unvault output
        let unvault_txid = &unsigned_tx.input[i].previous_output.txid;
        let db_vault = db_vaults.get(unvault_txid).expect("Must be present");

        // All pubkeys use the same one, fortunately!
        for pubkey in managers_pubkeys.clone().into_iter() {
            let pubkey = assume_ok!(
                pubkey
                    .derive(db_vault.derivation_index.into())
                    .derive_public_key(secp),
                "We just derived a non hardened index"
            );
            let sig = psbtin
                .partial_sigs
                .get(&pubkey)
                .ok_or_else(|| SigError::MissingSignature(pubkey))?;

            let (given_sighash_type, sig) = sig.split_last().ok_or(SigError::InvalidLength)?;
            if *given_sighash_type != sighash_type as u8 {
                return Err(SigError::InvalidSighash);
            }

            secp.verify(&sighash, &Signature::from_der(&sig)?, &pubkey.key)?;
        }
    }

    Ok(())
}

// Send a `sig` (https://github.com/revault/practical-revault/blob/master/messages.md#sig-1)
// message to the server for all the sigs of this mapping.
// Note that we are looping, but most (if not all) will only have a single signature
// attached. We are called by the `revocationtxs` RPC, sent after a `getrevocationtxs`
// which generates fresh unsigned transactions.
//
// `sigs` MUST contain valid signatures (including the attached sighash type)
pub fn send_sig_msg(
    transport: &mut KKTransport,
    id: Txid,
    sigs: BTreeMap<BitcoinPubKey, Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    for (pubkey, sig) in sigs {
        let pubkey = pubkey.key;
        let (sigtype, sig) = sig
            .split_last()
            .expect("They must provide valid signatures");
        assert!(
            *sigtype == SigHashType::AllPlusAnyoneCanPay as u8
                || *sigtype == SigHashType::All as u8
        );

        let signature = Signature::from_der(&sig).expect("They must provide valid signatures");
        let sig_msg = Sig {
            pubkey,
            signature,
            id,
        };
        log::debug!(
            "Sending sig '{:?}' to sync server: '{}'",
            sig_msg,
            serde_json::to_string(&sig_msg)?,
        );
        // This will retry 5 times
        transport.write(&serde_json::to_vec(&sig_msg)?)?;
    }

    Ok(())
}

// Send the signatures for the 3 revocation txs to the Coordinator
fn share_rev_signatures(
    revaultd: &RevaultD,
    cancel: (&CancelTransaction, BTreeMap<BitcoinPubKey, Vec<u8>>),
    emer: (&EmergencyTransaction, BTreeMap<BitcoinPubKey, Vec<u8>>),
    unvault_emer: (
        &UnvaultEmergencyTransaction,
        BTreeMap<BitcoinPubKey, Vec<u8>>,
    ),
) -> Result<(), Box<dyn std::error::Error>> {
    // We would not spam the coordinator, would we?
    assert!(cancel.1.len() > 0 && emer.1.len() > 0 && unvault_emer.1.len() > 0);
    let mut transport = KKTransport::connect(
        revaultd.coordinator_host,
        &revaultd.noise_secret,
        &revaultd.coordinator_noisekey,
    )?;

    let cancel_txid = cancel.0.txid();
    send_sig_msg(&mut transport, cancel_txid, cancel.1)?;
    let emer_txid = emer.0.txid();
    send_sig_msg(&mut transport, emer_txid, emer.1)?;
    let unvault_emer_txid = unvault_emer.0.txid();
    send_sig_msg(&mut transport, unvault_emer_txid, unvault_emer.1)?;

    Ok(())
}

fn share_unvault_signatures(
    revaultd: &RevaultD,
    unvault_tx: &UnvaultTransaction,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut transport = KKTransport::connect(
        revaultd.coordinator_host,
        &revaultd.noise_secret,
        &revaultd.coordinator_noisekey,
    )?;

    let sigs = &unvault_tx
        .inner_tx()
        .inputs
        .get(0)
        .expect("Unvault has a single input")
        .partial_sigs;
    log::trace!("Sharing unvault sigs {:?}", sigs);
    let txid = unvault_tx.txid();
    send_sig_msg(&mut transport, txid, sigs.clone())
}

// Will panic if not called by a manager
fn fetch_cosigner_signatures(
    revaultd: &RevaultD,
    spend_tx: &mut SpendTransaction,
) -> Result<(), Box<dyn std::error::Error>> {
    for (host, noise_key) in revaultd.cosigs.as_ref().expect("We are manager").iter() {
        // FIXME: connect should take a reference... This copy is useless
        let mut transport = KKTransport::connect(*host, &revaultd.noise_secret, &noise_key)?;
        let msg = SignRequest {
            tx: spend_tx.clone(),
        };
        log::debug!(
            "Sending '{}' to cosigning server at '{}' (key: '{:?}')",
            &serde_json::to_string(&msg)?,
            host,
            noise_key
        );
        transport.write(&serde_json::to_vec(&msg)?)?;

        let res_msg: SignResponse = serde_json::from_slice(&transport.read()?)?;
        log::debug!(
            "Receiving '{}' from cosigning server",
            &serde_json::to_string(&res_msg)?,
        );

        // FIXME: i abuse jsonrpc_core::Error here to avoid creating YA Error struct when we are
        // going to actually start throwing JSONRPC errors in this thread soon!
        let res_tx = res_msg.tx.ok_or(jsonrpc_core::Error::invalid_params(
            "One of the Cosigning Server already signed a Spend transaction spending \
                one of these vaults!"
                .to_string(),
        ))?;

        for (i, psbtin) in res_tx.into_psbt().inputs.into_iter().enumerate() {
            spend_tx
                .inner_tx_mut()
                .inputs
                .get_mut(i)
                .expect(
                    "A SpendTransaction cannot have a different number of txins and PSBT inputs",
                )
                .partial_sigs
                .extend(psbtin.partial_sigs);
        }
    }

    Ok(())
}

fn announce_spend_transaction(
    revaultd: &RevaultD,
    spend_tx: SpendTransaction,
    deposit_outpoints: Vec<OutPoint>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut transport = KKTransport::connect(
        revaultd.coordinator_host,
        &revaultd.noise_secret,
        &revaultd.coordinator_noisekey,
    )?;

    let msg = SetSpendTx::from_spend_tx(deposit_outpoints, spend_tx);
    transport.write(&serde_json::to_vec(&msg)?)?;
    //TODO: we should have an explicit response

    Ok(())
}

/// Handle events incoming from the JSONRPC interface.
pub fn handle_rpc_messages(
    revaultd: Arc<RwLock<RevaultD>>,
    db_path: PathBuf,
    network: Network,
    rpc_rx: Receiver<RpcMessageIn>,
    jsonrpc_thread: JoinHandle<()>,
    bitcoind_tx: Sender<BitcoindMessageOut>,
    bitcoind_thread: JoinHandle<()>,
    sigfetcher_tx: Sender<SigFetcherMessageOut>,
    sigfetcher_thread: JoinHandle<()>,
) -> Result<(), ControlError> {
    for msg in rpc_rx {
        match msg {
            RpcMessageIn::Shutdown => {
                log::info!("Stopping revaultd.");
                bitcoind_tx.send(BitcoindMessageOut::Shutdown)?;
                sigfetcher_tx.send(SigFetcherMessageOut::Shutdown)?;

                assume_ok!(jsonrpc_thread.join(), "Joining RPC server thread");
                assume_ok!(bitcoind_thread.join(), "Joining bitcoind thread");
                assume_ok!(sigfetcher_thread.join(), "Joining bitcoind thread");

                process::exit(0);
            }
            RpcMessageIn::GetInfo(response_tx) => {
                log::trace!("Got getinfo from RPC thread");

                let (bitrep_tx, bitrep_rx) = mpsc::sync_channel(0);
                bitcoind_tx.send(BitcoindMessageOut::SyncProgress(bitrep_tx))?;
                let progress = bitrep_rx.recv()?;

                // This means blockheight == 0 for IBD.
                let BlockchainTip {
                    height: blockheight,
                    ..
                } = db_tip(&db_path)?;

                let number_of_vaults = listvaults_from_db(&revaultd.read().unwrap(), None, None)?
                    .iter()
                    .filter(|l| {
                        l.status != VaultStatus::Spent
                            && l.status != VaultStatus::Canceled
                            && l.status != VaultStatus::Unvaulted
                            && l.status != VaultStatus::EmergencyVaulted
                    })
                    .collect::<Vec<_>>()
                    .len();

                response_tx.send((network.to_string(), blockheight, progress, number_of_vaults))?;
            }
            RpcMessageIn::ListVaults((statuses, outpoints), response_tx) => {
                log::trace!("Got listvaults from RPC thread");
                response_tx.send(listvaults_from_db(
                    &revaultd.read().unwrap(),
                    statuses,
                    outpoints,
                )?)?;
            }
            RpcMessageIn::DepositAddr(index, response_tx) => {
                log::trace!("Got 'depositaddr' request from RPC thread");
                response_tx.send(if let Some(index) = index {
                    revaultd.read().unwrap().vault_address(index)
                } else {
                    revaultd.read().unwrap().deposit_address()
                })?;
            }
            RpcMessageIn::GetRevocationTxs(outpoint, response_tx) => {
                log::trace!("Got 'getrevocationtxs' request from RPC thread");
                let revaultd = revaultd.read().unwrap();
                let db_file = &revaultd.db_file();

                // First, make sure the vault exists and is confirmed.
                let vault = match db_vault_by_deposit(db_file, &outpoint)? {
                    None => None,
                    Some(vault) => match vault.status {
                        VaultStatus::Unconfirmed => None,
                        _ => Some(vault),
                    },
                };
                if let Some(vault) = vault {
                    // Third, re-derive all the transactions out of it.
                    let emer_address = revaultd
                        .emergency_address
                        .clone()
                        .expect("The JSONRPC API checked we were a stakeholder");

                    let (_, cancel, emergency, unvault_emer) = transaction_chain(
                        outpoint,
                        vault.amount,
                        &revaultd.deposit_descriptor,
                        &revaultd.unvault_descriptor,
                        &revaultd.cpfp_descriptor,
                        vault.derivation_index,
                        emer_address,
                        revaultd.lock_time,
                        &revaultd.secp_ctx,
                    )?;

                    response_tx.send(Some((cancel, emergency, unvault_emer)))?;
                } else {
                    response_tx.send(None)?;
                }
            }
            RpcMessageIn::RevocationTxs(
                (outpoint, cancel_tx, emer_tx, unvault_emer_tx),
                response_tx,
            ) => {
                log::trace!("Got 'revocationtxs' from RPC thread");
                let revaultd = revaultd.read().unwrap();
                let db_path = revaultd.db_file();
                let secp_ctx = &revaultd.secp_ctx;

                // Checked by the RPC server
                assert!(revaultd.is_stakeholder());

                // They may only send revocation transactions for confirmed and not-yet-presigned
                // vaults.
                let db_vault = match db_vault_by_deposit(&db_path, &outpoint)? {
                    Some(v) => match v.status {
                        VaultStatus::Funded => v,
                        status => {
                            response_tx.send(Some(format!(
                                "Invalid vault status: expected {} but got {}",
                                VaultStatus::Funded,
                                status
                            )))?;
                            continue;
                        }
                    },
                    None => {
                        response_tx.send(Some(
                            "Outpoint does not correspond to an existing vault".to_string(),
                        ))?;
                        continue;
                    }
                };

                // Sanity check they didn't send us garbaged PSBTs
                // FIXME: this may not hold true in all cases, see https://github.com/revault/revaultd/issues/145
                let (cancel_db_id, db_cancel_tx) = db_cancel_transaction(&db_path, db_vault.id)?
                    .expect("must be here if at least in 'Funded' state");
                let rpc_txid = cancel_tx.wtxid();
                let db_txid = db_cancel_tx.wtxid();
                if rpc_txid != db_txid {
                    response_tx.send(Some(format!(
                        "Invalid Cancel tx: db wtxid is '{}' but this PSBT's is '{}' ",
                        db_txid, rpc_txid
                    )))?;
                    continue;
                }
                let (emer_db_id, db_emer_tx) = db_emer_transaction(&db_path, db_vault.id)?;
                let rpc_txid = emer_tx.wtxid();
                let db_txid = db_emer_tx.wtxid();
                if rpc_txid != db_txid {
                    response_tx.send(Some(format!(
                        "Invalid Emergency tx: db wtxid is '{}' but this PSBT's is '{}' ",
                        db_txid, rpc_txid
                    )))?;
                    continue;
                }
                let (unvault_emer_db_id, db_unemer_tx) =
                    db_unvault_emer_transaction(&db_path, db_vault.id)?;
                let rpc_txid = unvault_emer_tx.wtxid();
                let db_txid = db_unemer_tx.wtxid();
                if rpc_txid != db_txid {
                    response_tx.send(Some(format!(
                        "Invalid Unvault Emergency tx: db wtxid is '{}' but this PSBT's is '{}' ",
                        db_txid, rpc_txid
                    )))?;
                    continue;
                }

                let deriv_index = db_vault.derivation_index;
                let cancel_sigs = cancel_tx
                    .inner_tx()
                    .inputs
                    .get(0)
                    .expect("Cancel tx has a single input, inbefore fee bumping.")
                    .partial_sigs
                    .clone();
                let emer_sigs = emer_tx
                    .inner_tx()
                    .inputs
                    .get(0)
                    .expect("Emergency tx has a single input, inbefore fee bumping.")
                    .partial_sigs
                    .clone();
                let unvault_emer_sigs = unvault_emer_tx
                    .inner_tx()
                    .inputs
                    .get(0)
                    .expect("UnvaultEmergency tx has a single input, inbefore fee bumping.")
                    .partial_sigs
                    .clone();

                // They must have included *at least* a signature for our pubkey
                let our_pubkey = revaultd
                    .our_stk_xpub
                    .expect("We are a stakeholder")
                    .derive_pub(secp_ctx, &[deriv_index])
                    .expect("The derivation index stored in the database is sane (unhardened)")
                    .public_key;
                if !cancel_sigs.contains_key(&our_pubkey) {
                    response_tx.send(Some(format!(
                        "No signature for ourselves ({}) in Cancel transaction",
                        our_pubkey
                    )))?;
                    continue;
                }
                // We use the same public key across the transaction chain, that's pretty
                // neat from an usability perspective.
                if !emer_sigs.contains_key(&our_pubkey) {
                    response_tx.send(Some(
                        "No signature for ourselves in Emergency transaction".to_string(),
                    ))?;
                    continue;
                }
                if !unvault_emer_sigs.contains_key(&our_pubkey) {
                    response_tx.send(Some(
                        "No signature for ourselves in UnvaultEmergency transaction".to_string(),
                    ))?;
                    continue;
                }

                // Don't share anything if we were given invalid signatures. This
                // checks for the presence (and the validity!) of a SIGHASH type flag.
                if let Err(e) = check_revocation_signatures(secp_ctx, &cancel_tx, &cancel_sigs) {
                    response_tx.send(Some(format!(
                        "Invalid signature in Cancel transaction: {}",
                        e
                    )))?;
                    continue;
                }
                if let Err(e) = check_revocation_signatures(secp_ctx, &emer_tx, &emer_sigs) {
                    response_tx.send(Some(format!(
                        "Invalid signature in Emergency transaction: {}",
                        e
                    )))?;
                    continue;
                }
                if let Err(e) =
                    check_revocation_signatures(secp_ctx, &unvault_emer_tx, &unvault_emer_sigs)
                {
                    response_tx.send(Some(format!(
                        "Invalid signature in Unvault Emergency transaction: {}",
                        e
                    )))?;
                    continue;
                }

                // Ok, signatures look legit. Add them to the PSBTs in database.
                // FIXME: edgy edge case: don't crash here, rather return an error if
                // deposit tx was reorged out in between now and the above status check.

                // NOTE: we update it first as 'securing' as db_update_presigned_tx may update it
                // to 'secured' if it's fully signed.
                db_mark_securing_vault(&db_path, db_vault.id)?;
                db_update_presigned_tx(
                    &db_path,
                    db_vault.id,
                    cancel_db_id,
                    cancel_sigs.clone(),
                    secp_ctx,
                )?;
                db_update_presigned_tx(
                    &db_path,
                    db_vault.id,
                    emer_db_id,
                    emer_sigs.clone(),
                    secp_ctx,
                )?;
                db_update_presigned_tx(
                    &db_path,
                    db_vault.id,
                    unvault_emer_db_id,
                    unvault_emer_sigs.clone(),
                    secp_ctx,
                )?;

                // Share them with our felow stakeholders.
                if let Err(e) = share_rev_signatures(
                    &revaultd,
                    (&cancel_tx, cancel_sigs),
                    (&emer_tx, emer_sigs),
                    (&unvault_emer_tx, unvault_emer_sigs),
                ) {
                    response_tx.send(Some(format!("Error while sharing signatures: {}", e)))?;
                    continue;
                }

                // Ok, RPC server, tell them that everything is fine.
                response_tx.send(None)?;
            }
            RpcMessageIn::GetUnvaultTx(outpoint, response_tx) => {
                log::trace!("Got 'getunvaulttx' request from RPC thread");
                let revaultd = revaultd.read().unwrap();
                let db_file = &revaultd.db_file();

                // We allow the call for Funded 'only' as unvaulttx would later fail if it's
                // not 'secured'.
                let vault = match db_vault_by_deposit(db_file, &outpoint)? {
                    None => {
                        response_tx.send(Err(RpcControlError::UnknownOutpoint(outpoint)))?;
                        continue;
                    }
                    Some(vault) => match vault.status {
                        VaultStatus::Unconfirmed => {
                            response_tx.send(Err(RpcControlError::InvalidStatus((
                                vault.status,
                                VaultStatus::Funded,
                            ))))?;
                            continue;
                        }
                        _ => vault,
                    },
                };

                // Derive the descriptors needed to create the UnvaultTransaction
                let deposit_descriptor = revaultd
                    .deposit_descriptor
                    .derive(vault.derivation_index, &revaultd.secp_ctx);
                let deposit_txin = DepositTxIn::new(
                    outpoint,
                    DepositTxOut::new(vault.amount.as_sat(), &deposit_descriptor),
                );
                let unvault_descriptor = revaultd
                    .unvault_descriptor
                    .derive(vault.derivation_index, &revaultd.secp_ctx);
                let cpfp_descriptor = revaultd
                    .cpfp_descriptor
                    .derive(vault.derivation_index, &revaultd.secp_ctx);

                let unvault_tx = UnvaultTransaction::new(
                    deposit_txin,
                    &unvault_descriptor,
                    &cpfp_descriptor,
                    0,
                )?;
                response_tx.send(Ok(unvault_tx))?;
            }
            RpcMessageIn::UnvaultTx((outpoint, unvault_tx), response_tx) => {
                log::trace!("Got 'unvaulttx' from RPC thread");
                let revaultd = revaultd.read().unwrap();
                let db_path = revaultd.db_file();
                let secp_ctx = &revaultd.secp_ctx;

                // If they haven't got all the signatures for the revocation transactions, we'd
                // better not send our unvault sig!
                // If the vault is already active (or more) there is no point in spamming the
                // coordinator.
                let db_vault = match db_vault_by_deposit(&db_path, &outpoint)? {
                    None => {
                        response_tx.send(Err(RpcControlError::UnknownOutpoint(outpoint)))?;
                        continue;
                    }
                    Some(vault) => match vault.status {
                        VaultStatus::Secured => vault,
                        s => {
                            response_tx.send(Err(RpcControlError::InvalidStatus((
                                s,
                                VaultStatus::Funded,
                            ))))?;
                            continue;
                        }
                    },
                };

                // Sanity check they didn't send us a garbaged PSBT
                let (unvault_db_id, db_unvault_tx) = db_unvault_transaction(&db_path, db_vault.id)?;
                let rpc_txid = unvault_tx.wtxid();
                let db_txid = db_unvault_tx.wtxid();
                if rpc_txid != db_txid {
                    response_tx.send(Err(RpcControlError::InvalidPsbt(format!(
                        "Invalid Unvault tx: db wtxid is '{}' but this PSBT's is '{}' ",
                        db_txid, rpc_txid
                    ))))?;
                    continue;
                }

                let sigs = &unvault_tx
                    .inner_tx()
                    .inputs
                    .get(0)
                    .expect("UnvaultTransaction always has 1 input")
                    .partial_sigs;
                // They must have included *at least* a signature for our pubkey
                let our_pubkey = revaultd
                    .our_stk_xpub
                    .expect("We are a stakeholder")
                    .derive_pub(secp_ctx, &[db_vault.derivation_index])
                    .expect("The derivation index stored in the database is sane (unhardened)")
                    .public_key;
                if !sigs.contains_key(&our_pubkey) {
                    response_tx.send(Err(RpcControlError::InvalidPsbt(format!(
                        "No signature for ourselves ({}) in Unvault transaction",
                        our_pubkey
                    ))))?;
                    continue;
                }

                // Of course, don't send a PSBT with an invalid signature
                if let Err(e) = check_unvault_signatures(secp_ctx, &unvault_tx) {
                    response_tx.send(Err(RpcControlError::InvalidPsbt(format!(
                        "Invalid signature in Unvault transaction: '{}'",
                        e
                    ))))?;
                    continue;
                }

                // Sanity checks passed. Store it then share it.
                // FIXME: edgy edge case: don't crash here, rather return an error if
                // deposit tx was reorged out in between now and the above status check.

                // NOTE: we update it first as 'unvaulting' as db_update_presigned_tx may update it
                // to 'unvaulted' if it's fully signed.
                db_mark_activating_vault(&db_path, db_vault.id)?;
                db_update_presigned_tx(
                    &db_path,
                    db_vault.id,
                    unvault_db_id,
                    sigs.clone(),
                    secp_ctx,
                )?;
                if let Err(e) = share_unvault_signatures(&revaultd, &unvault_tx) {
                    response_tx.send(Err(RpcControlError::Communication(format!(
                        "Sharing Unvault signatures with coordinator: '{}'",
                        e
                    ))))?;
                    continue;
                }

                response_tx.send(Ok(()))?;
            }
            RpcMessageIn::ListPresignedTransactions(outpoints, response_tx) => {
                log::trace!("Got 'listpresignedtransactions' request from RPC thread");
                response_tx.send(presigned_txs_list_from_outpoints(
                    &revaultd.read().unwrap(),
                    outpoints,
                )?)?;
            }
            RpcMessageIn::ListOnchainTransactions(outpoints, response_tx) => {
                log::trace!("Got 'listonchaintransactions' request from RPC thread");
                response_tx.send(onchain_txs_list_from_outpoints(
                    &revaultd.read().unwrap(),
                    &bitcoind_tx,
                    outpoints,
                )?)?;
            }
            RpcMessageIn::GetSpendTx(outpoints, destinations, feerate_vb, response_tx) => {
                log::trace!("Got 'getspendtx' request from RPC thread");
                let revaultd = revaultd.read().unwrap();
                let db_file = &revaultd.db_file();

                // Reconstruct the DepositTxin s from the outpoints and the vaults informations
                let mut txins = Vec::with_capacity(outpoints.len());
                // If we need a change output, use the highest derivation index of the vaults
                // spent. This avoids leaking a new address needlessly while not introducing
                // disrepancy between our indexes.
                let mut change_index = ChildNumber::from(0);
                for outpoint in outpoints.iter() {
                    match db_vault_by_deposit(db_file, &outpoint)? {
                        Some(vault) => match vault.status {
                            VaultStatus::Active => {
                                if vault.derivation_index > change_index {
                                    change_index = vault.derivation_index;
                                }

                                txins.push((*outpoint, vault.amount, vault.derivation_index));
                            }
                            status => {
                                response_tx.send(Err(RpcControlError::InvalidStatus((
                                    status,
                                    VaultStatus::Active,
                                ))))?;
                                break;
                            }
                        },
                        None => {
                            response_tx.send(Err(RpcControlError::UnknownOutpoint(*outpoint)))?;
                            break;
                        }
                    }
                }
                if txins.len() != outpoints.len() {
                    // There was an error with one of the vaults, error is already sent.
                    continue;
                }

                // Mutable as we *may* add a change output
                let mut txos: Vec<SpendTxOut> = destinations
                    .into_iter()
                    .map(|(addr, value)| {
                        let script_pubkey = addr.script_pubkey();
                        SpendTxOut::Destination(ExternalTxOut::new(TxOut {
                            value,
                            script_pubkey,
                        }))
                    })
                    .collect();

                log::debug!(
                    "Creating a Spend transaction with deposit txins: '{:?}' and txos: '{:?}'",
                    &txins,
                    &txos
                );

                // This adds the CPFP output so create a dummy one to accurately compute the
                // feerate.
                let nochange_tx = match spend_tx_from_deposits(
                    txins.clone(),
                    txos.clone(),
                    &revaultd.deposit_descriptor,
                    &revaultd.unvault_descriptor,
                    &revaultd.cpfp_descriptor,
                    revaultd.lock_time,
                    /* Deactivate insane feerate check */
                    false,
                    &revaultd.secp_ctx,
                ) {
                    Ok(tx) => tx,
                    Err(e) => {
                        // Why doesn't the compiler recursively handle into()s ?
                        response_tx.send(Err(RpcControlError::Transaction(e.into())))?;
                        continue;
                    }
                };

                log::debug!(
                    "Spend tx without change: '{}'",
                    nochange_tx.as_psbt_string()
                );

                // If the feerate of the transaction would be much lower (< 90/100) than what they
                // requested for, tell them.
                let nochange_feerate_vb = nochange_tx
                    .max_feerate()
                    .checked_mul(4)
                    .expect("bug in feerate computation");
                if nochange_feerate_vb * 10 < feerate_vb * 9 {
                    response_tx.send(Err(RpcControlError::SpendLowFeerate(
                        feerate_vb,
                        nochange_feerate_vb,
                    )))?;
                    continue;
                }

                // Add a change output if it would not be dust according to our standard (200k sats
                // atm, see DUST_LIMIT).
                // 8 (amount) + 1 (len) + 1 (v0) + 1 (push) + 32 (witscript hash)
                const P2WSH_TXO_WEIGHT: u64 = 43 * 4;
                let with_change_weight = nochange_tx
                    .max_weight()
                    .checked_add(P2WSH_TXO_WEIGHT)
                    .expect("weight computation bug");
                let cur_fees = nochange_tx.fees();
                let want_fees = with_change_weight
                    // Mental gymnastic: sat/vbyte to sat/wu rounded up
                    .checked_mul(feerate_vb + 3)
                    .map(|vbyte| vbyte.checked_div(4).unwrap());
                let change_value = want_fees.map(|f| cur_fees.checked_sub(f));
                log::debug!(
                    "Weight with change: '{}'  --  Fees without change: '{}'  --  Wanted feerate: '{}'  \
                    --  Wanted fees: '{:?}'  --  Change value: '{:?}'",
                    with_change_weight, cur_fees, feerate_vb, want_fees, change_value);

                if let Some(Some(change_value)) = change_value {
                    // The overhead incurred to the value of the CPFP output by the change output
                    // See https://github.com/revault/practical-revault/blob/master/transactions.md#spend_tx
                    let cpfp_overhead = 16 * P2WSH_TXO_WEIGHT;
                    if change_value > revault_tx::transactions::DUST_LIMIT + cpfp_overhead {
                        let change_txo = DepositTxOut::new(
                            // arithmetic checked above
                            change_value - cpfp_overhead,
                            &revaultd
                                .deposit_descriptor
                                .derive(change_index, &revaultd.secp_ctx),
                        );
                        log::debug!("Adding a change txo: '{:?}'", change_txo);
                        txos.push(SpendTxOut::Change(change_txo));
                    }
                }

                // Now we can hand them the resulting transaction (sanity checked for insane fees).
                let tx_res = spend_tx_from_deposits(
                    txins,
                    txos,
                    &revaultd.deposit_descriptor,
                    &revaultd.unvault_descriptor,
                    &revaultd.cpfp_descriptor,
                    revaultd.lock_time,
                    true, /* Activate insane fee check */
                    &revaultd.secp_ctx,
                );
                log::debug!(
                    "Final Spend transaction: '{:?}'",
                    tx_res.as_ref().map(|tx| tx.as_psbt_string())
                );
                response_tx.send(tx_res.map_err(|e| RpcControlError::Transaction(e.into())))?;
            }
            RpcMessageIn::UpdateSpendTx(spend_tx, response_tx) => {
                log::trace!("Got 'updatespendtx' request from RPC thread");
                let revaultd = revaultd.read().unwrap();
                let db_path = revaultd.db_file();
                let spend_txid = spend_tx.txid();

                // Fetch the Unvault it spends from the DB
                let spend_inputs = &spend_tx.inner_tx().global.unsigned_tx.input;
                let mut db_unvaults = Vec::with_capacity(spend_inputs.len());
                for txin in spend_inputs.iter() {
                    let (db_vault, db_unvault) =
                        match db_vault_by_unvault_txid(&db_path, &txin.previous_output.txid)? {
                            Some(res) => res,
                            None => {
                                response_tx.send(Err(RpcControlError::SpendUnknownUnvault(
                                    txin.previous_output.txid,
                                )))?;
                                break;
                            }
                        };

                    if !matches!(db_vault.status, VaultStatus::Active) {
                        response_tx.send(Err(RpcControlError::InvalidStatus((
                            db_vault.status,
                            VaultStatus::Active,
                        ))))?;
                        break;
                    }

                    db_unvaults.push(db_unvault);
                }
                // There was an issue with an outpoint, error is already sent in the loop.
                if db_unvaults.len() != spend_inputs.len() {
                    continue;
                }

                if db_spend_transaction(&db_path, &spend_txid)?.is_some() {
                    log::debug!("Updating Spend transaction '{}'", spend_txid);
                    db_update_spend(&db_path, &spend_tx)?;
                } else {
                    log::debug!("Storing new Spend transaction '{}'", spend_txid);
                    db_insert_spend(&db_path, &db_unvaults, &spend_tx)?;
                }
                response_tx.send(Ok(()))?;
            }
            RpcMessageIn::DelSpendTx(spend_txid, response_tx) => {
                let db_path = revaultd.read().unwrap().db_file();

                db_delete_spend(&db_path, &spend_txid)?;

                response_tx.send(Ok(()))?;
            }
            RpcMessageIn::ListSpendTxs(response_tx) => {
                let db_path = revaultd.read().unwrap().db_file();

                let spend_tx_map = db_list_spends(&db_path)?;
                let mut listspend_entries = Vec::with_capacity(spend_tx_map.len());
                for (_, (psbt, deposit_outpoints)) in spend_tx_map {
                    listspend_entries.push(ListSpendEntry {
                        psbt,
                        deposit_outpoints,
                    });
                }

                response_tx.send(Ok(listspend_entries))?;
            }
            RpcMessageIn::SetSpendTx(spend_txid, response_tx) => {
                log::debug!(
                    "Got 'setspendtx' request from RPC thread for '{}'",
                    spend_txid
                );
                let revaultd = revaultd.read().unwrap();
                let db_path = revaultd.db_file();

                // Get the Spend they reference from DB
                let mut spend_tx = match db_spend_transaction(&db_path, &spend_txid)? {
                    Some(tx) => tx,
                    None => {
                        response_tx.send(Err(RpcControlError::UnknownSpend))?;
                        continue;
                    }
                };

                // Then check all our fellow managers already signed it
                let spent_vaults = db_vaults_from_spend(&db_path, &spend_txid)?;
                let tx = &spend_tx.psbt.inner_tx().global.unsigned_tx;
                if spent_vaults.len() < tx.input.len() {
                    response_tx.send(Err(RpcControlError::AlreadySpentVault))?;
                    continue;
                }
                #[cfg(debug_assertions)]
                {
                    for i in tx.input.iter() {
                        assert!(
                            spent_vaults.contains_key(&i.previous_output.txid),
                            "Insane DB: Spend transaction refers to unknown vaults"
                        );
                    }
                }
                match check_spend_signatures(
                    &revaultd.secp_ctx,
                    &spend_tx.psbt,
                    revaultd.managers_pubkeys.clone(),
                    &spent_vaults,
                ) {
                    Ok(()) => {}
                    Err(e) => {
                        response_tx.send(Err(RpcControlError::SpendSignature(e.to_string())))?;
                        continue;
                    }
                }

                // Now we can ask all the cosigning servers for their signatures
                log::debug!("Fetching signatures from Cosigning servers");
                match fetch_cosigner_signatures(&revaultd, &mut spend_tx.psbt) {
                    Ok(()) => {}
                    Err(e) => {
                        response_tx.send(Err(RpcControlError::Communication(e.to_string())))?;
                        continue;
                    }
                }
                let mut finalized_spend = spend_tx.psbt.clone();
                match finalized_spend.finalize(&revaultd.secp_ctx) {
                    Ok(()) => {}
                    Err(e) => {
                        response_tx.send(Err(RpcControlError::CosigningServer(format!(
                            "Invalid signature given by the cosigners, psbt: '{}' (error: '{}')",
                            spend_tx.psbt.as_psbt_string(),
                            e
                        ))))?;
                        continue;
                    }
                }

                // And then announce it to the Coordinator
                let deposit_outpoints = spent_vaults
                    .values()
                    .map(|db_vault| db_vault.deposit_outpoint)
                    .collect();
                match announce_spend_transaction(&revaultd, finalized_spend, deposit_outpoints) {
                    Ok(()) => {}
                    Err(e) => {
                        response_tx.send(Err(RpcControlError::Communication(e.to_string())))?;
                        continue;
                    }
                }
                db_update_spend(&db_path, &spend_tx.psbt)?;

                // Finally we can broadcast the Unvault(s) transaction(s) and store the Spend
                // transaction for later broadcast
                match bitcoind_broadcast_unvaults(
                    &bitcoind_tx,
                    &db_path,
                    &revaultd.secp_ctx,
                    &spent_vaults,
                ) {
                    Ok(()) => {}
                    Err(e) => {
                        response_tx.send(Err(RpcControlError::UnvaultBroadcast(e.to_string())))?;
                        continue;
                    }
                }
                db_mark_broadcastable_spend(&db_path, &spend_txid)?;

                response_tx.send(Ok(()))?;
            }
            RpcMessageIn::Revault(outpoint, response_tx) => {
                let revaultd = revaultd.read().unwrap();
                let db_path = revaultd.db_file();

                // Checking that the vault is secured, otherwise we don't have the cancel
                // transaction
                let vault = if let Some(vault) = db_vault_by_deposit(&db_path, &outpoint)? {
                    match vault.status {
                        VaultStatus::Unvaulting
                        | VaultStatus::Unvaulted
                        | VaultStatus::Spending => vault,
                        _ => {
                            response_tx.send(Err(RpcControlError::InvalidStatus((
                                vault.status,
                                VaultStatus::Unvaulting,
                            ))))?;
                            continue;
                        }
                    }
                } else {
                    response_tx.send(Err(RpcControlError::UnknownOutpoint(outpoint)))?;
                    continue;
                };

                response_tx.send(
                    bitcoind_broadcast_cancel(&bitcoind_tx, &db_path, &revaultd.secp_ctx, vault)
                        .map_err(|e| RpcControlError::CancelBroadcast(e.to_string())),
                )?;
            }
        }
    }

    Ok(())
}
