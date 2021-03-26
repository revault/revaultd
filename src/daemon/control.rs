//! Any process is at first initiated by a manual interaction. This interaction is possible using the
//! JSONRPC api, which events are handled in the main thread.
//! This module contains useful functions for handling RPC requests.

use crate::{
    bitcoind::BitcoindError,
    database::{
        interface::{
            db_cancel_transaction, db_emer_transaction, db_unvault_emer_transaction,
            db_unvault_transaction, db_vault_by_deposit, db_vaults, db_vaults_min_status,
        },
        schema::DbVault,
        DatabaseError,
    },
    revaultd::{RevaultD, VaultStatus},
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
        OutPoint, PublicKey as BitcoinPubKey, SigHashType, Txid,
    },
    miniscript::descriptor::DescriptorPublicKey,
    transactions::{
        CancelTransaction, EmergencyTransaction, RevaultTransaction, SpendTransaction,
        UnvaultEmergencyTransaction, UnvaultTransaction,
    },
};

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    path::PathBuf,
    process,
    sync::{
        mpsc::{self, RecvError, SendError, Sender},
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

/// Tell bitcoind to broadcast the Unvault transactions of all these vaults.
/// The vaults must be active for the Unvault to be finalizable.
pub fn bitcoind_broadcast_unvaults(
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

/// Tell bitcoind to broadcast the Cancel transactions of this vault.
pub fn bitcoind_broadcast_cancel(
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

/// List the vaults from DB, and filter out the info the RPC wants
// FIXME: we could make this more efficient with smarter SQL queries
pub fn listvaults_from_db(
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

/// List all the presigned transactions from these confirmed vaults.
pub fn presigned_txs_list_from_outpoints(
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

/// List all the onchain transactions from these vaults.
pub fn onchain_txs_list_from_outpoints(
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
pub enum SigError {
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

/// Check all complete signatures for revocation transactions (ie Cancel, Emergency,
/// or UnvaultEmergency)
pub fn check_revocation_signatures(
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

/// Check all complete signatures for unvault transactions
pub fn check_unvault_signatures(
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

/// Check that all the managers provided a valid signature for all the Spend transaction inputs.
/// Will panic if db_vaults does not contain an entry for each input or if the Spend transaction is
/// already finalized.
pub fn check_spend_signatures(
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

/// Send a `sig` (https://github.com/revault/practical-revault/blob/master/messages.md#sig-1)
/// message to the server for all the sigs of this mapping.
/// Note that we are looping, but most (if not all) will only have a single signature
/// attached. We are called by the `revocationtxs` RPC, sent after a `getrevocationtxs`
/// which generates fresh unsigned transactions.
///
/// `sigs` MUST contain valid signatures (including the attached sighash type)
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

/// Send the signatures for the 3 revocation txs to the Coordinator
pub fn share_rev_signatures(
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

/// Send the unvault signature to the Coordinator
pub fn share_unvault_signatures(
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

/// Fetch the Spend signatures from the cosigners
/// Will panic if not called by a manager
pub fn fetch_cosigner_signatures(
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

/// Sends the spend transaction for a certain outpoint to the coordinator
pub fn announce_spend_transaction(
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

#[derive(Clone)]
pub struct RpcUtils {
    pub revaultd: Arc<RwLock<RevaultD>>,
    pub bitcoind_tx: Sender<BitcoindMessageOut>,
    pub bitcoind_thread: Arc<RwLock<Option<JoinHandle<()>>>>,
    pub sigfetcher_tx: Sender<SigFetcherMessageOut>,
    pub sigfetcher_thread: Arc<RwLock<Option<JoinHandle<()>>>>,
}
