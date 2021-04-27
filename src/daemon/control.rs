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
    threadmessages::*,
};

use common::assume_ok;
use revault_net::{
    message::{
        coordinator::{GetSigs, SetSpendResult, SetSpendTx, Sig, SigResult, Sigs},
        cosigner::{SignRequest, SignResult},
    },
    transport::KKTransport,
};
use revault_tx::{
    bitcoin::{
        consensus::encode,
        hashes::hex::ToHex,
        secp256k1::{self, Signature},
        util::bip32::ChildNumber,
        Address, Amount, OutPoint, PublicKey as BitcoinPubKey, SigHashType,
        Transaction as BitcoinTransaction, Txid,
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

use serde::{Serialize, Serializer};

/// A presigned transaction
#[derive(Debug, Serialize)]
pub struct VaultPresignedTransaction<T: RevaultTransaction> {
    pub psbt: T,
    #[serde(rename(serialize = "hex"), serialize_with = "serialize_option_tx_hex")]
    pub transaction: Option<BitcoinTransaction>,
}

/// Contains the presigned transactions (Unvault, Cancel, Emergency, UnvaultEmergency)
/// of a specific vault
#[derive(Debug)]
pub struct VaultPresignedTransactions {
    pub outpoint: OutPoint,
    pub unvault: VaultPresignedTransaction<UnvaultTransaction>,
    pub cancel: VaultPresignedTransaction<CancelTransaction>,
    // None if not stakeholder
    pub emergency: Option<VaultPresignedTransaction<EmergencyTransaction>>,
    pub unvault_emergency: Option<VaultPresignedTransaction<UnvaultEmergencyTransaction>>,
}

/// Contains the transactions that have been broadcasted for a specific vault
#[derive(Debug)]
pub struct VaultOnchainTransactions {
    pub outpoint: OutPoint,
    pub deposit: WalletTransaction,
    pub unvault: Option<WalletTransaction>,
    pub cancel: Option<WalletTransaction>,
    // Always None if not stakeholder
    pub emergency: Option<WalletTransaction>,
    pub unvault_emergency: Option<WalletTransaction>,
    pub spend: Option<WalletTransaction>,
}

/// Contains the spend transaction for a specific vault
#[derive(Debug, Serialize)]
pub struct ListSpendEntry {
    pub deposit_outpoints: Vec<OutPoint>,
    pub psbt: SpendTransaction,
}

/// Contains information regarding a specific vault
#[derive(Debug)]
pub struct ListVaultsEntry {
    pub amount: Amount,
    pub blockheight: u32,
    pub status: VaultStatus,
    pub deposit_outpoint: OutPoint,
    pub derivation_index: ChildNumber,
    pub address: Address,
    pub received_at: u32,
    pub updated_at: u32,
}

fn serialize_tx_hex<S>(tx: &BitcoinTransaction, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let tx_hex = encode::serialize_hex(&tx);
    s.serialize_str(&tx_hex)
}

fn serialize_option_tx_hex<S>(tx: &Option<BitcoinTransaction>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Some(ref tx) = tx {
        serialize_tx_hex(tx, s)
    } else {
        s.serialize_none()
    }
}

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

/// Error while handling an RPC call
#[derive(Debug)]
pub enum RpcControlError {
    // .0 is current status, .1 is required status
    InvalidStatus(VaultStatus, VaultStatus),
    UnknownOutPoint(OutPoint),
}

impl fmt::Display for RpcControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::UnknownOutPoint(ref o) => write!(f, "No vault at '{}'", o),
            Self::InvalidStatus(current, required) => write!(
                f,
                "Invalid vault status: '{}'. Need '{}'",
                current, required
            ),
        }
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
        bitrep_tx,
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
                        return Ok(Err(RpcControlError::InvalidStatus(
                            vault.status,
                            VaultStatus::Funded,
                        )));
                    }
                    _ => vaults.push(vault),
                }
            } else {
                return Ok(Err(RpcControlError::UnknownOutPoint(*outpoint)));
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
                return Ok(Err(RpcControlError::UnknownOutPoint(*outpoint)));
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
    /// Transaction for which we check the sigs does not pass sanity checks
    InsaneTransaction,
    Tx(revault_tx::Error),
}

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "Invalid length of signature"),
            Self::InvalidSighash => write!(f, "Invalid SIGHASH type"),
            Self::VerifError(e) => write!(f, "Signature verification error: '{}'", e),
            Self::MissingSignature(pk) => write!(f, "Missing signature for '{}'", pk),
            Self::InsaneTransaction => write!(f, "Insane transaction"),
            Self::Tx(e) => write!(f, "Error in transaction management: '{}'", e),
        }
    }
}

impl std::error::Error for SigError {}

impl From<secp256k1::Error> for SigError {
    fn from(e: secp256k1::Error) -> Self {
        Self::VerifError(e)
    }
}

/// The signature hash of a presigned transaction (ie Unvault, Cancel, Emergency, or
/// UnvaultEmergency)
///
/// # Error
/// - If the transaction does not have exactly 1 input
/// - If the sighash is not either ALL of ALL|ACP
pub fn presigned_tx_sighash(
    tx: &impl RevaultTransaction,
    hashtype: SigHashType,
) -> Result<secp256k1::Message, SigError> {
    // Presigned transactions only have one input when handled by revaultd.
    if !tx.inner_tx().global.unsigned_tx.input.len() == 1 {
        return Err(SigError::InsaneTransaction);
    }

    // We wouldn't check the signatures of an already valid transaction, would we?
    if tx.is_finalized() {
        return Err(SigError::InsaneTransaction);
    }

    if hashtype != SigHashType::All && hashtype != SigHashType::AllPlusAnyoneCanPay {
        return Err(SigError::InvalidSighash);
    }

    let sighash = tx
        .signature_hash_internal_input(0, hashtype)
        .map_err(|e| SigError::Tx(e.into()))?;
    Ok(secp256k1::Message::from_slice(&sighash).expect("sighash is a 32 bytes hash"))
}

/// Check a raw (with no SIGHASH type appended) presigned tx (ie Unvault, Cancel, Emergency, or
/// UnvaultEmergency) signature.
pub fn check_signature(
    secp: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    tx: &impl RevaultTransaction,
    pubkey: BitcoinPubKey,
    sig: &secp256k1::Signature,
    hashtype: SigHashType,
) -> Result<(), SigError> {
    let sighash = presigned_tx_sighash(tx, hashtype)?;

    secp.verify(&sighash, sig, &pubkey.key)?;

    Ok(())
}

/// Check all complete signatures for revocation transactions (ie Cancel, Emergency,
/// or UnvaultEmergency)
pub fn check_revocation_signatures(
    secp: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    tx: &impl RevaultTransaction,
    // FIXME: it should get the sigs from the tx, as per the Unvault routine
    sigs: &BTreeMap<BitcoinPubKey, Vec<u8>>,
) -> Result<(), SigError> {
    let sighash_type = SigHashType::AllPlusAnyoneCanPay;
    let sighash = presigned_tx_sighash(tx, sighash_type)?;

    for (pubkey, sig) in sigs {
        let (sighash_type, sig) = sig.split_last().ok_or(SigError::InvalidLength)?;
        if *sighash_type != SigHashType::AllPlusAnyoneCanPay as u8 {
            return Err(SigError::InvalidSighash);
        }
        secp.verify(&sighash, &Signature::from_der(&sig)?, &pubkey.key)?;
    }

    Ok(())
}

/// Check all signatures of an Unvault transaction
pub fn check_unvault_signatures(
    secp: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    tx: &UnvaultTransaction,
) -> Result<(), SigError> {
    let sighash_type = SigHashType::All;
    let sighash = presigned_tx_sighash(tx, sighash_type)?;
    let sigs = &tx
        .inner_tx()
        .inputs
        .get(0)
        .ok_or(SigError::InsaneTransaction)?
        .partial_sigs;

    for (pubkey, sig) in sigs.iter() {
        let (sighash_type, sig) = sig.split_last().ok_or(SigError::InvalidLength)?;
        if *sighash_type != SigHashType::All as u8 {
            return Err(SigError::InvalidSighash);
        }
        secp.verify(&sighash, &Signature::from_der(&sig)?, &pubkey.key)?;
    }

    Ok(())
}

/// Check that all the managers provided a valid signature for all the Spend transaction inputs.
///
/// # Panic
/// If `db_vaults` does not contain an entry for each input.
pub fn check_spend_signatures(
    secp: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    psbt: &SpendTransaction,
    managers_pubkeys: Vec<DescriptorPublicKey>,
    db_vaults: &HashMap<Txid, DbVault>,
) -> Result<(), SigError> {
    let sighash_type = SigHashType::All;
    let unsigned_tx = &psbt.inner_tx().global.unsigned_tx;

    // We wouldn't check the signatures of an already valid transaction, would we?
    if psbt.is_finalized() {
        return Err(SigError::InsaneTransaction);
    }

    for (i, psbtin) in psbt.inner_tx().inputs.iter().enumerate() {
        let sighash = psbt
            .signature_hash_internal_input(i, sighash_type)
            .expect("In bounds, and we just checked it was not finalized");
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
                .ok_or(SigError::MissingSignature(pubkey))?;

            let (given_sighash_type, sig) = sig.split_last().ok_or(SigError::InvalidLength)?;
            if *given_sighash_type != sighash_type as u8 {
                return Err(SigError::InvalidSighash);
            }

            secp.verify(&sighash, &Signature::from_der(&sig)?, &pubkey.key)?;
        }
    }

    Ok(())
}

/// An error that occured when talking to a server
#[derive(Debug)]
pub enum CommunicationError {
    /// An error internal to revault_net, generally a transport error
    Net(revault_net::Error),
    /// The Coordinator told us they could not store our signature
    SignatureStorage,
    /// The Coordinator told us they could not store our Spend transaction
    SpendTxStorage,
    /// The Cosigning Server returned null to our request!
    CosigAlreadySigned,
}

impl fmt::Display for CommunicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Net(e) => write!(f, "Network error: '{}'", e),
            Self::SignatureStorage => {
                write!(f, "Coordinator error: it failed to store the signature")
            }
            Self::SpendTxStorage => write!(
                f,
                "Coordinator error: it failed to store the Spending transaction"
            ),
            Self::CosigAlreadySigned => write!(
                f,
                "Cosigning server error: one Cosigning Server already \
                    signed a Spend transaction spending one of these vaults."
            ),
        }
    }
}

impl std::error::Error for CommunicationError {}

impl From<revault_net::Error> for CommunicationError {
    fn from(e: revault_net::Error) -> Self {
        Self::Net(e)
    }
}

// Send a `sig` (https://github.com/revault/practical-revault/blob/master/messages.md#sig-1)
// message to the server for all the sigs of this mapping.
// Note that we are looping, but most (if not all) will only have a single signature
// attached. We are called by the `revocationtxs` RPC, sent after a `getrevocationtxs`
// which generates fresh unsigned transactions.
//
// `sigs` MUST contain valid signatures (including the attached sighash type)
fn send_sig_msg(
    transport: &mut KKTransport,
    id: Txid,
    sigs: BTreeMap<BitcoinPubKey, Vec<u8>>,
) -> Result<(), CommunicationError> {
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
        log::debug!("Sending sig '{:?}' to sync server", sig_msg,);
        let sig_result: SigResult = transport.send_req(&sig_msg.into())?;
        log::debug!("Got from coordinator: '{:?}'", sig_result);
        if !sig_result.ack {
            return Err(CommunicationError::SignatureStorage);
        }
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
    assert!(!cancel.1.is_empty() && !emer.1.is_empty() && !unvault_emer.1.is_empty());
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
) -> Result<(), CommunicationError> {
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

/// Make the cosigning servers sign this Spend transaction.
///
/// # Panic
/// - if not called by a manager
pub fn fetch_cosigs_signatures(
    revaultd: &RevaultD,
    spend_tx: &mut SpendTransaction,
) -> Result<(), CommunicationError> {
    // Strip the signatures before polling the Cosigning Server. It does not check them
    // anyways, and it makes us hit the Noise message size limit fairly quickly.
    let mut stripped_tx = spend_tx.clone();
    for psbtin in stripped_tx.inner_tx_mut().inputs.iter_mut() {
        psbtin.partial_sigs.clear();
    }

    for (host, noise_key) in revaultd.cosigs.as_ref().expect("We are manager").iter() {
        // FIXME: connect should take a reference... This copy is useless
        let mut transport = KKTransport::connect(*host, &revaultd.noise_secret, &noise_key)?;
        let msg = SignRequest {
            tx: stripped_tx.clone(),
        };
        log::debug!(
            "Sending '{:?}' to cosigning server at '{}' (key: '{}')",
            msg,
            host,
            noise_key.0.to_hex()
        );

        let sign_res: SignResult = transport.send_req(&msg.into())?;
        let signed_tx = sign_res.tx.ok_or(CommunicationError::CosigAlreadySigned)?;
        log::debug!(
            "Cosigning server returned: '{}'",
            &signed_tx.as_psbt_string(),
        );

        for (i, psbtin) in signed_tx.into_psbt().inputs.into_iter().enumerate() {
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
) -> Result<(), CommunicationError> {
    let mut transport = KKTransport::connect(
        revaultd.coordinator_host,
        &revaultd.noise_secret,
        &revaultd.coordinator_noisekey,
    )?;

    let msg = SetSpendTx::from_spend_tx(deposit_outpoints, spend_tx);
    log::debug!("Sending Spend tx to Coordinator: '{:?}'", msg);
    let resp: SetSpendResult = transport.send_req(&msg.into())?;
    log::debug!("Got from Coordinator: '{:?}'", resp);
    if !resp.ack {
        return Err(CommunicationError::SpendTxStorage);
    }

    Ok(())
}

/// Get the signatures for this presigned transaction from the Coordinator.
pub fn get_presigs(
    revaultd: &RevaultD,
    txid: Txid,
) -> Result<BTreeMap<secp256k1::PublicKey, secp256k1::Signature>, CommunicationError> {
    let getsigs_msg = GetSigs { id: txid };
    let mut transport = KKTransport::connect(
        revaultd.coordinator_host,
        &revaultd.noise_secret,
        &revaultd.coordinator_noisekey,
    )?;

    log::debug!("Sending to sync server: '{:?}'", getsigs_msg,);
    let resp: Sigs = transport.send_req(&getsigs_msg.into())?;
    log::debug!("Got sigs {:?} from coordinator.", resp);

    Ok(resp.signatures)
}

#[derive(Clone)]
pub struct RpcUtils {
    pub revaultd: Arc<RwLock<RevaultD>>,
    pub bitcoind_tx: Sender<BitcoindMessageOut>,
    pub bitcoind_thread: Arc<RwLock<JoinHandle<()>>>,
    pub sigfetcher_tx: Sender<SigFetcherMessageOut>,
    pub sigfetcher_thread: Arc<RwLock<JoinHandle<()>>>,
}
