//! This module contains routines for controlling our actions (checking signatures, communicating
//! with servers, with bitcoind, ..). Requests may originate from the RPC server or the signature
//! fetcher thread.

use crate::{
    bitcoind::BitcoindError,
    database::{
        interface::{
            db_cancel_transaction, db_emer_transaction, db_signed_emer_txs, db_signed_unemer_txs,
            db_unvault_emer_transaction, db_unvault_transaction, db_vault_by_deposit, db_vaults,
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
    miniscript::{descriptor::DescriptorPublicKey, DescriptorTrait},
    transactions::{
        CancelTransaction, EmergencyTransaction, RevaultTransaction, SpendTransaction,
        UnvaultEmergencyTransaction, UnvaultTransaction,
    },
};

use std::{
    collections::{BTreeMap, HashMap},
    fmt, process,
    sync::{
        mpsc::{self, RecvError, SendError, Sender},
        Arc, RwLock,
    },
    thread::JoinHandle,
};

use serde::{Deserialize, Serialize, Serializer};

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
    pub cpfp_index: usize,
    pub change_index: Option<usize>,
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

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ListSpendStatus {
    NonFinal,
    Pending,
    Broadcasted,
}

/// Error specific to calls that originated from the RPC server.
#[derive(Debug)]
pub enum RpcControlError {
    InvalidStatus(VaultStatus, OutPoint),
    UnknownOutPoint(OutPoint),
    Database(DatabaseError),
    Tx(revault_tx::Error),
    Bitcoind(BitcoindError),
    ThreadCommunication(String),
}

impl From<DatabaseError> for RpcControlError {
    fn from(e: DatabaseError) -> Self {
        Self::Database(e)
    }
}

impl From<revault_tx::Error> for RpcControlError {
    fn from(e: revault_tx::Error) -> Self {
        Self::Tx(e)
    }
}

impl From<BitcoindError> for RpcControlError {
    fn from(e: BitcoindError) -> Self {
        Self::Bitcoind(e)
    }
}

impl<T> From<SendError<T>> for RpcControlError {
    fn from(e: SendError<T>) -> Self {
        Self::ThreadCommunication(format!("Sending to thread: '{}'", e))
    }
}

impl From<RecvError> for RpcControlError {
    fn from(e: RecvError) -> Self {
        Self::ThreadCommunication(format!("Receiving from thread: '{}'", e))
    }
}

impl fmt::Display for RpcControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::UnknownOutPoint(ref o) => write!(f, "No vault at '{}'", o),
            Self::InvalidStatus(status, outpoint) => write!(
                f,
                "Invalid vault status '{}' for deposit outpoint '{}'",
                status, outpoint
            ),
            Self::Database(ref e) => write!(f, "Database error: '{}'", e),
            Self::Tx(ref e) => write!(f, "Transaction handling error: '{}'", e),
            Self::Bitcoind(ref e) => write!(f, "Bitcoind error: '{}'", e),
            Self::ThreadCommunication(ref e) => write!(f, "Thread communication error: '{}'", e),
        }
    }
}

// Ask bitcoind for a wallet transaction
fn bitcoind_wallet_tx(
    bitcoind_tx: &Sender<BitcoindMessageOut>,
    txid: Txid,
) -> Result<Option<WalletTransaction>, RpcControlError> {
    log::trace!("Sending WalletTx to bitcoind thread for {}", txid);

    let (bitrep_tx, bitrep_rx) = mpsc::sync_channel(0);
    bitcoind_tx.send(BitcoindMessageOut::WalletTransaction(txid, bitrep_tx))?;
    bitrep_rx.recv().map_err(|e| e.into())
}

/// Have bitcoind broadcast all these transactions
pub fn bitcoind_broadcast(
    bitcoind_tx: &Sender<BitcoindMessageOut>,
    transactions: Vec<BitcoinTransaction>,
) -> Result<(), RpcControlError> {
    let (bitrep_tx, bitrep_rx) = mpsc::sync_channel(0);

    if !transactions.is_empty() {
        // Note: this is a batched call to bitcoind's RPC, any failure will
        // override all the results.
        bitcoind_tx.send(BitcoindMessageOut::BroadcastTransactions(
            transactions,
            bitrep_tx.clone(),
        ))?;
        bitrep_rx.recv()??;
    }

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

/// Get all vaults from a list of deposit outpoints, if they are not in a given status.
///
/// # Errors
/// If an outpoint does not refer to a known deposit, or if the status of the vault is
/// part of `invalid_statuses`.
pub fn vaults_from_deposits(
    db_path: &std::path::PathBuf,
    outpoints: &[OutPoint],
    invalid_statuses: &[VaultStatus],
) -> Result<Vec<DbVault>, RpcControlError> {
    let mut vaults = Vec::with_capacity(outpoints.len());

    for outpoint in outpoints.iter() {
        // Note: being smarter with SQL queries implies enabling the 'table' feature of rusqlite
        // with a shit ton of dependencies.
        if let Some(vault) = db_vault_by_deposit(db_path, &outpoint)? {
            if invalid_statuses.contains(&vault.status) {
                return Err(RpcControlError::InvalidStatus(vault.status, *outpoint));
            }
            vaults.push(vault);
        } else {
            return Err(RpcControlError::UnknownOutPoint(*outpoint));
        }
    }

    Ok(vaults)
}

/// List all the presigned transactions from these confirmed vaults.
pub fn presigned_txs(
    revaultd: &RevaultD,
    db_vaults: Vec<DbVault>,
) -> Result<Vec<VaultPresignedTransactions>, RpcControlError> {
    let db_path = &revaultd.db_file();

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
            // FIXME: this *might* not hold true in all cases, see https://github.com/revault/revaultd/issues/145
            let (_, emer_psbt) = db_emer_transaction(db_path, db_vault.id)?
                .expect("Must be here post 'Funded' state");
            let mut finalized_emer = emer_psbt.clone();
            emergency = Some(VaultPresignedTransaction {
                transaction: if finalized_emer.finalize(&revaultd.secp_ctx).is_ok() {
                    Some(finalized_emer.into_psbt().extract_tx())
                } else {
                    None
                },
                psbt: emer_psbt,
            });

            // FIXME: this *might* not hold true in all cases, see https://github.com/revault/revaultd/issues/145
            let (_, unemer_psbt) = db_unvault_emer_transaction(db_path, db_vault.id)?
                .expect("Must be here post 'Funded' state");
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

    Ok(tx_list)
}

/// List all the onchain transactions from these vaults.
pub fn onchain_txs(
    revaultd: &RevaultD,
    bitcoind_tx: &Sender<BitcoindMessageOut>,
    db_vaults: Vec<DbVault>,
) -> Result<Vec<VaultOnchainTransactions>, RpcControlError> {
    let db_path = &revaultd.db_file();

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
                    // FIXME: this *might* not hold true in all cases, see https://github.com/revault/revaultd/issues/145
                    let emer = db_emer_transaction(db_path, db_vault.id)?
                        .expect("Must be here post 'Funded' state")
                        .1;
                    emergency =
                        bitcoind_wallet_tx(bitcoind_tx, emer.into_psbt().extract_tx().txid())?;

                    // FIXME: this *might* not hold true in all cases, see https://github.com/revault/revaultd/issues/145
                    let unemer = db_unvault_emer_transaction(db_path, db_vault.id)?
                        .expect("Must be here if not 'unconfirmed'")
                        .1;
                    unvault_emergency =
                        bitcoind_wallet_tx(bitcoind_tx, unemer.into_psbt().extract_tx().txid())?;
                }

                let spend = if let Some(spend_txid) = db_vault.spend_txid {
                    bitcoind_wallet_tx(bitcoind_tx, spend_txid)?
                } else {
                    None
                };

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

    Ok(tx_list)
}

/// Get all the finalized Emergency transactions for each vault, depending on wether the Unvault
/// was already broadcast or not (ie get the one spending from the deposit or the Unvault tx).
pub fn finalized_emer_txs(revaultd: &RevaultD) -> Result<Vec<BitcoinTransaction>, RpcControlError> {
    let db_path = revaultd.db_file();

    let emer_iter = db_signed_emer_txs(&db_path)?.into_iter().map(|mut tx| {
        tx.finalize(&revaultd.secp_ctx)?;
        Ok(tx.into_psbt().extract_tx())
    });
    let unemer_iter = db_signed_unemer_txs(&db_path)?.into_iter().map(|mut tx| {
        tx.finalize(&revaultd.secp_ctx)?;
        Ok(tx.into_psbt().extract_tx())
    });

    emer_iter
        .chain(unemer_iter)
        .collect::<Result<Vec<BitcoinTransaction>, revault_tx::Error>>()
        .map_err(|e| e.into())
}

/// An error thrown when the verification of a signature fails
#[derive(Debug)]
pub enum SigError {
    InvalidLength,
    InvalidSighash,
    VerifError(secp256k1::Error),
    NotEnoughSignatures(usize, usize),
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
            Self::NotEnoughSignatures(needed, current) => {
                write!(
                    f,
                    "Not enough signatures, needed: {}, current: {}",
                    needed, current
                )
            }
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
    if tx.tx().input.len() != 1 {
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
        .signature_hash(0, hashtype)
        .map_err(|e| SigError::Tx(e.into()))?;
    Ok(secp256k1::Message::from_slice(&sighash).expect("sighash is a 32 bytes hash"))
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
        .psbt()
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
    managers_threshold: usize,
    psbt: &SpendTransaction,
    managers_pubkeys: Vec<DescriptorPublicKey>,
    db_vaults: &HashMap<Txid, DbVault>,
) -> Result<(), SigError> {
    let sighash_type = SigHashType::All;
    let unsigned_tx = &psbt.tx();

    // We wouldn't check the signatures of an already valid transaction, would we?
    if psbt.is_finalized() {
        return Err(SigError::InsaneTransaction);
    }

    for (i, psbtin) in psbt.psbt().inputs.iter().enumerate() {
        let mut valid_sigs = 0;
        let sighash = psbt
            .signature_hash(i, sighash_type)
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
            if let Some(sig) = psbtin.partial_sigs.get(&pubkey) {
                let (given_sighash_type, sig) = sig.split_last().ok_or(SigError::InvalidLength)?;
                if *given_sighash_type != sighash_type as u8 {
                    return Err(SigError::InvalidSighash);
                }

                secp.verify(&sighash, &Signature::from_der(&sig)?, &pubkey.key)?;
                valid_sigs += 1;
            }
        }

        if valid_sigs < managers_threshold {
            return Err(SigError::NotEnoughSignatures(
                managers_threshold,
                valid_sigs,
            ));
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
    /// The Cosigning Server tried to fool us!
    CosigInsanePsbt,
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
            Self::CosigInsanePsbt => write!(f, "Cosigning server error: they sent an insane PSBT"),
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

    // FIXME: don't blindly assume the index here..
    let sigs = &unvault_tx
        .psbt()
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
    for psbtin in stripped_tx.psbt_mut().inputs.iter_mut() {
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
        log::debug!("Cosigning server returned: '{}'", &signed_tx,);

        for (i, psbtin) in signed_tx.into_psbt().inputs.into_iter().enumerate() {
            for (key, sig) in psbtin.partial_sigs {
                let (_, rawsig) = sig
                    .split_last()
                    .ok_or(CommunicationError::CosigInsanePsbt)?;
                let sig = secp256k1::Signature::from_der(&rawsig)
                    .map_err(|_| CommunicationError::CosigInsanePsbt)?;
                spend_tx
                    .add_signature(i, key.key, sig, &revaultd.secp_ctx)
                    .map_err(|_| CommunicationError::CosigInsanePsbt)?;
            }
        }
    }

    Ok(())
}

/// This function estimates (conservatively) the size of the message
/// for sending the fully-signed tx to the coordinator, returning
/// if the size is smaller than NOISE_PLAINTEXT_MAX_SIZE
pub fn check_spend_transaction_size(revaultd: &RevaultD, spend_tx: SpendTransaction) -> bool {
    let tx_finalized = spend_tx.is_finalized();
    let mut tx = spend_tx.into_psbt().extract_tx();

    if !tx_finalized {
        let max_satisfaction_weight = revaultd
            .unvault_descriptor
            .inner()
            .max_satisfaction_weight()
            .expect("Script must be satisfiable");
        for input in tx.input.iter_mut() {
            // It's not exact, but close enough
            input.witness.push(vec![0; max_satisfaction_weight]);
        }
    }

    let deposit_outpoints: Vec<OutPoint> = tx.input.iter().map(|i| i.previous_output).collect();
    let tx_hex = encode::serialize_hex(&tx);
    let msg = serde_json::to_string(&serde_json::json!( {
        "deposit_outpoints": deposit_outpoints,
        "transaction": tx_hex,
    }))
    .expect("JSON created inline");
    return msg.len() <= revault_net::noise::NOISE_PLAINTEXT_MAX_SIZE;
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

#[cfg(test)]
mod test {
    use crate::{
        control::*,
        database::{
            actions::{
                db_confirm_deposit, db_confirm_unvault, db_insert_new_unconfirmed_vault,
                db_update_presigned_tx,
            },
            interface::{
                db_cancel_transaction, db_emer_transaction, db_unvault_emer_transaction,
                db_unvault_transaction, db_vault_by_deposit,
            },
            schema::DbVault,
        },
        jsonrpc::UserRole,
        revaultd::{RevaultD, VaultStatus},
        setup_db,
        utils::test_utils::{dummy_revaultd, test_datadir},
    };
    use revault_tx::{
        bitcoin::{
            blockdata::transaction::OutPoint,
            hash_types::Txid,
            network::constants::Network,
            secp256k1,
            util::{amount::Amount, bip143::SigHashCache, bip32::ChildNumber},
            PrivateKey as BitcoinPrivKey, PublicKey as BitcoinPubKey, SigHashType,
        },
        miniscript::descriptor::{DescriptorPublicKey, DescriptorSinglePub},
        transactions::{
            CancelTransaction, EmergencyTransaction, RevaultTransaction, SpendTransaction,
            UnvaultEmergencyTransaction, UnvaultTransaction,
        },
    };
    use std::{fs, str::FromStr};

    #[test]
    fn test_check_spend_transaction_size() {
        let datadir = test_datadir();
        let revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);
        // One input, three outputs, 2 stakeholders and 1 manager psbt. No problem.
        let tx = SpendTransaction::from_psbt_str("cHNidP8BAKgCAAAAAWQYLaJLKOGr2VUPYwlZz5UStWUr7SlxGT+K8S8ubTM1AAAAAAADAAAAA6BCAAAAAAAAIgAg6eJKGnlvCyzkIYItHMBwQDkooqkNDi9RvlVWyl+rYTGA8PoCAAAAABYAFCgf4ZTSb/CpYwWa+Wp0yRMIJoVYf4D4AgAAAAAiACB18mkXdMgWd4MYRrAoIgDiiLLFlxC1j3Qxg9SSVQfbxQAAAAAAAQErybfzBQAAAAAiACCoQFnKMvBMFQZ1py8aLwPpRU6pUCx/LKGU9VMp//zoOwEDBAEAAAABBaghAgKTOrEDfq0KpKeFjG1J1nBeH7O8X2awCRive58A7NUmrFGHZHapFHKpXyKvmhuuuFL5qVJy+MIdmPJkiKxrdqkUtsmtuJyMk3Jsg+KhtdlHidd7lWGIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgAAQElIQK1323qfhEH7yMqxloxMQOfxx7VhZrl5zso8JRdkhBfH6xRhwAAAQFHUiECWC3tv0T0ZWTl2M2wZ1NtYOvjTNHRgBz/Ubv516wom0MhA0cE3stVtaqI/9HvXQY2YkjBMU4ZZVETb/FOq4u6SkkOUq4A").unwrap();
        assert!(check_spend_transaction_size(&revaultd, tx));
        // This 80 inputs tx tho, that's a problem...
        let tx = SpendTransaction::from_psbt_str("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").unwrap();
        assert!(!check_spend_transaction_size(&revaultd, tx));
    }

    #[derive(Clone)]
    struct TestVault {
        db_vault: DbVault,
        transactions: Option<TestTransactions>,
    }

    #[derive(Clone)]
    struct TestTransactions {
        pub initial_cancel: CancelTransaction,
        pub final_cancel: Option<CancelTransaction>,
        pub initial_unvault: UnvaultTransaction,
        pub final_unvault: Option<UnvaultTransaction>,
        pub initial_emer: EmergencyTransaction,
        pub final_emer: Option<EmergencyTransaction>,
        pub initial_unvault_emer: UnvaultEmergencyTransaction,
        pub final_unvault_emer: Option<UnvaultEmergencyTransaction>,
    }

    /// Create 4 vaults: one unconfirmed, one funded, one secured and one active
    fn create_vaults(revaultd: &RevaultD) -> Vec<TestVault> {
        let db_file = revaultd.db_file();
        let outpoints = vec![
            // Unconfirmed
            OutPoint::new(
                Txid::from_str("fcb6ab963b654c773de786f4ac92c132b3d2e816ccea37af9592aa0b4aaec04b")
                    .unwrap(),
                0,
            ),
            // Funded
            OutPoint::new(
                Txid::from_str("617eab1fc0b03ee7f82ba70166725291783461f1a0e7975eaf8b5f8f674234f2")
                    .unwrap(),
                1,
            ),
            // Secured
            OutPoint::new(
                Txid::from_str("a9735f42110ce529386f612194a1e137a2a2679ac0e789ad7f470cd70c3c2c24")
                    .unwrap(),
                2,
            ),
            // Active
            OutPoint::new(
                Txid::from_str("cafa9f92be48ba41f9ee67e775b6c4afebd1bdbde5758792e9f30f6dea41e7fb")
                    .unwrap(),
                3,
            ),
        ];

        let transactions = vec![
            None,
            Some(TestTransactions {
                initial_cancel:
                CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAASDOvhSZlTSEcEoUq/CT7Cg3ILtc6sqt5qJKvAMq+LbIAAAAAAD9////AXYfpDUAAAAAIgAg9AncsIZc8g7mJdfT9infAeWlqjtxBs93ireDGnQn/DYAAAAAAAEBK7hhpDUAAAAAIgAgFZlOQkpDkFSsLUfyeMGVAOT3T88jZM7L/XlVZoJ2jnABAwSBAAAAAQWpIQMVlEoh50lasMhcdwnrmnCp2ROlGY5CrH+HtxQmfZDZ06xRh2R2qRS/INUX1CaP7Pbn5GmtGYu2wgqjnIisa3apFO/kceq8yo9w69g4VVtlFAf739qTiKxsk1KHZ1IhAnddfXi3N38A+aEQ74sUdeuV7sg+2L3ijTjMHMEAfq3cIQLWP96FqjfC5qKQkC2WhYbbLJx1FbNSAjsnMfwDnK0jD1KvARKyaAABAUdSIQOO/iUanbfqJaBaLJWvYVlGFX+WECg27quCjtdyUuOSoCEDCnC1swAcW//WAUHvmyUVt796JvEtizTBlCkqeSvj0PtSrgA=").unwrap(),
                final_cancel: None,
                initial_unvault:
                UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAajRZE5yVgzG9McmOyy/WdcYdrGrK15bB5N/Hg8zhKOkAQAAAAD9////ArhhpDUAAAAAIgAgFZlOQkpDkFSsLUfyeMGVAOT3T88jZM7L/XlVZoJ2jnAwdQAAAAAAACIAILKCCA/RbV3QMPMrwwQmk4Ark4w1WyElM27WtBgftq6ZAAAAAAABASsA6aQ1AAAAACIAIPQJ3LCGXPIO5iXX0/Yp3wHlpao7cQbPd4q3gxp0J/w2AQMEAQAAAAEFR1IhA47+JRqdt+oloFosla9hWUYVf5YQKDbuq4KO13JS45KgIQMKcLWzABxb/9YBQe+bJRW3v3om8S2LNMGUKSp5K+PQ+1KuAAEBqSEDFZRKIedJWrDIXHcJ65pwqdkTpRmOQqx/h7cUJn2Q2dOsUYdkdqkUvyDVF9Qmj+z25+RprRmLtsIKo5yIrGt2qRTv5HHqvMqPcOvYOFVbZRQH+9/ak4isbJNSh2dSIQJ3XX14tzd/APmhEO+LFHXrle7IPti94o04zBzBAH6t3CEC1j/ehao3wuaikJAtloWG2yycdRWzUgI7JzH8A5ytIw9SrwESsmgAAQElIQOO/iUanbfqJaBaLJWvYVlGFX+WECg27quCjtdyUuOSoKxRhwA=").unwrap(),
                final_unvault: None,
                initial_emer:
                EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAajRZE5yVgzG9McmOyy/WdcYdrGrK15bB5N/Hg8zhKOkAQAAAAD9////AXC1pDUAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBKwDppDUAAAAAIgAg9AncsIZc8g7mJdfT9infAeWlqjtxBs93ireDGnQn/DYBAwSBAAAAAQVHUiEDjv4lGp236iWgWiyVr2FZRhV/lhAoNu6rgo7XclLjkqAhAwpwtbMAHFv/1gFB75slFbe/eibxLYs0wZQpKnkr49D7Uq4AAA==").unwrap(),
                final_emer: None,
                initial_unvault_emer:
                UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAASDOvhSZlTSEcEoUq/CT7Cg3ILtc6sqt5qJKvAMq+LbIAAAAAAD9////AXYfpDUAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK7hhpDUAAAAAIgAgFZlOQkpDkFSsLUfyeMGVAOT3T88jZM7L/XlVZoJ2jnABAwSBAAAAAQWpIQMVlEoh50lasMhcdwnrmnCp2ROlGY5CrH+HtxQmfZDZ06xRh2R2qRS/INUX1CaP7Pbn5GmtGYu2wgqjnIisa3apFO/kceq8yo9w69g4VVtlFAf739qTiKxsk1KHZ1IhAnddfXi3N38A+aEQ74sUdeuV7sg+2L3ijTjMHMEAfq3cIQLWP96FqjfC5qKQkC2WhYbbLJx1FbNSAjsnMfwDnK0jD1KvARKyaAAA").unwrap(),
                final_unvault_emer: None,
            }),
            Some(TestTransactions {
                initial_cancel:CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAAZ8pm+vF5rxGSF9+DGV18WMpOEDv45AC3cPpy+gzfBudAAAAAAD9////ARgJ46YAAAAAIgAgdfJpF3TIFneDGEawKCIA4oiyxZcQtY90MYPUklUH28UAAAAAAAEBK0RL46YAAAAAIgAgqEBZyjLwTBUGdacvGi8D6UVOqVAsfyyhlPVTKf/86DsBAwSBAAAAAQWoIQICkzqxA36tCqSnhYxtSdZwXh+zvF9msAkYr3ufAOzVJqxRh2R2qRRyqV8ir5obrrhS+alScvjCHZjyZIisa3apFLbJrbicjJNybIPiobXZR4nXe5VhiKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoAAEBR1IhAlgt7b9E9GVk5djNsGdTbWDr40zR0YAc/1G7+desKJtDIQNHBN7LVbWqiP/R710GNmJIwTFOGWVRE2/xTquLukpJDlKuAA==").unwrap(),
                final_cancel: Some(CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAAZ8pm+vF5rxGSF9+DGV18WMpOEDv45AC3cPpy+gzfBudAAAAAAD9////ARgJ46YAAAAAIgAgdfJpF3TIFneDGEawKCIA4oiyxZcQtY90MYPUklUH28UAAAAAAAEBK0RL46YAAAAAIgAgqEBZyjLwTBUGdacvGi8D6UVOqVAsfyyhlPVTKf/86DsiAgJYLe2/RPRlZOXYzbBnU21g6+NM0dGAHP9Ru/nXrCibQ0gwRQIhAL944Kpjbgr9v1ehOvJoTagRD6mAscPvs1oQlZ7sAF4aAiBiV7TRvErwbFlKrWAgYJlmfpWpbOTqxELqU8LzwYX/r4EiAgNHBN7LVbWqiP/R710GNmJIwTFOGWVRE2/xTquLukpJDkgwRQIhAIhVSc83b0wHhtqHWnZYXs8/n5m/qoq+bUnHwr6rnLbeAiBdhfDlGBKIKvGgCsTqN6WswMXkOartdZFSjEGN1DL/CIEBAwSBAAAAAQWoIQICkzqxA36tCqSnhYxtSdZwXh+zvF9msAkYr3ufAOzVJqxRh2R2qRRyqV8ir5obrrhS+alScvjCHZjyZIisa3apFLbJrbicjJNybIPiobXZR4nXe5VhiKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoAAEBR1IhAlgt7b9E9GVk5djNsGdTbWDr40zR0YAc/1G7+desKJtDIQNHBN7LVbWqiP/R710GNmJIwTFOGWVRE2/xTquLukpJDlKuAA==").unwrap()),
                initial_unvault: UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAYaXLfGg2dQ9K7Z5WCwqwckivsB0tbs/wct42zEuG0zsAAAAAAD9////AkRL46YAAAAAIgAgqEBZyjLwTBUGdacvGi8D6UVOqVAsfyyhlPVTKf/86DswdQAAAAAAACIAIOniShp5bwss5CGCLRzAcEA5KKKpDQ4vUb5VVspfq2ExAAAAAAABASuM0uOmAAAAACIAIHXyaRd0yBZ3gxhGsCgiAOKIssWXELWPdDGD1JJVB9vFAQMEAQAAAAEFR1IhAlgt7b9E9GVk5djNsGdTbWDr40zR0YAc/1G7+desKJtDIQNHBN7LVbWqiP/R710GNmJIwTFOGWVRE2/xTquLukpJDlKuAAEBqCECApM6sQN+rQqkp4WMbUnWcF4fs7xfZrAJGK97nwDs1SasUYdkdqkUcqlfIq+aG664UvmpUnL4wh2Y8mSIrGt2qRS2ya24nIyTcmyD4qG12UeJ13uVYYisbJNSh2dSIQMPZLkiruL9WX8QS8bLO2cPHKLGxJsQcaGmwBBXXZT+WiECq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5Sr1OyaAABASUhArXfbep+EQfvIyrGWjExA5/HHtWFmuXnOyjwlF2SEF8frFGHAA==").unwrap(),
                final_unvault: None,
                initial_emer:
                EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAYaXLfGg2dQ9K7Z5WCwqwckivsB0tbs/wct42zEuG0zsAAAAAAD9////Afye46YAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK4zS46YAAAAAIgAgdfJpF3TIFneDGEawKCIA4oiyxZcQtY90MYPUklUH28UBAwSBAAAAAQVHUiECWC3tv0T0ZWTl2M2wZ1NtYOvjTNHRgBz/Ubv516wom0MhA0cE3stVtaqI/9HvXQY2YkjBMU4ZZVETb/FOq4u6SkkOUq4AAA==").unwrap(),
                final_emer: Some(
                    EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAYaXLfGg2dQ9K7Z5WCwqwckivsB0tbs/wct42zEuG0zsAAAAAAD9////Afye46YAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK4zS46YAAAAAIgAgdfJpF3TIFneDGEawKCIA4oiyxZcQtY90MYPUklUH28UiAgJYLe2/RPRlZOXYzbBnU21g6+NM0dGAHP9Ru/nXrCibQ0gwRQIhAPByVLRaSE7sYQr2tRRs++nK/Ow/6ZIgdGR7mJ2Md2VPAiAqtn37t6/KOl3wsc6O+a1UdJka8G1JnkEAhUY6TcY7DoEiAgNHBN7LVbWqiP/R710GNmJIwTFOGWVRE2/xTquLukpJDkgwRQIhAMu1RAxu3m+CLdAm0eC9d2AprHmvpoNmS5scvEeBTKumAiAw0rBYkbFQfZzv/O6/BadoV/DdY9cP9Q7/zNQK2kJEg4EBAwSBAAAAAQVHUiECWC3tv0T0ZWTl2M2wZ1NtYOvjTNHRgBz/Ubv516wom0MhA0cE3stVtaqI/9HvXQY2YkjBMU4ZZVETb/FOq4u6SkkOUq4AAA==").unwrap(),
                ),
                initial_unvault_emer:
                UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAZ8pm+vF5rxGSF9+DGV18WMpOEDv45AC3cPpy+gzfBudAAAAAAD9////ARgJ46YAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK0RL46YAAAAAIgAgqEBZyjLwTBUGdacvGi8D6UVOqVAsfyyhlPVTKf/86DsBAwSBAAAAAQWoIQICkzqxA36tCqSnhYxtSdZwXh+zvF9msAkYr3ufAOzVJqxRh2R2qRRyqV8ir5obrrhS+alScvjCHZjyZIisa3apFLbJrbicjJNybIPiobXZR4nXe5VhiKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoAAA=").unwrap(),
                final_unvault_emer: Some(
                    UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAZ8pm+vF5rxGSF9+DGV18WMpOEDv45AC3cPpy+gzfBudAAAAAAD9////ARgJ46YAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK0RL46YAAAAAIgAgqEBZyjLwTBUGdacvGi8D6UVOqVAsfyyhlPVTKf/86DsiAgJYLe2/RPRlZOXYzbBnU21g6+NM0dGAHP9Ru/nXrCibQ0cwRAIgIppqYDsvb77lOOqQgs+R/W67n+VX3R4KXhUZOk74GnECIHJpz4QA/xEly1k7SqJyxljbs+LbxqYzzIDHsigDAnzMgSICA0cE3stVtaqI/9HvXQY2YkjBMU4ZZVETb/FOq4u6SkkOSDBFAiEA5SYSLhIdcGaMHo/AFz9ED/BmfywQzw8YLgKjSCB3+koCIBpbFuA7EDvz34wDJ3tgLZNpPvUekBRfzuNtZu01xcDXgQEDBIEAAAABBaghAgKTOrEDfq0KpKeFjG1J1nBeH7O8X2awCRive58A7NUmrFGHZHapFHKpXyKvmhuuuFL5qVJy+MIdmPJkiKxrdqkUtsmtuJyMk3Jsg+KhtdlHidd7lWGIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgAAA==").unwrap(),
                ),
            }),
            Some(TestTransactions {
                initial_cancel:
                CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAARU919uuOZ2HHyRUrQsCrT2s98u7j8/xW6DXMzO7+eYFAAAAAAD9////AaRl6QsAAAAAIgAgp2OS/+Hk2PIc49J6ezFShMrdXWUXMa9LrOwbThd1+zwAAAAAAAEBK9Cn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QBAwSBAAAAAQWoIQIGcwwFZVqf0EVFaTWYlQmxQ4oTCIkj+5KOstDoG1vgOaxRh2R2qRRvoS9lQLcmcOnmhvvrvSYgPxBG3oisa3apFEWuYAoAKnNlB7Zvc0vqNpOAwYMciKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoAAEBR1IhAvuWyyfoIfsyrTwNoR8N80zSBdfJrGff+D9XKBRL7aEFIQJDFo5gffr4sTpOPvcI45wr3VtVCTh/yw/SiCJaCIjiV1KuAA==").unwrap(),
                final_cancel: Some(CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAARU919uuOZ2HHyRUrQsCrT2s98u7j8/xW6DXMzO7+eYFAAAAAAD9////AaRl6QsAAAAAIgAgp2OS/+Hk2PIc49J6ezFShMrdXWUXMa9LrOwbThd1+zwAAAAAAAEBK9Cn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QiAgJDFo5gffr4sTpOPvcI45wr3VtVCTh/yw/SiCJaCIjiV0cwRAIgV8fkyYpVObnygZ74ABmc53lQ2yCfEpQkSsMsUfT4OaICIHTBlPzAyZS0TTDE/+s9uFpsB7/W/s/E5qsJiV+7+j1xgSICAvuWyyfoIfsyrTwNoR8N80zSBdfJrGff+D9XKBRL7aEFSDBFAiEA3QWAAJ0kph9Igr9FMeIAjAhR9jzwvmXU77onyZJG7LkCICcPMk/ycmTKndDJxc7iiA3xBIUsim8cMc+XuuSfuvItgQEDBIEAAAABBaghAgZzDAVlWp/QRUVpNZiVCbFDihMIiSP7ko6y0OgbW+A5rFGHZHapFG+hL2VAtyZw6eaG++u9JiA/EEbeiKxrdqkURa5gCgAqc2UHtm9zS+o2k4DBgxyIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgAAQFHUiEC+5bLJ+gh+zKtPA2hHw3zTNIF18msZ9/4P1coFEvtoQUhAkMWjmB9+vixOk4+9wjjnCvdW1UJOH/LD9KIIloIiOJXUq4A").unwrap()),
                initial_unvault:
                UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAUaovJQUhwegF7P9qJBrWxtPq7dcJVPZ8MTjp9v8LUoDAAAAAAD9////AtCn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QwdQAAAAAAACIAIOD4aW9ds/RNXcNihA2bsw1c+bmg65auhz/3DoPPEg7oAAAAAAABASsYL+oLAAAAACIAIKdjkv/h5NjyHOPSensxUoTK3V1lFzGvS6zsG04Xdfs8AQMEAQAAAAEFR1IhAvuWyyfoIfsyrTwNoR8N80zSBdfJrGff+D9XKBRL7aEFIQJDFo5gffr4sTpOPvcI45wr3VtVCTh/yw/SiCJaCIjiV1KuAAEBqCECBnMMBWVan9BFRWk1mJUJsUOKEwiJI/uSjrLQ6Btb4DmsUYdkdqkUb6EvZUC3JnDp5ob7670mID8QRt6IrGt2qRRFrmAKACpzZQe2b3NL6jaTgMGDHIisbJNSh2dSIQMPZLkiruL9WX8QS8bLO2cPHKLGxJsQcaGmwBBXXZT+WiECq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5Sr1OyaAABASUhAlg43AlKAoXb47H4rxKCu40jBgz7l1svOSFK+N+gIKOdrFGHAA==").unwrap(),
                final_unvault: Some(UnvaultTransaction::from_psbt_str("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").unwrap()),
                initial_emer:
                EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAUaovJQUhwegF7P9qJBrWxtPq7dcJVPZ8MTjp9v8LUoDAAAAAAD9////AYj76QsAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBKxgv6gsAAAAAIgAgp2OS/+Hk2PIc49J6ezFShMrdXWUXMa9LrOwbThd1+zwBAwSBAAAAAQVHUiEC+5bLJ+gh+zKtPA2hHw3zTNIF18msZ9/4P1coFEvtoQUhAkMWjmB9+vixOk4+9wjjnCvdW1UJOH/LD9KIIloIiOJXUq4AAA==").unwrap(),
            final_emer: Some(EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAUaovJQUhwegF7P9qJBrWxtPq7dcJVPZ8MTjp9v8LUoDAAAAAAD9////AYj76QsAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBKxgv6gsAAAAAIgAgp2OS/+Hk2PIc49J6ezFShMrdXWUXMa9LrOwbThd1+zwiAgJDFo5gffr4sTpOPvcI45wr3VtVCTh/yw/SiCJaCIjiV0gwRQIhALJvF8aQzLHn/ggXqdv3Yxc6DUNcUUfBkp5VDc+mHnLrAiBdzlVaNZA3otm6DyD5GTFQuTPsp+DhIgGc3gkq+CzDKoEiAgL7lssn6CH7Mq08DaEfDfNM0gXXyaxn3/g/VygUS+2hBUcwRAIgIzC2vDhc2kfVPG2EYnMmkgrPHHkxlzyuAe6KQXfNjqsCIALiWWK3tsXR210Y0HOkYNIMmTW/qUKzeGO9aRMqoEdzgQEDBIEAAAABBUdSIQL7lssn6CH7Mq08DaEfDfNM0gXXyaxn3/g/VygUS+2hBSECQxaOYH36+LE6Tj73COOcK91bVQk4f8sP0ogiWgiI4ldSrgAA").unwrap()),
                initial_unvault_emer:
                UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAARU919uuOZ2HHyRUrQsCrT2s98u7j8/xW6DXMzO7+eYFAAAAAAD9////AaRl6QsAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK9Cn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QBAwSBAAAAAQWoIQIGcwwFZVqf0EVFaTWYlQmxQ4oTCIkj+5KOstDoG1vgOaxRh2R2qRRvoS9lQLcmcOnmhvvrvSYgPxBG3oisa3apFEWuYAoAKnNlB7Zvc0vqNpOAwYMciKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoAAA=").unwrap(),
            final_unvault_emer: Some(UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAARU919uuOZ2HHyRUrQsCrT2s98u7j8/xW6DXMzO7+eYFAAAAAAD9////AaRl6QsAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK9Cn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QiAgJDFo5gffr4sTpOPvcI45wr3VtVCTh/yw/SiCJaCIjiV0gwRQIhAPSxaISa+1b4SqwfE0WfmXUe3YfIc7zIJfO1PA3ZdUqUAiBJ5JUqCXojmLZilVZGhgVHHwxpu5Kl4z9VftegjciTyoEiAgL7lssn6CH7Mq08DaEfDfNM0gXXyaxn3/g/VygUS+2hBUcwRAIgMval9daakP00a+64tfLtVXcX8iX/RDD+8ds4Ki9qn14CIEeo8hDkwNVJxMiNgM6QQ9I5RLtPPQnVxhzkle3q9lCdgQEDBIEAAAABBaghAgZzDAVlWp/QRUVpNZiVCbFDihMIiSP7ko6y0OgbW+A5rFGHZHapFG+hL2VAtyZw6eaG++u9JiA/EEbeiKxrdqkURa5gCgAqc2UHtm9zS+o2k4DBgxyIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgAAA==").unwrap()),
            }),
        ];

        for outpoint in &outpoints {
            db_insert_new_unconfirmed_vault(
                &db_file,
                1,
                &outpoint,
                &Amount::ONE_BTC,
                ChildNumber::from_normal_idx(0).unwrap(),
                1,
            )
            .unwrap();
        }

        // First vault: Funded
        db_confirm_deposit(
            &db_file,
            &outpoints[1],
            9, // blockheight
            &transactions[1].as_ref().unwrap().initial_unvault,
            &transactions[1].as_ref().unwrap().initial_cancel,
            Some(&transactions[1].as_ref().unwrap().initial_emer),
            Some(&transactions[1].as_ref().unwrap().initial_unvault_emer),
        )
        .unwrap();
        assert_eq!(
            db_vault_by_deposit(&db_file, &outpoints[1])
                .unwrap()
                .unwrap()
                .status,
            VaultStatus::Funded
        );

        // Second vault: Secured
        db_confirm_deposit(
            &db_file,
            &outpoints[2],
            9, // blockheight
            &transactions[2].as_ref().unwrap().initial_unvault,
            &transactions[2].as_ref().unwrap().initial_cancel,
            Some(&transactions[2].as_ref().unwrap().initial_emer),
            Some(&transactions[2].as_ref().unwrap().initial_unvault_emer),
        )
        .unwrap();

        let vaults: Vec<_> = outpoints
            .iter()
            .map(|o| db_vault_by_deposit(&db_file, &o).unwrap().unwrap())
            .collect();

        let (tx_db_id, _) = db_cancel_transaction(&db_file, vaults[2].id)
            .unwrap()
            .unwrap();
        db_update_presigned_tx(
            &db_file,
            vaults[2].id,
            tx_db_id,
            transactions[2]
                .as_ref()
                .unwrap()
                .final_cancel
                .as_ref()
                .unwrap()
                .psbt()
                .inputs[0]
                .partial_sigs
                .clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();

        let (tx_db_id, _) = db_emer_transaction(&db_file, vaults[2].id)
            .unwrap()
            .unwrap();
        db_update_presigned_tx(
            &db_file,
            vaults[2].id,
            tx_db_id,
            transactions[2]
                .as_ref()
                .unwrap()
                .final_emer
                .as_ref()
                .unwrap()
                .psbt()
                .inputs[0]
                .partial_sigs
                .clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();

        let (tx_db_id, _) = db_unvault_emer_transaction(&db_file, vaults[2].id)
            .unwrap()
            .unwrap();
        db_update_presigned_tx(
            &db_file,
            vaults[2].id,
            tx_db_id,
            transactions[2]
                .as_ref()
                .unwrap()
                .final_unvault_emer
                .as_ref()
                .unwrap()
                .psbt()
                .inputs[0]
                .partial_sigs
                .clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();
        assert_eq!(
            db_vault_by_deposit(&db_file, &outpoints[2])
                .unwrap()
                .unwrap()
                .status,
            VaultStatus::Secured
        );

        // Third vault: Active
        db_confirm_deposit(
            &db_file,
            &vaults[3].deposit_outpoint,
            9, // blockheight
            &transactions[3].as_ref().unwrap().initial_unvault,
            &transactions[3].as_ref().unwrap().initial_cancel,
            Some(&transactions[3].as_ref().unwrap().initial_emer),
            Some(&transactions[3].as_ref().unwrap().initial_unvault_emer),
        )
        .unwrap();

        let (tx_db_id, _) = db_cancel_transaction(&db_file, vaults[3].id)
            .unwrap()
            .unwrap();
        db_update_presigned_tx(
            &db_file,
            vaults[2].id,
            tx_db_id,
            transactions[3]
                .as_ref()
                .unwrap()
                .final_cancel
                .as_ref()
                .unwrap()
                .psbt()
                .inputs[0]
                .partial_sigs
                .clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();

        let (tx_db_id, _) = db_emer_transaction(&db_file, vaults[3].id)
            .unwrap()
            .unwrap();
        db_update_presigned_tx(
            &db_file,
            vaults[2].id,
            tx_db_id,
            transactions[3]
                .as_ref()
                .unwrap()
                .final_emer
                .as_ref()
                .unwrap()
                .psbt()
                .inputs[0]
                .partial_sigs
                .clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();

        let (tx_db_id, _) = db_unvault_emer_transaction(&db_file, vaults[3].id)
            .unwrap()
            .unwrap();
        db_update_presigned_tx(
            &db_file,
            vaults[2].id,
            tx_db_id,
            transactions[3]
                .as_ref()
                .unwrap()
                .final_unvault_emer
                .as_ref()
                .unwrap()
                .psbt()
                .inputs[0]
                .partial_sigs
                .clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();

        let (tx_db_id, _) = db_unvault_transaction(&db_file, vaults[3].id).unwrap();
        db_update_presigned_tx(
            &db_file,
            vaults[3].id,
            tx_db_id,
            transactions[3]
                .as_ref()
                .unwrap()
                .final_unvault
                .as_ref()
                .unwrap()
                .psbt()
                .inputs[0]
                .partial_sigs
                .clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();
        assert_eq!(
            db_vault_by_deposit(&db_file, &outpoints[3])
                .unwrap()
                .unwrap()
                .status,
            VaultStatus::Active
        );

        vaults
            .into_iter()
            .zip(transactions)
            .map(|(v, txs)| TestVault {
                db_vault: db_vault_by_deposit(&db_file, &v.deposit_outpoint)
                    .unwrap()
                    .unwrap(),
                transactions: txs,
            })
            .collect()
    }

    #[test]
    fn test_listvaults_from_db() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);
        setup_db(&mut revaultd).unwrap();
        let vaults = create_vaults(&revaultd);

        // Checking that the result is sane
        for v in &vaults {
            let res = &listvaults_from_db(
                &revaultd,
                Some(vec![v.db_vault.status]),
                Some(vec![v.db_vault.deposit_outpoint]),
            )
            .unwrap()[0];
            assert_eq!(res.amount, v.db_vault.amount);
            assert_eq!(res.blockheight, v.db_vault.blockheight);
            assert_eq!(res.status, v.db_vault.status);
            assert_eq!(res.deposit_outpoint, v.db_vault.deposit_outpoint);
            assert_eq!(
                res.derivation_index,
                ChildNumber::from_normal_idx(0).unwrap()
            );
        }

        // Checking that filters work
        assert_eq!(listvaults_from_db(&revaultd, None, None).unwrap().len(), 4);
        assert_eq!(
            listvaults_from_db(&revaultd, Some(vec![VaultStatus::Unconfirmed]), None)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            listvaults_from_db(
                &revaultd,
                Some(vec![VaultStatus::Unconfirmed]),
                Some(vec![vaults[1].db_vault.deposit_outpoint])
            )
            .unwrap()
            .len(),
            0
        );
        assert_eq!(
            listvaults_from_db(
                &revaultd,
                None,
                Some(vec![
                    vaults[0].db_vault.deposit_outpoint,
                    vaults[1].db_vault.deposit_outpoint
                ])
            )
            .unwrap()
            .len(),
            2
        );
        assert_eq!(
            listvaults_from_db(
                &revaultd,
                Some(vec![
                    VaultStatus::Unconfirmed,
                    VaultStatus::Funded,
                    VaultStatus::Secured
                ]),
                None,
            )
            .unwrap()
            .len(),
            3
        );
        assert_eq!(
            listvaults_from_db(
                &revaultd,
                Some(vec![
                    VaultStatus::Unconfirmed,
                    VaultStatus::Funded,
                    VaultStatus::Secured,
                    VaultStatus::Active,
                ]),
                None,
            )
            .unwrap()
            .len(),
            4
        );

        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }

    #[test]
    fn test_vaults_from_deposits() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);
        let db_file = revaultd.db_file();
        setup_db(&mut revaultd).unwrap();
        let vaults = create_vaults(&revaultd);
        let outpoints: Vec<_> = vaults.iter().map(|v| v.db_vault.deposit_outpoint).collect();

        assert_eq!(
            vaults_from_deposits(&db_file, &outpoints, &vec![],)
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            vaults_from_deposits(&db_file, &outpoints[1..], &vec![VaultStatus::Unconfirmed],)
                .unwrap()
                .len(),
            3
        );

        // Returning an error if one of the vaults has an invalid status
        assert!(
            vaults_from_deposits(&db_file, &outpoints, &vec![VaultStatus::Unconfirmed])
                .unwrap_err()
                .to_string()
                .contains(
                    &RpcControlError::InvalidStatus(VaultStatus::Unconfirmed, outpoints[0])
                        .to_string()
                )
        );

        // Returning an error if the outpoint is unknown
        let wrong_outpoint = OutPoint::new(
            Txid::from_str("abababababababababababababababababababababababababababababababab")
                .unwrap(),
            2,
        );
        assert!(
            vaults_from_deposits(&db_file, &vec![wrong_outpoint], &vec![],)
                .unwrap_err()
                .to_string()
                .contains(&RpcControlError::UnknownOutPoint(wrong_outpoint).to_string())
        );

        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }

    #[test]
    fn test_presigned_txs() {
        let datadir = test_datadir();
        let mut stake_revaultd = dummy_revaultd(datadir.clone(), UserRole::Stakeholder);
        let man_revaultd = dummy_revaultd(datadir.clone(), UserRole::Manager);
        setup_db(&mut stake_revaultd).unwrap();
        let vaults = create_vaults(&stake_revaultd);

        // vault[0] is not confirmed, no presigned txs here!
        assert!(
            presigned_txs(&stake_revaultd, vec![vaults[0].db_vault.clone()])
                .unwrap_err()
                .to_string()
                .contains("Database error: No unvault tx in db")
        );

        // vault[1] is funded, no txs is final
        // The stakeholder has all the txs
        let stake_txs = presigned_txs(&stake_revaultd, vec![vaults[1].db_vault.clone()]).unwrap();
        assert_eq!(stake_txs.len(), 1);
        assert_eq!(stake_txs[0].outpoint, vaults[1].db_vault.deposit_outpoint);
        assert_eq!(
            stake_txs[0].cancel.psbt,
            vaults[1].transactions.as_ref().unwrap().initial_cancel
        );
        assert!(stake_txs[0].cancel.transaction.is_none());
        assert_eq!(
            stake_txs[0].unvault.psbt,
            vaults[1].transactions.as_ref().unwrap().initial_unvault
        );
        assert!(stake_txs[0].unvault.transaction.is_none());
        assert_eq!(
            stake_txs[0].emergency.as_ref().unwrap().psbt,
            vaults[1].transactions.as_ref().unwrap().initial_emer
        );
        assert!(stake_txs[0]
            .emergency
            .as_ref()
            .unwrap()
            .transaction
            .is_none());
        assert_eq!(
            stake_txs[0].unvault_emergency.as_ref().unwrap().psbt,
            vaults[1]
                .transactions
                .as_ref()
                .unwrap()
                .initial_unvault_emer
        );
        assert!(stake_txs[0]
            .unvault_emergency
            .as_ref()
            .unwrap()
            .transaction
            .is_none());

        // The manager has the same txs, but no emergency
        let man_txs = presigned_txs(&man_revaultd, vec![vaults[1].db_vault.clone()]).unwrap();
        assert_eq!(man_txs.len(), 1);
        assert_eq!(man_txs[0].outpoint, vaults[1].db_vault.deposit_outpoint);
        assert_eq!(
            man_txs[0].cancel.psbt,
            vaults[1].transactions.as_ref().unwrap().initial_cancel
        );
        assert!(man_txs[0].cancel.transaction.is_none());
        assert_eq!(
            man_txs[0].unvault.psbt,
            vaults[1].transactions.as_ref().unwrap().initial_unvault
        );
        assert!(man_txs[0].unvault.transaction.is_none());
        assert!(man_txs[0].emergency.is_none());
        assert!(man_txs[0].unvault_emergency.is_none());

        // vault[2] is secured, the unvault tx is not final
        // The stakeholder has all the txs
        let stake_txs = presigned_txs(&stake_revaultd, vec![vaults[2].db_vault.clone()]).unwrap();
        assert_eq!(stake_txs.len(), 1);
        assert_eq!(stake_txs[0].outpoint, vaults[2].db_vault.deposit_outpoint);
        assert_eq!(
            stake_txs[0].cancel.psbt,
            *vaults[2]
                .transactions
                .as_ref()
                .unwrap()
                .final_cancel
                .as_ref()
                .unwrap()
        );
        assert!(stake_txs[0].cancel.transaction.is_some());
        assert_eq!(
            stake_txs[0].unvault.psbt,
            vaults[2].transactions.as_ref().unwrap().initial_unvault
        );
        assert!(stake_txs[0].unvault.transaction.is_none());
        assert_eq!(
            stake_txs[0].emergency.as_ref().unwrap().psbt,
            *vaults[2]
                .transactions
                .as_ref()
                .unwrap()
                .final_emer
                .as_ref()
                .unwrap()
        );
        assert!(stake_txs[0]
            .emergency
            .as_ref()
            .unwrap()
            .transaction
            .is_some());
        assert_eq!(
            stake_txs[0].unvault_emergency.as_ref().unwrap().psbt,
            *vaults[2]
                .transactions
                .as_ref()
                .unwrap()
                .final_unvault_emer
                .as_ref()
                .unwrap()
        );
        assert!(stake_txs[0]
            .unvault_emergency
            .as_ref()
            .unwrap()
            .transaction
            .is_some());

        // The manager has the same txs, but no emergency
        let man_txs = presigned_txs(&man_revaultd, vec![vaults[2].db_vault.clone()]).unwrap();
        assert_eq!(man_txs.len(), 1);
        assert_eq!(man_txs[0].outpoint, vaults[2].db_vault.deposit_outpoint);
        assert_eq!(
            man_txs[0].cancel.psbt,
            *vaults[2]
                .transactions
                .as_ref()
                .unwrap()
                .final_cancel
                .as_ref()
                .unwrap()
        );
        assert!(man_txs[0].cancel.transaction.is_some());
        assert_eq!(
            man_txs[0].unvault.psbt,
            vaults[2].transactions.as_ref().unwrap().initial_unvault
        );
        assert!(man_txs[0].unvault.transaction.is_none());
        assert!(man_txs[0].emergency.is_none());
        assert!(man_txs[0].unvault_emergency.is_none());

        // vault[3] is active, every tx is final
        // The stakeholder has all the txs
        let stake_txs = presigned_txs(&stake_revaultd, vec![vaults[3].db_vault.clone()]).unwrap();
        assert_eq!(stake_txs.len(), 1);
        assert_eq!(stake_txs[0].outpoint, vaults[3].db_vault.deposit_outpoint);
        assert_eq!(
            stake_txs[0].cancel.psbt,
            *vaults[3]
                .transactions
                .as_ref()
                .unwrap()
                .final_cancel
                .as_ref()
                .unwrap()
        );
        assert!(stake_txs[0].cancel.transaction.is_some());
        assert_eq!(
            stake_txs[0].unvault.psbt,
            *vaults[3]
                .transactions
                .as_ref()
                .unwrap()
                .final_unvault
                .as_ref()
                .unwrap()
        );
        assert!(stake_txs[0].unvault.transaction.is_some());
        assert_eq!(
            stake_txs[0].emergency.as_ref().unwrap().psbt,
            *vaults[3]
                .transactions
                .as_ref()
                .unwrap()
                .final_emer
                .as_ref()
                .unwrap()
        );
        assert!(stake_txs[0]
            .emergency
            .as_ref()
            .unwrap()
            .transaction
            .is_some());
        assert_eq!(
            stake_txs[0].unvault_emergency.as_ref().unwrap().psbt,
            *vaults[3]
                .transactions
                .as_ref()
                .unwrap()
                .final_unvault_emer
                .as_ref()
                .unwrap()
        );
        assert!(stake_txs[0]
            .unvault_emergency
            .as_ref()
            .unwrap()
            .transaction
            .is_some());

        // The manager has the same txs, but no emergency
        let man_txs = presigned_txs(&man_revaultd, vec![vaults[3].db_vault.clone()]).unwrap();
        assert_eq!(man_txs.len(), 1);
        assert_eq!(man_txs[0].outpoint, vaults[3].db_vault.deposit_outpoint);
        assert_eq!(
            man_txs[0].cancel.psbt,
            *vaults[3]
                .transactions
                .as_ref()
                .unwrap()
                .final_cancel
                .as_ref()
                .unwrap()
        );
        assert!(man_txs[0].cancel.transaction.is_some());
        assert_eq!(
            man_txs[0].unvault.psbt,
            *vaults[3]
                .transactions
                .as_ref()
                .unwrap()
                .final_unvault
                .as_ref()
                .unwrap()
        );
        assert!(man_txs[0].unvault.transaction.is_some());
        assert!(man_txs[0].emergency.is_none());
        assert!(man_txs[0].unvault_emergency.is_none());

        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }

    #[test]
    fn test_finalized_emer_txs() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::Manager);
        setup_db(&mut revaultd).unwrap();
        let db_file = revaultd.db_file();
        let vaults = create_vaults(&revaultd);

        // Let's calculate all our emer, unemer txs
        // vault[2]
        let mut emer2 = vaults[2]
            .transactions
            .as_ref()
            .unwrap()
            .final_emer
            .clone()
            .unwrap();
        emer2.finalize(&revaultd.secp_ctx).unwrap();
        let emer2 = emer2.into_psbt().extract_tx();
        let mut unvault_emer2 = vaults[2]
            .transactions
            .as_ref()
            .unwrap()
            .final_unvault_emer
            .clone()
            .unwrap();
        unvault_emer2.finalize(&revaultd.secp_ctx).unwrap();
        let unvault_emer2 = unvault_emer2.into_psbt().extract_tx();

        // vault[3]
        let mut emer3 = vaults[3]
            .transactions
            .as_ref()
            .unwrap()
            .final_emer
            .clone()
            .unwrap();
        emer3.finalize(&revaultd.secp_ctx).unwrap();
        let emer3 = emer3.into_psbt().extract_tx();
        let mut unvault_emer3 = vaults[3]
            .transactions
            .as_ref()
            .unwrap()
            .final_unvault_emer
            .clone()
            .unwrap();
        unvault_emer3.finalize(&revaultd.secp_ctx).unwrap();
        let unvault_emer3 = unvault_emer3.into_psbt().extract_tx();

        // I will get all the emergency txs, as I don't have >= unvaulting vaults
        let txs = finalized_emer_txs(&revaultd).unwrap();
        // One secured vault and one active vault
        assert_eq!(txs.len(), 2);
        assert!(txs.contains(&emer2));
        assert!(txs.contains(&emer3));

        // Let's upgraude vault[2] to Unvaulted...
        // (we can, as we're manually touching the db, even if we don't even have the fully signed
        // unvault!)
        db_confirm_unvault(
            &db_file,
            &vaults[2]
                .transactions
                .as_ref()
                .unwrap()
                .initial_unvault
                .psbt()
                .global
                .unsigned_tx
                .txid(),
        )
        .unwrap();
        // I will get one emer and one unvault_emer
        let txs = finalized_emer_txs(&revaultd).unwrap();
        assert_eq!(txs.len(), 2);
        assert!(txs.contains(&unvault_emer2));
        assert!(txs.contains(&emer3));

        // Let's upgraude vault[3] to Unvaulted...
        db_confirm_unvault(
            &db_file,
            &vaults[3]
                .transactions
                .as_ref()
                .unwrap()
                .initial_unvault
                .psbt()
                .global
                .unsigned_tx
                .txid(),
        )
        .unwrap();
        // Two unvault emer!
        let txs = finalized_emer_txs(&revaultd).unwrap();
        assert_eq!(txs.len(), 2);
        assert!(txs.contains(&unvault_emer2));
        assert!(txs.contains(&unvault_emer3));

        fs::remove_dir_all(&datadir).unwrap();
    }

    #[test]
    fn test_presigned_tx_sighash() {
        let datadir = test_datadir();
        let revaultd = dummy_revaultd(datadir, UserRole::ManagerStakeholder);

        // A RevaultTransaction with multiple inputs
        let tx = CancelTransaction::from_psbt_str("cHNidP8BAIcCAAAAAvvnQeptD/Ppkod15b290euvxLZ152fu+UG6SL6Sn/rKAwAAAAD9////K6wOngepyjysKKXiEUntd0HTM9hDT6d2hzOnGOYvB5EAAAAAAP3///8Bes3LHQAAAAAiACAiB1URdpLbPVOgR361M5byVJWUrSorRzKB9ls5e4WZEQAAAAAAAQErpg/MHQAAAAAiACD81LIaR5tvZke/RiX8d1TzDKcJHsnQr7Y8HRBh/Txh8SICAryqF/aeT6OwqH48wpkNaKu5BZqcZXzgyl4Z758P0YuESDBFAiEAxTjt2+FUGQYvyk4s22KffTBG6EUyMenpGZ9gPeKPM6ECIDQ1Bxds9DZjpTGAHgmIZtru1HA9WGeStbgKH7cQUeq6gSICAxjzGCXfRtFhIh3oMXqXJGNnIAASdnv3ew8UlNfn7N5ZSDBFAiEA/FXZdFvem9r9Rgj/ndhW/5k9nhA1GbpAUx15BItV4PgCICy+YnzAFGiXPZVR3um6GW/T0uxt3Wzhi289nqUaHXFDgQEDBIEAAAABBaghAgPHSfAloH4bK1PlRN6K+IzAbbxkf/YS1Ki1aS+XwQe7rFGHZHapFKH2KeYE3b7EwzjxOTdU46doSmy3iKxrdqkUmEKNXQMQl/KOoGRty6RxMQ5QrgeIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgAAQEfNgAAAAAAAAAWABQAAAAAAAAAAAAAAAAAAAAAAAAAAAEDBAEAAAAAAQFHUiECvKoX9p5Po7CofjzCmQ1oq7kFmpxlfODKXhnvnw/Ri4QhAxjzGCXfRtFhIh3oMXqXJGNnIAASdnv3ew8UlNfn7N5ZUq4A").unwrap();
        assert!(presigned_tx_sighash(&tx, SigHashType::AllPlusAnyoneCanPay)
            .unwrap_err()
            .to_string()
            .contains(&SigError::InsaneTransaction.to_string()));

        // A RevaultTransaction already finalized
        let mut tx = UnvaultTransaction::from_psbt_str("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").unwrap();
        tx.finalize(&revaultd.secp_ctx).unwrap();
        assert!(presigned_tx_sighash(&tx, SigHashType::All)
            .unwrap_err()
            .to_string()
            .contains(&SigError::InsaneTransaction.to_string()));

        // A RevaultTransaction with the wrong SigHashType
        let tx = UnvaultTransaction::from_psbt_str("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").unwrap();
        assert!(presigned_tx_sighash(&tx, SigHashType::Single)
            .unwrap_err()
            .to_string()
            .contains(&SigError::InvalidSighash.to_string()));

        // And finally, a proper RevaultTransaction :)
        let tx = UnvaultTransaction::from_psbt_str("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").unwrap();
        presigned_tx_sighash(&tx, SigHashType::All).unwrap();
    }

    fn create_keys(
        ctx: &secp256k1::Secp256k1<secp256k1::All>,
        secret_slice: &[u8],
    ) -> (BitcoinPrivKey, BitcoinPubKey) {
        let secret_key = secp256k1::SecretKey::from_slice(secret_slice).unwrap();
        let private_key = BitcoinPrivKey {
            compressed: true,
            network: Network::Regtest,
            key: secret_key,
        };
        let public_key = BitcoinPubKey::from_private_key(&ctx, &private_key);
        (private_key, public_key)
    }

    #[test]
    fn test_check_revocation_signatures() {
        let revaultds = [
            dummy_revaultd(test_datadir(), UserRole::Manager),
            dummy_revaultd(test_datadir(), UserRole::ManagerStakeholder),
            dummy_revaultd(test_datadir(), UserRole::Stakeholder),
        ];

        // We need a ctx that can sign as well (revaultd context is verify only)
        let ctx = secp256k1::Secp256k1::new();

        let (private_key, public_key) =
            create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);

        // Let's create a valid signature
        let tx = UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAbmw9RR44LLNO5aKs0SOdUDW4aJgM9indHt2KSEVkRNBAAAAAAD9////AaQvhEcAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK9BxhEcAAAAAIgAgMJBZ5AwbSGM9P3Q44qxIeXv5J4UXLnhwdfblfBLn2voBAwSBAAAAAQWoIQL5vFDdmMV/P4SpzIWhDMbHKHMGlMwntZxaWtwUXd9KvKxRh2R2qRTtnZLjf14tI1q08+ZyoIEpuuMqWYisa3apFJKFWLx/I+YKyIXcNmwC0yw69uN9iKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoAAA=").unwrap();
        let psbt = tx.psbt();
        let mut cache = SigHashCache::new(&psbt.global.unsigned_tx);
        let prev_value = psbt.inputs[0].witness_utxo.as_ref().unwrap().value;
        let script_code = psbt.inputs[0].witness_script.as_ref().unwrap();
        let sighash = cache.signature_hash(
            0,
            &script_code,
            prev_value,
            SigHashType::AllPlusAnyoneCanPay,
        );
        let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
        let mut sig = ctx
            .sign(&sighash, &private_key.key)
            .serialize_der()
            .to_vec();
        sig.push(SigHashType::AllPlusAnyoneCanPay as u8);
        let mut sigs = BTreeMap::new();
        sigs.insert(public_key, sig.clone());

        // Happy path: everything works :)
        for revaultd in &revaultds {
            check_revocation_signatures(&revaultd.secp_ctx, &tx, &sigs).unwrap();
        }

        // Now, onto with the sad paths...

        // Signature is empty? Wtf?
        let mut wrong_sigs = BTreeMap::new();
        wrong_sigs.insert(public_key, vec![]);
        for revaultd in &revaultds {
            assert!(
                check_revocation_signatures(&revaultd.secp_ctx, &tx, &wrong_sigs)
                    .unwrap_err()
                    .to_string()
                    .contains(&SigError::InvalidLength.to_string())
            );
        }

        // Signature is not a valid der-encoded string
        let mut wrong_sig = vec![1, 2, 3];
        wrong_sig.push(SigHashType::All as u8);
        let mut wrong_sigs = BTreeMap::new();
        wrong_sigs.insert(public_key, wrong_sig);
        for revaultd in &revaultds {
            assert!(
                check_revocation_signatures(&revaultd.secp_ctx, &tx, &wrong_sigs)
                    .unwrap_err()
                    .to_string()
                    .contains(&SigError::InvalidSighash.to_string())
            );
        }

        // I signed with the right sighash_type but pushed the wrong one
        let mut wrong_sig = ctx
            .sign(&sighash, &private_key.key)
            .serialize_der()
            .to_vec();
        wrong_sig.push(SigHashType::All as u8);
        let mut wrong_sigs = BTreeMap::new();
        wrong_sigs.insert(public_key, wrong_sig);
        for revaultd in &revaultds {
            assert!(
                check_revocation_signatures(&revaultd.secp_ctx, &tx, &wrong_sigs)
                    .unwrap_err()
                    .to_string()
                    .contains(&SigError::InvalidSighash.to_string())
            );
        }

        // I signed with the wrong sighash_type but pushed the right one
        let wrong_sighash = cache.signature_hash(0, &script_code, prev_value, SigHashType::All);
        let wrong_sighash = secp256k1::Message::from_slice(&wrong_sighash).unwrap();
        let mut wrong_sig = ctx
            .sign(&wrong_sighash, &private_key.key)
            .serialize_der()
            .to_vec();
        wrong_sig.push(SigHashType::AllPlusAnyoneCanPay as u8);
        let mut wrong_sigs = BTreeMap::new();
        wrong_sigs.insert(public_key, wrong_sig);
        for revaultd in &revaultds {
            assert!(
                check_revocation_signatures(&revaultd.secp_ctx, &tx, &wrong_sigs)
                    .unwrap_err()
                    .to_string()
                    .contains("Signature verification error")
            );
        }

        // The signature is correct, but signed by another key
        let (_, another_public_key) =
            create_keys(&ctx, &[3; secp256k1::constants::SECRET_KEY_SIZE]);
        let mut wrong_sigs = BTreeMap::new();
        wrong_sigs.insert(another_public_key, sig.clone());
        for revaultd in &revaultds {
            assert!(
                check_revocation_signatures(&revaultd.secp_ctx, &tx, &wrong_sigs)
                    .unwrap_err()
                    .to_string()
                    .contains("Signature verification error")
            );
        }

        // The signature is correct, but signs a completely different message
        let wrong_msg = secp256k1::Message::from_slice(&[1; 32]).unwrap();
        let mut wrong_sig = ctx
            .sign(&wrong_msg, &private_key.key)
            .serialize_der()
            .to_vec();
        wrong_sig.push(SigHashType::AllPlusAnyoneCanPay as u8);
        let mut wrong_sigs = BTreeMap::new();
        wrong_sigs.insert(public_key, wrong_sig);
        for revaultd in &revaultds {
            assert!(
                check_revocation_signatures(&revaultd.secp_ctx, &tx, &wrong_sigs)
                    .unwrap_err()
                    .to_string()
                    .contains("Signature verification error")
            );
        }
    }

    #[test]
    fn test_check_unvault_signatures() {
        let revaultds = [
            dummy_revaultd(test_datadir(), UserRole::Manager),
            dummy_revaultd(test_datadir(), UserRole::ManagerStakeholder),
            dummy_revaultd(test_datadir(), UserRole::Stakeholder),
        ];

        // We need a ctx that can sign as well (revaultd context is verify only)
        let ctx = secp256k1::Secp256k1::new();

        let (private_key, public_key) =
            create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);

        let mut tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAYi2DPhirMLIyBDVZxf7imJWUCdV4q2yE8kvyE+dsJz5AAAAAAD9////AtBxhEcAAAAAIgAgMJBZ5AwbSGM9P3Q44qxIeXv5J4UXLnhwdfblfBLn2vowdQAAAAAAACIAIJZTpkweKS2TREar9MCFqF1QwPShzY3fF5zdVq2cA+SBAAAAAAABASsY+YRHAAAAACIAIA7F4yZpfkQdqB/Rizfk6gwzgZ0r/n2BfCUn69oRaXDZAQMEAQAAAAEFR1IhAlA4fOi+w5kA39d/IoJWs5m37DR1ZYGpO85N4jdF/oLQIQO9bL04WJFHJXFejdFCVHKAgUcX4cUrPan81x0tF18pxVKuAAEBqCEC+bxQ3ZjFfz+EqcyFoQzGxyhzBpTMJ7WcWlrcFF3fSrysUYdkdqkU7Z2S439eLSNatPPmcqCBKbrjKlmIrGt2qRSShVi8fyPmCsiF3DZsAtMsOvbjfYisbJNSh2dSIQMPZLkiruL9WX8QS8bLO2cPHKLGxJsQcaGmwBBXXZT+WiECq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5Sr1OyaAABASUhAwMP2nhloxevl/eBAfL2jOTIHpt8z0WcFtm2ihnyZuPSrFGHAA==").unwrap();

        // No sigs, everything is fine
        for revaultd in &revaultds {
            check_unvault_signatures(&revaultd.secp_ctx, &tx).unwrap();
        }

        // Let's forge a valid signature
        let psbt = tx.psbt_mut();
        let mut cache = SigHashCache::new(&psbt.global.unsigned_tx);
        let prev_value = psbt.inputs[0].witness_utxo.as_ref().unwrap().value;
        let script_code = psbt.inputs[0].witness_script.as_ref().unwrap();
        let sighash = cache.signature_hash(0, &script_code, prev_value, SigHashType::All);
        let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
        let mut sig = ctx
            .sign(&sighash, &private_key.key)
            .serialize_der()
            .to_vec();
        sig.push(SigHashType::All as u8);
        psbt.inputs[0].partial_sigs.insert(public_key, sig.clone());

        // Happy path: everything works :)
        for revaultd in &revaultds {
            check_unvault_signatures(&revaultd.secp_ctx, &tx).unwrap();
        }

        // Now, onto with the sad paths...

        // A tx without inputs??
        let mut tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAYi2DPhirMLIyBDVZxf7imJWUCdV4q2yE8kvyE+dsJz5AAAAAAD9////AtBxhEcAAAAAIgAgMJBZ5AwbSGM9P3Q44qxIeXv5J4UXLnhwdfblfBLn2vowdQAAAAAAACIAIJZTpkweKS2TREar9MCFqF1QwPShzY3fF5zdVq2cA+SBAAAAAAABASsY+YRHAAAAACIAIA7F4yZpfkQdqB/Rizfk6gwzgZ0r/n2BfCUn69oRaXDZAQMEAQAAAAEFR1IhAlA4fOi+w5kA39d/IoJWs5m37DR1ZYGpO85N4jdF/oLQIQO9bL04WJFHJXFejdFCVHKAgUcX4cUrPan81x0tF18pxVKuAAEBqCEC+bxQ3ZjFfz+EqcyFoQzGxyhzBpTMJ7WcWlrcFF3fSrysUYdkdqkU7Z2S439eLSNatPPmcqCBKbrjKlmIrGt2qRSShVi8fyPmCsiF3DZsAtMsOvbjfYisbJNSh2dSIQMPZLkiruL9WX8QS8bLO2cPHKLGxJsQcaGmwBBXXZT+WiECq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5Sr1OyaAABASUhAwMP2nhloxevl/eBAfL2jOTIHpt8z0WcFtm2ihnyZuPSrFGHAA==").unwrap();
        tx.psbt_mut().inputs.remove(0);
        for revaultd in &revaultds {
            assert!(check_unvault_signatures(&revaultd.secp_ctx, &tx)
                .unwrap_err()
                .to_string().contains("Error in transaction management: \'Revault input satisfaction error: \'Index out of bounds of inputs list\'\'"));
        }

        // The error is a bit different if there are no inputs in the unsigned_tx...
        let mut tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAYi2DPhirMLIyBDVZxf7imJWUCdV4q2yE8kvyE+dsJz5AAAAAAD9////AtBxhEcAAAAAIgAgMJBZ5AwbSGM9P3Q44qxIeXv5J4UXLnhwdfblfBLn2vowdQAAAAAAACIAIJZTpkweKS2TREar9MCFqF1QwPShzY3fF5zdVq2cA+SBAAAAAAABASsY+YRHAAAAACIAIA7F4yZpfkQdqB/Rizfk6gwzgZ0r/n2BfCUn69oRaXDZAQMEAQAAAAEFR1IhAlA4fOi+w5kA39d/IoJWs5m37DR1ZYGpO85N4jdF/oLQIQO9bL04WJFHJXFejdFCVHKAgUcX4cUrPan81x0tF18pxVKuAAEBqCEC+bxQ3ZjFfz+EqcyFoQzGxyhzBpTMJ7WcWlrcFF3fSrysUYdkdqkU7Z2S439eLSNatPPmcqCBKbrjKlmIrGt2qRSShVi8fyPmCsiF3DZsAtMsOvbjfYisbJNSh2dSIQMPZLkiruL9WX8QS8bLO2cPHKLGxJsQcaGmwBBXXZT+WiECq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5Sr1OyaAABASUhAwMP2nhloxevl/eBAfL2jOTIHpt8z0WcFtm2ihnyZuPSrFGHAA==").unwrap();
        tx.psbt_mut().global.unsigned_tx.input.remove(0);
        for revaultd in &revaultds {
            assert!(check_unvault_signatures(&revaultd.secp_ctx, &tx)
                .unwrap_err()
                .to_string()
                .contains(&SigError::InsaneTransaction.to_string()));
        }

        // Signature is empty? Wtf?
        let mut tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAYi2DPhirMLIyBDVZxf7imJWUCdV4q2yE8kvyE+dsJz5AAAAAAD9////AtBxhEcAAAAAIgAgMJBZ5AwbSGM9P3Q44qxIeXv5J4UXLnhwdfblfBLn2vowdQAAAAAAACIAIJZTpkweKS2TREar9MCFqF1QwPShzY3fF5zdVq2cA+SBAAAAAAABASsY+YRHAAAAACIAIA7F4yZpfkQdqB/Rizfk6gwzgZ0r/n2BfCUn69oRaXDZAQMEAQAAAAEFR1IhAlA4fOi+w5kA39d/IoJWs5m37DR1ZYGpO85N4jdF/oLQIQO9bL04WJFHJXFejdFCVHKAgUcX4cUrPan81x0tF18pxVKuAAEBqCEC+bxQ3ZjFfz+EqcyFoQzGxyhzBpTMJ7WcWlrcFF3fSrysUYdkdqkU7Z2S439eLSNatPPmcqCBKbrjKlmIrGt2qRSShVi8fyPmCsiF3DZsAtMsOvbjfYisbJNSh2dSIQMPZLkiruL9WX8QS8bLO2cPHKLGxJsQcaGmwBBXXZT+WiECq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5Sr1OyaAABASUhAwMP2nhloxevl/eBAfL2jOTIHpt8z0WcFtm2ihnyZuPSrFGHAA==").unwrap();
        tx.psbt_mut().inputs[0]
            .partial_sigs
            .insert(public_key, vec![]);
        for revaultd in &revaultds {
            assert!(check_unvault_signatures(&revaultd.secp_ctx, &tx)
                .unwrap_err()
                .to_string()
                .contains(&SigError::InvalidLength.to_string()));
        }

        // Signature is not a valid der-encoded string
        let mut tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAYi2DPhirMLIyBDVZxf7imJWUCdV4q2yE8kvyE+dsJz5AAAAAAD9////AtBxhEcAAAAAIgAgMJBZ5AwbSGM9P3Q44qxIeXv5J4UXLnhwdfblfBLn2vowdQAAAAAAACIAIJZTpkweKS2TREar9MCFqF1QwPShzY3fF5zdVq2cA+SBAAAAAAABASsY+YRHAAAAACIAIA7F4yZpfkQdqB/Rizfk6gwzgZ0r/n2BfCUn69oRaXDZAQMEAQAAAAEFR1IhAlA4fOi+w5kA39d/IoJWs5m37DR1ZYGpO85N4jdF/oLQIQO9bL04WJFHJXFejdFCVHKAgUcX4cUrPan81x0tF18pxVKuAAEBqCEC+bxQ3ZjFfz+EqcyFoQzGxyhzBpTMJ7WcWlrcFF3fSrysUYdkdqkU7Z2S439eLSNatPPmcqCBKbrjKlmIrGt2qRSShVi8fyPmCsiF3DZsAtMsOvbjfYisbJNSh2dSIQMPZLkiruL9WX8QS8bLO2cPHKLGxJsQcaGmwBBXXZT+WiECq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5Sr1OyaAABASUhAwMP2nhloxevl/eBAfL2jOTIHpt8z0WcFtm2ihnyZuPSrFGHAA==").unwrap();
        let mut wrong_sig = vec![1, 2, 3];
        wrong_sig.push(SigHashType::All as u8);
        tx.psbt_mut().inputs[0]
            .partial_sigs
            .insert(public_key, wrong_sig);
        for revaultd in &revaultds {
            assert!(check_unvault_signatures(&revaultd.secp_ctx, &tx)
                .unwrap_err()
                .to_string()
                .contains("Signature verification error"));
        }

        // I signed with the right sighash_type but pushed the wrong one
        let mut tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAYi2DPhirMLIyBDVZxf7imJWUCdV4q2yE8kvyE+dsJz5AAAAAAD9////AtBxhEcAAAAAIgAgMJBZ5AwbSGM9P3Q44qxIeXv5J4UXLnhwdfblfBLn2vowdQAAAAAAACIAIJZTpkweKS2TREar9MCFqF1QwPShzY3fF5zdVq2cA+SBAAAAAAABASsY+YRHAAAAACIAIA7F4yZpfkQdqB/Rizfk6gwzgZ0r/n2BfCUn69oRaXDZAQMEAQAAAAEFR1IhAlA4fOi+w5kA39d/IoJWs5m37DR1ZYGpO85N4jdF/oLQIQO9bL04WJFHJXFejdFCVHKAgUcX4cUrPan81x0tF18pxVKuAAEBqCEC+bxQ3ZjFfz+EqcyFoQzGxyhzBpTMJ7WcWlrcFF3fSrysUYdkdqkU7Z2S439eLSNatPPmcqCBKbrjKlmIrGt2qRSShVi8fyPmCsiF3DZsAtMsOvbjfYisbJNSh2dSIQMPZLkiruL9WX8QS8bLO2cPHKLGxJsQcaGmwBBXXZT+WiECq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5Sr1OyaAABASUhAwMP2nhloxevl/eBAfL2jOTIHpt8z0WcFtm2ihnyZuPSrFGHAA==").unwrap();
        let psbt = tx.psbt_mut();
        let mut cache = SigHashCache::new(&psbt.global.unsigned_tx);
        let prev_value = psbt.inputs[0].witness_utxo.as_ref().unwrap().value;
        let script_code = psbt.inputs[0].witness_script.as_ref().unwrap();
        let sighash = cache.signature_hash(0, &script_code, prev_value, SigHashType::All);
        let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
        let mut wrong_sig = ctx
            .sign(&sighash, &private_key.key)
            .serialize_der()
            .to_vec();
        wrong_sig.push(SigHashType::AllPlusAnyoneCanPay as u8);
        tx.psbt_mut().inputs[0]
            .partial_sigs
            .insert(public_key, wrong_sig);
        for revaultd in &revaultds {
            assert!(check_unvault_signatures(&revaultd.secp_ctx, &tx)
                .unwrap_err()
                .to_string()
                .contains(&SigError::InvalidSighash.to_string()));
        }

        // I signed with the wrong sighash_type but pushed the right one
        let mut tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAYi2DPhirMLIyBDVZxf7imJWUCdV4q2yE8kvyE+dsJz5AAAAAAD9////AtBxhEcAAAAAIgAgMJBZ5AwbSGM9P3Q44qxIeXv5J4UXLnhwdfblfBLn2vowdQAAAAAAACIAIJZTpkweKS2TREar9MCFqF1QwPShzY3fF5zdVq2cA+SBAAAAAAABASsY+YRHAAAAACIAIA7F4yZpfkQdqB/Rizfk6gwzgZ0r/n2BfCUn69oRaXDZAQMEAQAAAAEFR1IhAlA4fOi+w5kA39d/IoJWs5m37DR1ZYGpO85N4jdF/oLQIQO9bL04WJFHJXFejdFCVHKAgUcX4cUrPan81x0tF18pxVKuAAEBqCEC+bxQ3ZjFfz+EqcyFoQzGxyhzBpTMJ7WcWlrcFF3fSrysUYdkdqkU7Z2S439eLSNatPPmcqCBKbrjKlmIrGt2qRSShVi8fyPmCsiF3DZsAtMsOvbjfYisbJNSh2dSIQMPZLkiruL9WX8QS8bLO2cPHKLGxJsQcaGmwBBXXZT+WiECq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5Sr1OyaAABASUhAwMP2nhloxevl/eBAfL2jOTIHpt8z0WcFtm2ihnyZuPSrFGHAA==").unwrap();
        let psbt = tx.psbt_mut();
        let mut cache = SigHashCache::new(&psbt.global.unsigned_tx);
        let prev_value = psbt.inputs[0].witness_utxo.as_ref().unwrap().value;
        let script_code = psbt.inputs[0].witness_script.as_ref().unwrap();
        let wrong_sighash = cache.signature_hash(
            0,
            &script_code,
            prev_value,
            SigHashType::AllPlusAnyoneCanPay,
        );
        let wrong_sighash = secp256k1::Message::from_slice(&wrong_sighash).unwrap();
        let mut wrong_sig = ctx
            .sign(&wrong_sighash, &private_key.key)
            .serialize_der()
            .to_vec();
        wrong_sig.push(SigHashType::All as u8);
        tx.psbt_mut().inputs[0]
            .partial_sigs
            .insert(public_key, wrong_sig);
        for revaultd in &revaultds {
            assert!(check_unvault_signatures(&revaultd.secp_ctx, &tx)
                .unwrap_err()
                .to_string()
                .contains("Signature verification error"));
        }

        // The signature is correct, but signed by another key
        let (_, another_public_key) =
            create_keys(&ctx, &[3; secp256k1::constants::SECRET_KEY_SIZE]);
        let mut tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAYi2DPhirMLIyBDVZxf7imJWUCdV4q2yE8kvyE+dsJz5AAAAAAD9////AtBxhEcAAAAAIgAgMJBZ5AwbSGM9P3Q44qxIeXv5J4UXLnhwdfblfBLn2vowdQAAAAAAACIAIJZTpkweKS2TREar9MCFqF1QwPShzY3fF5zdVq2cA+SBAAAAAAABASsY+YRHAAAAACIAIA7F4yZpfkQdqB/Rizfk6gwzgZ0r/n2BfCUn69oRaXDZAQMEAQAAAAEFR1IhAlA4fOi+w5kA39d/IoJWs5m37DR1ZYGpO85N4jdF/oLQIQO9bL04WJFHJXFejdFCVHKAgUcX4cUrPan81x0tF18pxVKuAAEBqCEC+bxQ3ZjFfz+EqcyFoQzGxyhzBpTMJ7WcWlrcFF3fSrysUYdkdqkU7Z2S439eLSNatPPmcqCBKbrjKlmIrGt2qRSShVi8fyPmCsiF3DZsAtMsOvbjfYisbJNSh2dSIQMPZLkiruL9WX8QS8bLO2cPHKLGxJsQcaGmwBBXXZT+WiECq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5Sr1OyaAABASUhAwMP2nhloxevl/eBAfL2jOTIHpt8z0WcFtm2ihnyZuPSrFGHAA==").unwrap();
        let psbt = tx.psbt_mut();
        let mut cache = SigHashCache::new(&psbt.global.unsigned_tx);
        let prev_value = psbt.inputs[0].witness_utxo.as_ref().unwrap().value;
        let script_code = psbt.inputs[0].witness_script.as_ref().unwrap();
        let sighash = cache.signature_hash(0, &script_code, prev_value, SigHashType::All);
        let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
        let mut sig = ctx
            .sign(&sighash, &private_key.key)
            .serialize_der()
            .to_vec();
        sig.push(SigHashType::All as u8);
        tx.psbt_mut().inputs[0]
            .partial_sigs
            .insert(another_public_key, sig);
        for revaultd in &revaultds {
            assert!(check_unvault_signatures(&revaultd.secp_ctx, &tx)
                .unwrap_err()
                .to_string()
                .contains("Signature verification error"));
        }

        // The signature is correct, but signs a completely different message
        let wrong_msg = secp256k1::Message::from_slice(&[1; 32]).unwrap();
        let mut wrong_sig = ctx
            .sign(&wrong_msg, &private_key.key)
            .serialize_der()
            .to_vec();
        wrong_sig.push(SigHashType::AllPlusAnyoneCanPay as u8);
        tx.psbt_mut().inputs[0]
            .partial_sigs
            .insert(public_key, wrong_sig);
        for revaultd in &revaultds {
            assert!(check_unvault_signatures(&revaultd.secp_ctx, &tx)
                .unwrap_err()
                .to_string()
                .contains("Signature verification error"));
        }
    }

    #[test]
    fn test_check_spend_signatures() {
        let mut revaultds = [
            dummy_revaultd(test_datadir(), UserRole::Manager),
            dummy_revaultd(test_datadir(), UserRole::ManagerStakeholder),
            dummy_revaultd(test_datadir(), UserRole::Stakeholder),
        ];
        setup_db(&mut revaultds[0]).unwrap();
        let vaults = create_vaults(&revaultds[0]);
        let vaults = vaults
            .into_iter()
            .map(|v| (v.db_vault.deposit_outpoint.txid, v.db_vault))
            .collect();

        // We need a ctx that can sign as well (revaultd context is verify only)
        let ctx = secp256k1::Secp256k1::new();

        let manager_keychains: Vec<_> = (1..3)
            .into_iter()
            .map(|i| create_keys(&ctx, &[i; secp256k1::constants::SECRET_KEY_SIZE]))
            .collect();
        let managers_pubkeys: Vec<_> = manager_keychains
            .clone()
            .into_iter()
            .map(|(_, key)| {
                DescriptorPublicKey::SinglePub(DescriptorSinglePub { origin: None, key })
            })
            .collect();

        // Happy path: everything works :)
        let mut tx = SpendTransaction::from_psbt_str("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").unwrap();
        let psbt = tx.psbt_mut();
        let mut cache = SigHashCache::new(&psbt.global.unsigned_tx);
        for input in &mut psbt.inputs {
            let prev_value = input.witness_utxo.as_ref().unwrap().value;
            let script_code = input.witness_script.as_ref().unwrap();
            let sighash = cache.signature_hash(0, &script_code, prev_value, SigHashType::All);
            let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
            for keychain in &manager_keychains {
                let mut sig = ctx.sign(&sighash, &keychain.0.key).serialize_der().to_vec();
                sig.push(SigHashType::All as u8);
                input.partial_sigs.insert(keychain.1, sig.clone());
            }
        }
        for revaultd in &revaultds {
            // FIXME: here we're passing managers_pubkeys.len() instead of
            // revaultd.managers_threshold() because this tests are costructed
            // in a very hacky way: we have revaultd but the descriptors actually contain
            // different keys from the managers_xpubs that we're using for testing!
            // Hopefully in the future this tests won't be that hacky, and we'll be able
            // to call managers_threshold here as well
            check_spend_signatures(
                &revaultd.secp_ctx,
                managers_pubkeys.len(),
                &tx,
                managers_pubkeys.clone(),
                &vaults,
            )
            .unwrap();
        }

        // Already finalized PSBT
        let mut tx = SpendTransaction::from_psbt_str("cHNidP8BAKgCAAAAARU919uuOZ2HHyRUrQsCrT2s98u7j8/xW6DXMzO7+eYFAAAAAAADAAAAA6BCAAAAAAAAIgAg4Phpb12z9E1dw2KEDZuzDVz5uaDrlq6HP/cOg88SDuiAlpgAAAAAABYAFPAj0esIbomyGAolRR1U/vYas0RxhspQCwAAAAAiACCnY5L/4eTY8hzj0np7MVKEyt1dZRcxr0us7BtOF3X7PAAAAAAAAQEr0KfpCwAAAAAiACDxHhkvHdl/8DtU5xns+0DOFIujmiWSqpg/6+gsJEWfZCICAgKTOrEDfq0KpKeFjG1J1nBeH7O8X2awCRive58A7NUmRzBEAiB3KkDDMDY+tFDP/NEp0Qvl7ndg0zeah+aeWC8pcrLedQIgCRgErTVJbFpEXY//cEejA/35u9DDR9Odx0B6CyIETHABIgICA8dJ8CWgfhsrU+VE3or4jMBtvGR/9hLUqLVpL5fBB7tIMEUCIQDlxg6DwLX1ilz36a1aSydMfTCz/Cj5jgDgqk1gogDxiAIgHn85138uFwbEpAI4dfqdaOE4FTjg10c/JepCMJ75nGIBIgICBnMMBWVan9BFRWk1mJUJsUOKEwiJI/uSjrLQ6Btb4DlIMEUCIQCNVIPcowRztg4naOv4SkLlsWE/JK6txS1rhrdEFjgzGwIgd7TQy9C/HytCj46Xr7AShn4lm9AKsIwhcDK+ZRYCZP4BIgICEUcipBjtxtFxFXI6CYvMq/KXtJxTVJETq5tRILViovxIMEUCIQCq1nTvhPAEqpwvT83E7l903TZfeA0wwBd1sdIAaMrzlQIgR7v+TYZxt5GOADgDqMHd20E9ps9yjt38Xx5FEMeRpIEBIgICq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5HMEQCIDs+EJm+1ahGgXUteU0UpiD+pF+byHKgcXuCAGK2cr+dAiAXLnVdMLBT06XA1PNT7pzRYn8YwRuagHsqdFZn1/kqGQEiAgLKu0S06bTqM58ay1TmFWXs+3OwjYhNK8e07OGWSCCnNEgwRQIhAPf5MXo44ra2oHhiS2+mrigZsVwlBHeI8TIUa8nkFsg0AiApIhymkAPpbh1iX5HhKhv7ZSnpDFZCf2MAG0XdKUaA+gEiAgLoIlcyuneynTYaX6GkPZgd6S7+s33mK+GmsoFNFj4f0kcwRAIgZ1LcuP3qnxzMPLDSJKPnKxW9NUEr2FEPxypmfy5Axx0CIEhDmU61ffHePcWxwRB01k9nh1UNjjZcwWv6/7lLReThASICAvbewaqhppKhJmJCtUrXIa2E4HIeghNYUe3jdZpOPyWsRzBEAiB+YisdkzDamRmocVNY1L78iYs6NPTXdXRr9PcXeqYJmQIgcgs1E2bsopySlAlVHNmXVI2AgYNiPK8cFFqR09CQIAwBIgIC+bxQ3ZjFfz+EqcyFoQzGxyhzBpTMJ7WcWlrcFF3fSrxIMEUCIQD0B7BRPDeDOsmvnc0ndozXLlYJgATXvahWi6WtI1loXQIgfxw7aGb7rXyKnL0cCtOt2Mo2shV8mXbYvyIZhVEeP44BIgIDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lpHMEQCIF9+ZZO4AoFaz0WVZbLXNONf0S4pPQJrqRBrTII/nfxmAiBMppaQlftKQNtw2AcmvbFnxdqfXys+TwM0I+Env+0YzQEiAgM10BzuiowG8+zoJisSnHBWMbB2Z7eaB/4FoNWsJyvU9EcwRAIgY/4i6WCy9dKm4bIIFVgo+RmNwMOCxpGBn4o8pmYrqpcCIAM7hMX+az0D10wg0gzwc1ltYuf/JRkCNJfAN3AvA3XgASICA05t+3A0/e1NLMTAIYAg3jdEy4ofmtzSh8emoXMoeusXSDBFAiEAnWN8RXH69QweNR3T3VKpdNEHugiVTL6cIvXcnK6P+AMCIEZy/RkyUxcsXW80/hY4c71KZsCbwIyTcvhhgflGaXGwASICA06OB5pRHoR9/LWGTHq6Sy4Ugc85I1tQyEymGej6/fiNRzBEAiBAXayRXgy0xZ2lR6xTwN8iaDCr//SxLz/biRmdYG1usAIgf9l3przSfZcX2wnkKQPQLFzCeseLvy+w14tOQ/fABjYBIgIDwCr2aH/yTKugv5gL94kaje+nlTukczWC88/V6l4oDo5HMEQCIHzww7Pq/oCNpS1R9aEPGF3AHBlCrx6NE32CA4ZThxCcAiBtsieXalS5Bd4i/+JxytFVn2Le/Pf7/7ko7zhQDE4gUgEBAwQBAAAAAQWoIQIGcwwFZVqf0EVFaTWYlQmxQ4oTCIkj+5KOstDoG1vgOaxRh2R2qRRvoS9lQLcmcOnmhvvrvSYgPxBG3oisa3apFEWuYAoAKnNlB7Zvc0vqNpOAwYMciKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoAAEBJSECWDjcCUoChdvjsfivEoK7jSMGDPuXWy85IUr436Ago52sUYcAAAEBR1IhAvuWyyfoIfsyrTwNoR8N80zSBdfJrGff+D9XKBRL7aEFIQJDFo5gffr4sTpOPvcI45wr3VtVCTh/yw/SiCJaCIjiV1KuAA==").unwrap();
        tx.finalize(&revaultds[0].secp_ctx).unwrap();
        for revaultd in &revaultds {
            assert!(check_spend_signatures(
                &revaultd.secp_ctx,
                managers_pubkeys.len(),
                &tx,
                managers_pubkeys.clone(),
                &vaults
            )
            .unwrap_err()
            .to_string()
            .contains(&SigError::InsaneTransaction.to_string()));
        }

        // Someone didn't sign here...
        let mut tx = SpendTransaction::from_psbt_str("cHNidP8BALQCAAAAAfvnQeptD/Ppkod15b290euvxLZ152fu+UG6SL6Sn/rKAwAAAAADAAAAA6BFAAAAAAAAIgAg4Phpb12z9E1dw2KEDZuzDVz5uaDrlq6HP/cOg88SDugA4fUFAAAAACIAIOD4aW9ds/RNXcNihA2bsw1c+bmg65auhz/3DoPPEg7o33DzBQAAAAAiACCnY5L/4eTY8hzj0np7MVKEyt1dZRcxr0us7BtOF3X7PAAAAAAAAQEr0KfpCwAAAAAiACDxHhkvHdl/8DtU5xns+0DOFIujmiWSqpg/6+gsJEWfZAEDBAEAAAABBaghAgZzDAVlWp/QRUVpNZiVCbFDihMIiSP7ko6y0OgbW+A5rFGHZHapFG+hL2VAtyZw6eaG++u9JiA/EEbeiKxrdqkURa5gCgAqc2UHtm9zS+o2k4DBgxyIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgAAQElIQJYONwJSgKF2+Ox+K8SgruNIwYM+5dbLzkhSvjfoCCjnaxRhwAAAQFHUiEC+5bLJ+gh+zKtPA2hHw3zTNIF18msZ9/4P1coFEvtoQUhAkMWjmB9+vixOk4+9wjjnCvdW1UJOH/LD9KIIloIiOJXUq4A").unwrap();
        let psbt = tx.psbt_mut();
        let mut cache = SigHashCache::new(&psbt.global.unsigned_tx);
        let prev_value = psbt.inputs[0].witness_utxo.as_ref().unwrap().value;
        let script_code = psbt.inputs[0].witness_script.as_ref().unwrap();
        let sighash = cache.signature_hash(0, &script_code, prev_value, SigHashType::All);
        let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
        for keychain in &manager_keychains[1..] {
            let mut sig = ctx.sign(&sighash, &keychain.0.key).serialize_der().to_vec();
            sig.push(SigHashType::All as u8);
            psbt.inputs[0].partial_sigs.insert(keychain.1, sig.clone());
        }
        for revaultd in &revaultds {
            assert!(check_spend_signatures(
                &revaultd.secp_ctx,
                managers_pubkeys.len(),
                &tx,
                managers_pubkeys.clone(),
                &vaults
            )
            .unwrap_err()
            .to_string()
            .contains(
                &SigError::NotEnoughSignatures(managers_pubkeys.len(), managers_pubkeys.len() - 1)
                    .to_string()
            ));
        }

        // An empty signature?! Wtf?!
        let mut tx = SpendTransaction::from_psbt_str("cHNidP8BALQCAAAAAfvnQeptD/Ppkod15b290euvxLZ152fu+UG6SL6Sn/rKAwAAAAADAAAAA6BFAAAAAAAAIgAg4Phpb12z9E1dw2KEDZuzDVz5uaDrlq6HP/cOg88SDugA4fUFAAAAACIAIOD4aW9ds/RNXcNihA2bsw1c+bmg65auhz/3DoPPEg7o33DzBQAAAAAiACCnY5L/4eTY8hzj0np7MVKEyt1dZRcxr0us7BtOF3X7PAAAAAAAAQEr0KfpCwAAAAAiACDxHhkvHdl/8DtU5xns+0DOFIujmiWSqpg/6+gsJEWfZAEDBAEAAAABBaghAgZzDAVlWp/QRUVpNZiVCbFDihMIiSP7ko6y0OgbW+A5rFGHZHapFG+hL2VAtyZw6eaG++u9JiA/EEbeiKxrdqkURa5gCgAqc2UHtm9zS+o2k4DBgxyIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgAAQElIQJYONwJSgKF2+Ox+K8SgruNIwYM+5dbLzkhSvjfoCCjnaxRhwAAAQFHUiEC+5bLJ+gh+zKtPA2hHw3zTNIF18msZ9/4P1coFEvtoQUhAkMWjmB9+vixOk4+9wjjnCvdW1UJOH/LD9KIIloIiOJXUq4A").unwrap();
        let psbt = tx.psbt_mut();
        psbt.inputs[0]
            .partial_sigs
            .insert(manager_keychains[0].1, vec![]);
        for revaultd in &revaultds {
            assert!(check_spend_signatures(
                &revaultd.secp_ctx,
                managers_pubkeys.len(),
                &tx,
                vec![managers_pubkeys[0].clone()],
                &vaults,
            )
            .unwrap_err()
            .to_string()
            .contains(&SigError::InvalidLength.to_string()));
        }

        // I signed with the right sighash_type but pushed the wrong one
        let mut tx = SpendTransaction::from_psbt_str("cHNidP8BALQCAAAAAfvnQeptD/Ppkod15b290euvxLZ152fu+UG6SL6Sn/rKAwAAAAADAAAAA6BFAAAAAAAAIgAg4Phpb12z9E1dw2KEDZuzDVz5uaDrlq6HP/cOg88SDugA4fUFAAAAACIAIOD4aW9ds/RNXcNihA2bsw1c+bmg65auhz/3DoPPEg7o33DzBQAAAAAiACCnY5L/4eTY8hzj0np7MVKEyt1dZRcxr0us7BtOF3X7PAAAAAAAAQEr0KfpCwAAAAAiACDxHhkvHdl/8DtU5xns+0DOFIujmiWSqpg/6+gsJEWfZAEDBAEAAAABBaghAgZzDAVlWp/QRUVpNZiVCbFDihMIiSP7ko6y0OgbW+A5rFGHZHapFG+hL2VAtyZw6eaG++u9JiA/EEbeiKxrdqkURa5gCgAqc2UHtm9zS+o2k4DBgxyIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgAAQElIQJYONwJSgKF2+Ox+K8SgruNIwYM+5dbLzkhSvjfoCCjnaxRhwAAAQFHUiEC+5bLJ+gh+zKtPA2hHw3zTNIF18msZ9/4P1coFEvtoQUhAkMWjmB9+vixOk4+9wjjnCvdW1UJOH/LD9KIIloIiOJXUq4A").unwrap();
        let psbt = tx.psbt_mut();
        let mut cache = SigHashCache::new(&psbt.global.unsigned_tx);
        let prev_value = psbt.inputs[0].witness_utxo.as_ref().unwrap().value;
        let script_code = psbt.inputs[0].witness_script.as_ref().unwrap();
        let wrong_sighash = cache.signature_hash(0, &script_code, prev_value, SigHashType::All);
        let wrong_sighash = secp256k1::Message::from_slice(&wrong_sighash).unwrap();
        for keychain in &manager_keychains {
            let mut wrong_sig = ctx
                .sign(&wrong_sighash, &keychain.0.key)
                .serialize_der()
                .to_vec();
            wrong_sig.push(SigHashType::AllPlusAnyoneCanPay as u8);
            psbt.inputs[0].partial_sigs.insert(keychain.1, wrong_sig);
        }
        for revaultd in &revaultds {
            assert!(check_spend_signatures(
                &revaultd.secp_ctx,
                managers_pubkeys.len(),
                &tx,
                managers_pubkeys.clone(),
                &vaults
            )
            .unwrap_err()
            .to_string()
            .contains(&SigError::InvalidSighash.to_string()));
        }

        // I signed with the wrong sighash_type but pushed the right one
        let mut tx = SpendTransaction::from_psbt_str("cHNidP8BALQCAAAAAfvnQeptD/Ppkod15b290euvxLZ152fu+UG6SL6Sn/rKAwAAAAADAAAAA6BFAAAAAAAAIgAg4Phpb12z9E1dw2KEDZuzDVz5uaDrlq6HP/cOg88SDugA4fUFAAAAACIAIOD4aW9ds/RNXcNihA2bsw1c+bmg65auhz/3DoPPEg7o33DzBQAAAAAiACCnY5L/4eTY8hzj0np7MVKEyt1dZRcxr0us7BtOF3X7PAAAAAAAAQEr0KfpCwAAAAAiACDxHhkvHdl/8DtU5xns+0DOFIujmiWSqpg/6+gsJEWfZAEDBAEAAAABBaghAgZzDAVlWp/QRUVpNZiVCbFDihMIiSP7ko6y0OgbW+A5rFGHZHapFG+hL2VAtyZw6eaG++u9JiA/EEbeiKxrdqkURa5gCgAqc2UHtm9zS+o2k4DBgxyIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgAAQElIQJYONwJSgKF2+Ox+K8SgruNIwYM+5dbLzkhSvjfoCCjnaxRhwAAAQFHUiEC+5bLJ+gh+zKtPA2hHw3zTNIF18msZ9/4P1coFEvtoQUhAkMWjmB9+vixOk4+9wjjnCvdW1UJOH/LD9KIIloIiOJXUq4A").unwrap();
        let psbt = tx.psbt_mut();
        let mut cache = SigHashCache::new(&psbt.global.unsigned_tx);
        let prev_value = psbt.inputs[0].witness_utxo.as_ref().unwrap().value;
        let script_code = psbt.inputs[0].witness_script.as_ref().unwrap();
        let wrong_sighash = cache.signature_hash(
            0,
            &script_code,
            prev_value,
            SigHashType::AllPlusAnyoneCanPay,
        );
        let wrong_sighash = secp256k1::Message::from_slice(&wrong_sighash).unwrap();
        for keychain in &manager_keychains {
            let mut wrong_sig = ctx
                .sign(&wrong_sighash, &keychain.0.key)
                .serialize_der()
                .to_vec();
            wrong_sig.push(SigHashType::All as u8);
            psbt.inputs[0].partial_sigs.insert(keychain.1, wrong_sig);
        }
        for revaultd in &revaultds {
            assert!(check_spend_signatures(
                &revaultd.secp_ctx,
                managers_pubkeys.len(),
                &tx,
                managers_pubkeys.clone(),
                &vaults
            )
            .unwrap_err()
            .to_string()
            .contains("Signature verification error"));
        }

        // The signature is correct, but signed by another key
        let mut tx = SpendTransaction::from_psbt_str("cHNidP8BALQCAAAAAfvnQeptD/Ppkod15b290euvxLZ152fu+UG6SL6Sn/rKAwAAAAADAAAAA6BFAAAAAAAAIgAg4Phpb12z9E1dw2KEDZuzDVz5uaDrlq6HP/cOg88SDugA4fUFAAAAACIAIOD4aW9ds/RNXcNihA2bsw1c+bmg65auhz/3DoPPEg7o33DzBQAAAAAiACCnY5L/4eTY8hzj0np7MVKEyt1dZRcxr0us7BtOF3X7PAAAAAAAAQEr0KfpCwAAAAAiACDxHhkvHdl/8DtU5xns+0DOFIujmiWSqpg/6+gsJEWfZAEDBAEAAAABBaghAgZzDAVlWp/QRUVpNZiVCbFDihMIiSP7ko6y0OgbW+A5rFGHZHapFG+hL2VAtyZw6eaG++u9JiA/EEbeiKxrdqkURa5gCgAqc2UHtm9zS+o2k4DBgxyIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgAAQElIQJYONwJSgKF2+Ox+K8SgruNIwYM+5dbLzkhSvjfoCCjnaxRhwAAAQFHUiEC+5bLJ+gh+zKtPA2hHw3zTNIF18msZ9/4P1coFEvtoQUhAkMWjmB9+vixOk4+9wjjnCvdW1UJOH/LD9KIIloIiOJXUq4A").unwrap();
        let psbt = tx.psbt_mut();
        let mut cache = SigHashCache::new(&psbt.global.unsigned_tx);
        let prev_value = psbt.inputs[0].witness_utxo.as_ref().unwrap().value;
        let script_code = psbt.inputs[0].witness_script.as_ref().unwrap();
        let sighash = cache.signature_hash(0, &script_code, prev_value, SigHashType::All);
        let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
        let mut sig = ctx
            .sign(&sighash, &manager_keychains[0].0.key)
            .serialize_der()
            .to_vec();
        sig.push(SigHashType::All as u8);
        psbt.inputs[0]
            .partial_sigs
            .insert(manager_keychains[1].1, sig.clone());
        for revaultd in &revaultds {
            assert!(check_spend_signatures(
                &revaultd.secp_ctx,
                managers_pubkeys.len(),
                &tx,
                vec![managers_pubkeys[1].clone()],
                &vaults,
            )
            .unwrap_err()
            .to_string()
            .contains("Signature verification error"));
        }

        // The signature is correct, but signs a completely different message
        let mut tx = SpendTransaction::from_psbt_str("cHNidP8BALQCAAAAAfvnQeptD/Ppkod15b290euvxLZ152fu+UG6SL6Sn/rKAwAAAAADAAAAA6BFAAAAAAAAIgAg4Phpb12z9E1dw2KEDZuzDVz5uaDrlq6HP/cOg88SDugA4fUFAAAAACIAIOD4aW9ds/RNXcNihA2bsw1c+bmg65auhz/3DoPPEg7o33DzBQAAAAAiACCnY5L/4eTY8hzj0np7MVKEyt1dZRcxr0us7BtOF3X7PAAAAAAAAQEr0KfpCwAAAAAiACDxHhkvHdl/8DtU5xns+0DOFIujmiWSqpg/6+gsJEWfZAEDBAEAAAABBaghAgZzDAVlWp/QRUVpNZiVCbFDihMIiSP7ko6y0OgbW+A5rFGHZHapFG+hL2VAtyZw6eaG++u9JiA/EEbeiKxrdqkURa5gCgAqc2UHtm9zS+o2k4DBgxyIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgAAQElIQJYONwJSgKF2+Ox+K8SgruNIwYM+5dbLzkhSvjfoCCjnaxRhwAAAQFHUiEC+5bLJ+gh+zKtPA2hHw3zTNIF18msZ9/4P1coFEvtoQUhAkMWjmB9+vixOk4+9wjjnCvdW1UJOH/LD9KIIloIiOJXUq4A").unwrap();
        let psbt = tx.psbt_mut();
        let wrong_msg = secp256k1::Message::from_slice(&[1; 32]).unwrap();
        let mut sig = ctx
            .sign(&wrong_msg, &manager_keychains[0].0.key)
            .serialize_der()
            .to_vec();
        sig.push(SigHashType::All as u8);
        psbt.inputs[0]
            .partial_sigs
            .insert(manager_keychains[0].1, sig.clone());
        for revaultd in &revaultds {
            assert!(check_spend_signatures(
                &revaultd.secp_ctx,
                managers_pubkeys.len(),
                &tx,
                vec![managers_pubkeys[0].clone()],
                &vaults,
            )
            .unwrap_err()
            .to_string()
            .contains("Signature verification error"));
        }
    }

    #[test]
    #[should_panic(expected = "Must be present")]
    fn test_check_spend_signatures_panic() {
        let datadir = test_datadir();
        let revaultd = dummy_revaultd(datadir, UserRole::ManagerStakeholder);

        // check_spend_signatures will panic if db_vaults doesn't contain an entry
        // for each input
        let tx = SpendTransaction::from_psbt_str("cHNidP8BAKgCAAAAARU919uuOZ2HHyRUrQsCrT2s98u7j8/xW6DXMzO7+eYFAAAAAAADAAAAA6BCAAAAAAAAIgAg4Phpb12z9E1dw2KEDZuzDVz5uaDrlq6HP/cOg88SDuiAlpgAAAAAABYAFPAj0esIbomyGAolRR1U/vYas0RxhspQCwAAAAAiACCnY5L/4eTY8hzj0np7MVKEyt1dZRcxr0us7BtOF3X7PAAAAAAAAQEr0KfpCwAAAAAiACDxHhkvHdl/8DtU5xns+0DOFIujmiWSqpg/6+gsJEWfZAEDBAEAAAABBaghAgZzDAVlWp/QRUVpNZiVCbFDihMIiSP7ko6y0OgbW+A5rFGHZHapFG+hL2VAtyZw6eaG++u9JiA/EEbeiKxrdqkURa5gCgAqc2UHtm9zS+o2k4DBgxyIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgAAQElIQJYONwJSgKF2+Ox+K8SgruNIwYM+5dbLzkhSvjfoCCjnaxRhwAAAQFHUiEC+5bLJ+gh+zKtPA2hHw3zTNIF18msZ9/4P1coFEvtoQUhAkMWjmB9+vixOk4+9wjjnCvdW1UJOH/LD9KIIloIiOJXUq4A").unwrap();
        check_spend_signatures(&revaultd.secp_ctx, 0, &tx, vec![], &HashMap::new()).unwrap();
    }
}
