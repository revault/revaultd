//! This module contains routines for controlling our actions (checking signatures, communicating
//! with servers, with bitcoind, ..). Requests may originate from the RPC server or the signature
//! fetcher thread.

use crate::daemon::{
    bitcoind::BitcoindError,
    database::{
        interface::{
            db_cancel_transaction, db_emer_transaction, db_signed_emer_txs, db_signed_unemer_txs,
            db_unvault_emer_transaction, db_unvault_transaction, db_vault_by_deposit, db_vaults,
        },
        schema::{DbTransaction, DbVault},
        DatabaseError,
    },
    revaultd::{RevaultD, VaultStatus},
    threadmessages::*,
};

use revault_net::{
    message::{
        coordinator::{GetSigs, SetSpendResult, SetSpendTx, Sig, SigResult, Sigs},
        cosigner::{SignRequest, SignResult},
    },
    transport::KKTransport,
};
use revault_tx::{
    bitcoin::{
        consensus::encode, hashes::hex::ToHex, secp256k1, util::bip32::ChildNumber, Address,
        Amount, OutPoint, Transaction as BitcoinTransaction, Txid,
    },
    miniscript::DescriptorTrait,
    transactions::{
        CancelTransaction, EmergencyTransaction, RevaultTransaction, SpendTransaction,
        UnvaultEmergencyTransaction, UnvaultTransaction,
    },
};

use std::{
    collections::BTreeMap,
    fmt,
    sync::{mpsc::Sender, Arc, RwLock},
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

#[derive(Debug, Serialize)]
pub struct ServerStatus {
    pub host: String,
    pub reachable: bool,
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
    /// An error returned when, given a previous poll of the state of the vault
    /// in database a certain pre-signed transaction should be present but it was
    /// not. Could be due to another thread wiping all the txs due to for instance
    /// a block chain reorg.
    TransactionNotFound,
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
            Self::TransactionNotFound => write!(
                f,
                "Transaction not found although it should have been in database"
            ),
        }
    }
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

        let unvault_psbt = db_unvault_transaction(db_path, db_vault.id)?
            .ok_or(RpcControlError::TransactionNotFound)?
            .psbt
            .assert_unvault();
        let mut finalized_unvault = unvault_psbt.clone();
        let unvault = VaultPresignedTransaction {
            transaction: if finalized_unvault.finalize(&revaultd.secp_ctx).is_ok() {
                Some(finalized_unvault.into_psbt().extract_tx())
            } else {
                None
            },
            psbt: unvault_psbt,
        };

        let cancel_db_tx = db_cancel_transaction(db_path, db_vault.id)?
            .ok_or(RpcControlError::TransactionNotFound)?;
        let cancel_psbt = cancel_db_tx.psbt.assert_cancel();
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
            let emer_db_tx = db_emer_transaction(db_path, db_vault.id)?
                .ok_or(RpcControlError::TransactionNotFound)?;
            let emer_psbt = emer_db_tx.psbt.assert_emer();
            let mut finalized_emer = emer_psbt.clone();
            emergency = Some(VaultPresignedTransaction {
                transaction: if finalized_emer.finalize(&revaultd.secp_ctx).is_ok() {
                    Some(finalized_emer.into_psbt().extract_tx())
                } else {
                    None
                },
                psbt: emer_psbt,
            });

            let unemer_db_tx = db_unvault_emer_transaction(db_path, db_vault.id)?
                .ok_or(RpcControlError::TransactionNotFound)?;
            let unemer_psbt = unemer_db_tx.psbt.assert_unvault_emer();
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
pub fn onchain_txs<T: BitcoindThread>(
    revaultd: &RevaultD,
    bitcoind_conn: &T,
    db_vaults: Vec<DbVault>,
) -> Result<Vec<VaultOnchainTransactions>, RpcControlError> {
    let db_path = &revaultd.db_file();

    let mut tx_list = Vec::with_capacity(db_vaults.len());
    for db_vault in db_vaults {
        let outpoint = db_vault.deposit_outpoint;

        // If the vault exist, there must always be a deposit transaction available.
        let deposit = bitcoind_conn
            .wallet_tx(db_vault.deposit_outpoint.txid)?
            .expect("Vault exists but not deposit tx?");

        // For the other transactions, it depends on the status of the vault. For the sake of
        // simplicity bitcoind will tell us (but we could have some optimisation eventually here,
        // eg returning None early on Funded vaults).
        let (unvault, cancel, emergency, unvault_emergency, spend) = match db_vault.status {
            VaultStatus::Unvaulting | VaultStatus::Unvaulted => {
                let unvault_db_tx = db_unvault_transaction(db_path, db_vault.id)?
                    .ok_or(RpcControlError::TransactionNotFound)?;
                let unvault = bitcoind_conn.wallet_tx(unvault_db_tx.psbt.txid())?;
                (unvault, None, None, None, None)
            }
            VaultStatus::Spending | VaultStatus::Spent => {
                let unvault_db_tx = db_unvault_transaction(db_path, db_vault.id)?
                    .ok_or(RpcControlError::TransactionNotFound)?;
                let unvault = bitcoind_conn.wallet_tx(unvault_db_tx.psbt.txid())?;
                let spend = if let Some(spend_txid) = db_vault.final_txid {
                    bitcoind_conn.wallet_tx(spend_txid)?
                } else {
                    None
                };
                (unvault, None, None, None, spend)
            }
            VaultStatus::Canceling | VaultStatus::Canceled => {
                let unvault_db_tx = db_unvault_transaction(db_path, db_vault.id)?
                    .ok_or(RpcControlError::TransactionNotFound)?;
                let unvault = bitcoind_conn.wallet_tx(unvault_db_tx.psbt.txid())?;
                let cancel = if let Some(cancel_txid) = db_vault.final_txid {
                    bitcoind_conn.wallet_tx(cancel_txid)?
                } else {
                    None
                };
                (unvault, cancel, None, None, None)
            }
            VaultStatus::EmergencyVaulting | VaultStatus::EmergencyVaulted => {
                // Emergencies are only for stakeholders!
                if revaultd.is_stakeholder() {
                    let emer_db_tx = db_emer_transaction(db_path, db_vault.id)?
                        .ok_or(RpcControlError::TransactionNotFound)?;
                    let emergency = bitcoind_conn.wallet_tx(emer_db_tx.psbt.txid())?;
                    (None, None, emergency, None, None)
                } else {
                    (None, None, None, None, None)
                }
            }
            VaultStatus::UnvaultEmergencyVaulting | VaultStatus::UnvaultEmergencyVaulted => {
                let unvault_db_tx = db_unvault_transaction(db_path, db_vault.id)?
                    .ok_or(RpcControlError::TransactionNotFound)?;
                let unvault = bitcoind_conn.wallet_tx(unvault_db_tx.psbt.txid())?;

                // Emergencies are only for stakeholders!
                if revaultd.is_stakeholder() {
                    let unemer_db_tx = db_emer_transaction(db_path, db_vault.id)?
                        .ok_or(RpcControlError::TransactionNotFound)?;
                    let unvault_emergency = bitcoind_conn.wallet_tx(unemer_db_tx.psbt.txid())?;
                    (unvault, None, None, unvault_emergency, None)
                } else {
                    (unvault, None, None, None, None)
                }
            }
            // Other statuses do not have on chain transactions apart the deposit.
            VaultStatus::Unconfirmed
            | VaultStatus::Funded
            | VaultStatus::Securing
            | VaultStatus::Secured
            | VaultStatus::Activating
            | VaultStatus::Active => (None, None, None, None, None),
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
    sigs: BTreeMap<secp256k1::PublicKey, secp256k1::Signature>,
) -> Result<(), CommunicationError> {
    for (pubkey, signature) in sigs {
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
    coordinator_host: std::net::SocketAddr,
    noise_secret: &revault_net::noise::SecretKey,
    coordinator_noisekey: &revault_net::noise::PublicKey,
    rev_txs: &[DbTransaction],
) -> Result<(), CommunicationError> {
    let mut transport = KKTransport::connect(coordinator_host, noise_secret, coordinator_noisekey)?;

    for tx in rev_txs {
        send_sig_msg(&mut transport, tx.psbt.txid(), tx.psbt.signatures())?;
    }

    Ok(())
}

/// Send the unvault signature to the Coordinator
pub fn share_unvault_signatures(
    coordinator_host: std::net::SocketAddr,
    noise_secret: &revault_net::noise::SecretKey,
    coordinator_noisekey: &revault_net::noise::PublicKey,
    unvault_tx: &DbTransaction,
) -> Result<(), CommunicationError> {
    let mut transport = KKTransport::connect(coordinator_host, noise_secret, coordinator_noisekey)?;

    send_sig_msg(
        &mut transport,
        unvault_tx.psbt.txid(),
        unvault_tx.psbt.signatures(),
    )
}

// A hack to workaround the immutability of the SpendTransaction.
// FIXME: should probably have a helper in revault_tx instead?
fn strip_signatures(spend_tx: SpendTransaction) -> SpendTransaction {
    let mut psbt = spend_tx.into_psbt();
    for psbtin in psbt.inputs.iter_mut() {
        psbtin.partial_sigs.clear();
    }
    SpendTransaction::from_raw_psbt(&encode::serialize(&psbt)).expect("We just deserialized it")
}

/// Make the cosigning servers sign this Spend transaction.
/// This method checks that the signatures are valid, but it doesn't
/// check that the cosigners are returning signatures in the first place.
pub fn fetch_cosigs_signatures<C: secp256k1::Verification>(
    secp: &secp256k1::Secp256k1<C>,
    noise_secret: &revault_net::noise::SecretKey,
    spend_tx: &mut SpendTransaction,
    cosigs: &[(std::net::SocketAddr, revault_net::noise::PublicKey)],
) -> Result<(), CommunicationError> {
    // Strip the signatures before polling the Cosigning Server. It does not check them
    // anyways, and it makes us hit the Noise message size limit fairly quickly.
    let tx = strip_signatures(spend_tx.clone());
    let msg = SignRequest { tx };
    log::trace!(
        "Prepared msg to fetch cosigning servers signatures: '{:?}'",
        msg
    );

    for (host, noise_key) in cosigs {
        // FIXME: connect should take a reference... This copy is useless
        let mut transport = KKTransport::connect(*host, noise_secret, noise_key)?;
        log::debug!(
            "Polling cosigning server at '{}' (key: '{}') for spend '{}'",
            host,
            noise_key.0.to_hex(),
            spend_tx.txid(),
        );

        let sign_res: SignResult = transport.send_req(&msg.clone().into())?;
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
                    .add_signature(i, key.key, sig, secp)
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
    let tx = base64::encode(encode::serialize(&tx));
    let msg = serde_json::to_string(&serde_json::json!( {
        "deposit_outpoints": deposit_outpoints,
        "transaction": tx,
    }))
    .expect("JSON created inline");
    return msg.len() <= revault_net::noise::NOISE_PLAINTEXT_MAX_SIZE;
}

/// Sends the spend transaction for a certain outpoint to the coordinator
pub fn announce_spend_transaction(
    coordinator_host: std::net::SocketAddr,
    noise_secret: &revault_net::noise::SecretKey,
    coordinator_noisekey: &revault_net::noise::PublicKey,
    spend_tx: SpendTransaction,
    deposit_outpoints: Vec<OutPoint>,
) -> Result<(), CommunicationError> {
    let mut transport = KKTransport::connect(coordinator_host, noise_secret, coordinator_noisekey)?;

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
    coordinator_host: std::net::SocketAddr,
    noise_secret: &revault_net::noise::SecretKey,
    coordinator_noisekey: &revault_net::noise::PublicKey,
    txid: Txid,
) -> Result<BTreeMap<secp256k1::PublicKey, secp256k1::Signature>, CommunicationError> {
    let getsigs_msg = GetSigs { id: txid };
    let mut transport =
        KKTransport::connect(coordinator_host, &noise_secret, &coordinator_noisekey)?;

    log::debug!("Sending to sync server: '{:?}'", getsigs_msg,);
    let resp: Sigs = transport.send_req(&getsigs_msg.into())?;
    log::debug!("Got sigs {:?} from coordinator.", resp);

    Ok(resp.signatures)
}

pub fn coordinator_status(revaultd: &RevaultD) -> ServerStatus {
    let reachable = KKTransport::connect(
        revaultd.coordinator_host,
        &revaultd.noise_secret,
        &revaultd.coordinator_noisekey,
    )
    .is_ok();

    ServerStatus {
        host: revaultd.coordinator_host.to_string(),
        reachable,
    }
}

pub fn cosigners_status(revaultd: &RevaultD) -> Vec<ServerStatus> {
    let mut cosigners = Vec::new();
    if let Some(c) = &revaultd.cosigs {
        for (host, key) in c {
            let reachable = KKTransport::connect(*host, &revaultd.noise_secret, &key).is_ok();

            cosigners.push(ServerStatus {
                host: host.to_string(),
                reachable,
            });
        }
    }
    cosigners
}

pub fn watchtowers_status(revaultd: &RevaultD) -> Vec<ServerStatus> {
    let mut watchtowers = Vec::new();
    if let Some(w) = &revaultd.watchtowers {
        for (host, key) in w {
            let reachable = KKTransport::connect(*host, &revaultd.noise_secret, &key).is_ok();

            watchtowers.push(ServerStatus {
                host: host.to_string(),
                reachable,
            });
        }
    }

    watchtowers
}

#[derive(Clone)]
pub struct RpcUtils {
    pub revaultd: Arc<RwLock<RevaultD>>,
    pub bitcoind_conn: BitcoindSender,
    pub bitcoind_thread: Arc<RwLock<JoinHandle<()>>>,
    pub sigfetcher_tx: Sender<SigFetcherMessageOut>,
    pub sigfetcher_thread: Arc<RwLock<JoinHandle<()>>>,
}

#[cfg(test)]
mod test {
    use crate::daemon::{
        control::*,
        database::{
            actions::{
                db_confirm_deposit, db_confirm_unvault, db_insert_new_unconfirmed_vault,
                db_update_presigned_txs,
            },
            bitcointx::{RevaultTx, TransactionType},
            interface::{
                db_cancel_transaction, db_emer_transaction, db_exec, db_unvault_emer_transaction,
                db_unvault_transaction, db_vault_by_deposit,
            },
            schema::{DbTransaction, DbVault},
        },
        jsonrpc::UserRole,
        revaultd::{RevaultD, VaultStatus},
        setup_db,
        utils::test_utils::{dummy_revaultd, test_datadir},
    };
    use revault_net::{
        message, sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::gen_keypair,
        transport::KKTransport,
    };
    use revault_tx::{
        bitcoin::{
            blockdata::transaction::OutPoint,
            hash_types::Txid,
            hashes::hex::FromHex,
            network::constants::Network,
            secp256k1,
            util::{amount::Amount, bip32::ChildNumber},
            PrivateKey as BitcoinPrivKey, PublicKey as BitcoinPubKey, SigHashType,
        },
        transactions::{
            CancelTransaction, EmergencyTransaction, RevaultTransaction, SpendTransaction,
            UnvaultEmergencyTransaction, UnvaultTransaction,
        },
    };
    use rusqlite::params;
    use std::{collections::BTreeMap, fs, net::TcpListener, str::FromStr, thread};

    #[test]
    fn test_check_spend_transaction_size() {
        let datadir = test_datadir();
        let revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);
        // One input, three outputs, 2 stakeholders and 1 manager psbt. No problem.
        let tx = SpendTransaction::from_psbt_str("cHNidP8BAKgCAAAAAWQYLaJLKOGr2VUPYwlZz5UStWUr7SlxGT+K8S8ubTM1AAAAAAADAAAAA6BCAAAAAAAAIgAg6eJKGnlvCyzkIYItHMBwQDkooqkNDi9RvlVWyl+rYTGA8PoCAAAAABYAFCgf4ZTSb/CpYwWa+Wp0yRMIJoVYf4D4AgAAAAAiACB18mkXdMgWd4MYRrAoIgDiiLLFlxC1j3Qxg9SSVQfbxQAAAAAAAQErybfzBQAAAAAiACCoQFnKMvBMFQZ1py8aLwPpRU6pUCx/LKGU9VMp//zoOwEDBAEAAAABBaghAgKTOrEDfq0KpKeFjG1J1nBeH7O8X2awCRive58A7NUmrFGHZHapFHKpXyKvmhuuuFL5qVJy+MIdmPJkiKxrdqkUtsmtuJyMk3Jsg+KhtdlHidd7lWGIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgiBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAABASUhArXfbep+EQfvIyrGWjExA5/HHtWFmuXnOyjwlF2SEF8frFGHIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQFHUiECWC3tv0T0ZWTl2M2wZ1NtYOvjTNHRgBz/Ubv516wom0MhA0cE3stVtaqI/9HvXQY2YkjBMU4ZZVETb/FOq4u6SkkOUq4iAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap();
        assert!(check_spend_transaction_size(&revaultd, tx));
        let tx = SpendTransaction::from_psbt_str("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").unwrap();
        assert!(!check_spend_transaction_size(&revaultd, tx));

        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
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

    fn update_presigned_tx<C>(
        db_path: &std::path::PathBuf,
        db_vault: &DbVault,
        mut db_tx: DbTransaction,
        sigs: &BTreeMap<BitcoinPubKey, Vec<u8>>,
        secp: &secp256k1::Secp256k1<C>,
    ) where
        C: secp256k1::Verification,
    {
        for (key, sig) in sigs {
            let sig = secp256k1::Signature::from_der(&sig[..sig.len() - 1]).unwrap();
            match db_tx.psbt {
                RevaultTx::Unvault(ref mut tx) => {
                    tx.add_signature(0, key.key, sig, secp).unwrap();
                }
                RevaultTx::Cancel(ref mut tx) => {
                    tx.add_signature(0, key.key, sig, secp).unwrap();
                }
                RevaultTx::Emergency(ref mut tx) => {
                    tx.add_signature(0, key.key, sig, secp).unwrap();
                }
                RevaultTx::UnvaultEmergency(ref mut tx) => {
                    tx.add_signature(0, key.key, sig, secp).unwrap();
                }
            }
        }
        db_update_presigned_txs(db_path, db_vault, vec![db_tx], secp).unwrap();
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
                CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAASDOvhSZlTSEcEoUq/CT7Cg3ILtc6sqt5qJKvAMq+LbIAAAAAAD9////AXYfpDUAAAAAIgAg9AncsIZc8g7mJdfT9infAeWlqjtxBs93ireDGnQn/DYAAAAAAAEBK7hhpDUAAAAAIgAgFZlOQkpDkFSsLUfyeMGVAOT3T88jZM7L/XlVZoJ2jnABAwSBAAAAAQWpIQMVlEoh50lasMhcdwnrmnCp2ROlGY5CrH+HtxQmfZDZ06xRh2R2qRS/INUX1CaP7Pbn5GmtGYu2wgqjnIisa3apFO/kceq8yo9w69g4VVtlFAf739qTiKxsk1KHZ1IhAnddfXi3N38A+aEQ74sUdeuV7sg+2L3ijTjMHMEAfq3cIQLWP96FqjfC5qKQkC2WhYbbLJx1FbNSAjsnMfwDnK0jD1KvARKyaCIGAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBR1IhA47+JRqdt+oloFosla9hWUYVf5YQKDbuq4KO13JS45KgIQMKcLWzABxb/9YBQe+bJRW3v3om8S2LNMGUKSp5K+PQ+1KuIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap(),
                final_cancel: None,
                initial_unvault:
                UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAajRZE5yVgzG9McmOyy/WdcYdrGrK15bB5N/Hg8zhKOkAQAAAAD9////ArhhpDUAAAAAIgAgFZlOQkpDkFSsLUfyeMGVAOT3T88jZM7L/XlVZoJ2jnAwdQAAAAAAACIAILKCCA/RbV3QMPMrwwQmk4Ark4w1WyElM27WtBgftq6ZAAAAAAABASsA6aQ1AAAAACIAIPQJ3LCGXPIO5iXX0/Yp3wHlpao7cQbPd4q3gxp0J/w2AQMEAQAAAAEFR1IhA47+JRqdt+oloFosla9hWUYVf5YQKDbuq4KO13JS45KgIQMKcLWzABxb/9YBQe+bJRW3v3om8S2LNMGUKSp5K+PQ+1KuIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQGpIQMVlEoh50lasMhcdwnrmnCp2ROlGY5CrH+HtxQmfZDZ06xRh2R2qRS/INUX1CaP7Pbn5GmtGYu2wgqjnIisa3apFO/kceq8yo9w69g4VVtlFAf739qTiKxsk1KHZ1IhAnddfXi3N38A+aEQ74sUdeuV7sg+2L3ijTjMHMEAfq3cIQLWP96FqjfC5qKQkC2WhYbbLJx1FbNSAjsnMfwDnK0jD1KvARKyaCICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBJSEDjv4lGp236iWgWiyVr2FZRhV/lhAoNu6rgo7XclLjkqCsUYciAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap(),
                final_unvault: None,
                initial_emer:
                EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAajRZE5yVgzG9McmOyy/WdcYdrGrK15bB5N/Hg8zhKOkAQAAAAD9////AXC1pDUAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBKwDppDUAAAAAIgAg9AncsIZc8g7mJdfT9infAeWlqjtxBs93ireDGnQn/DYBAwSBAAAAAQVHUiEDjv4lGp236iWgWiyVr2FZRhV/lhAoNu6rgo7XclLjkqAhAwpwtbMAHFv/1gFB75slFbe/eibxLYs0wZQpKnkr49D7Uq4iBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAAiAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap(),
                final_emer: None,
                initial_unvault_emer:
                UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAASDOvhSZlTSEcEoUq/CT7Cg3ILtc6sqt5qJKvAMq+LbIAAAAAAD9////AXYfpDUAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK7hhpDUAAAAAIgAgFZlOQkpDkFSsLUfyeMGVAOT3T88jZM7L/XlVZoJ2jnABAwSBAAAAAQWpIQMVlEoh50lasMhcdwnrmnCp2ROlGY5CrH+HtxQmfZDZ06xRh2R2qRS/INUX1CaP7Pbn5GmtGYu2wgqjnIisa3apFO/kceq8yo9w69g4VVtlFAf739qTiKxsk1KHZ1IhAnddfXi3N38A+aEQ74sUdeuV7sg+2L3ijTjMHMEAfq3cIQLWP96FqjfC5qKQkC2WhYbbLJx1FbNSAjsnMfwDnK0jD1KvARKyaCIGAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAACICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAA==").unwrap(),
                final_unvault_emer: None,
            }),
            Some(TestTransactions {
                initial_cancel:CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAAZ8pm+vF5rxGSF9+DGV18WMpOEDv45AC3cPpy+gzfBudAAAAAAD9////ARgJ46YAAAAAIgAgdfJpF3TIFneDGEawKCIA4oiyxZcQtY90MYPUklUH28UAAAAAAAEBK0RL46YAAAAAIgAgqEBZyjLwTBUGdacvGi8D6UVOqVAsfyyhlPVTKf/86DsBAwSBAAAAAQWoIQICkzqxA36tCqSnhYxtSdZwXh+zvF9msAkYr3ufAOzVJqxRh2R2qRRyqV8ir5obrrhS+alScvjCHZjyZIisa3apFLbJrbicjJNybIPiobXZR4nXe5VhiKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQFHUiECWC3tv0T0ZWTl2M2wZ1NtYOvjTNHRgBz/Ubv516wom0MhA0cE3stVtaqI/9HvXQY2YkjBMU4ZZVETb/FOq4u6SkkOUq4iAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap(),
                final_cancel: Some(CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAAZ8pm+vF5rxGSF9+DGV18WMpOEDv45AC3cPpy+gzfBudAAAAAAD9////ARgJ46YAAAAAIgAgdfJpF3TIFneDGEawKCIA4oiyxZcQtY90MYPUklUH28UAAAAAAAEBK0RL46YAAAAAIgAgqEBZyjLwTBUGdacvGi8D6UVOqVAsfyyhlPVTKf/86DsiAgJYLe2/RPRlZOXYzbBnU21g6+NM0dGAHP9Ru/nXrCibQ0gwRQIhAL944Kpjbgr9v1ehOvJoTagRD6mAscPvs1oQlZ7sAF4aAiBiV7TRvErwbFlKrWAgYJlmfpWpbOTqxELqU8LzwYX/r4EiAgNHBN7LVbWqiP/R710GNmJIwTFOGWVRE2/xTquLukpJDkgwRQIhAIhVSc83b0wHhtqHWnZYXs8/n5m/qoq+bUnHwr6rnLbeAiBdhfDlGBKIKvGgCsTqN6WswMXkOartdZFSjEGN1DL/CIEBAwSBAAAAAQWoIQICkzqxA36tCqSnhYxtSdZwXh+zvF9msAkYr3ufAOzVJqxRh2R2qRRyqV8ir5obrrhS+alScvjCHZjyZIisa3apFLbJrbicjJNybIPiobXZR4nXe5VhiKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQFHUiECWC3tv0T0ZWTl2M2wZ1NtYOvjTNHRgBz/Ubv516wom0MhA0cE3stVtaqI/9HvXQY2YkjBMU4ZZVETb/FOq4u6SkkOUq4iAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap()),
                initial_unvault: UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAYaXLfGg2dQ9K7Z5WCwqwckivsB0tbs/wct42zEuG0zsAAAAAAD9////AkRL46YAAAAAIgAgqEBZyjLwTBUGdacvGi8D6UVOqVAsfyyhlPVTKf/86DswdQAAAAAAACIAIOniShp5bwss5CGCLRzAcEA5KKKpDQ4vUb5VVspfq2ExAAAAAAABASuM0uOmAAAAACIAIHXyaRd0yBZ3gxhGsCgiAOKIssWXELWPdDGD1JJVB9vFAQMEAQAAAAEFR1IhAlgt7b9E9GVk5djNsGdTbWDr40zR0YAc/1G7+desKJtDIQNHBN7LVbWqiP/R710GNmJIwTFOGWVRE2/xTquLukpJDlKuIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQGoIQICkzqxA36tCqSnhYxtSdZwXh+zvF9msAkYr3ufAOzVJqxRh2R2qRRyqV8ir5obrrhS+alScvjCHZjyZIisa3apFLbJrbicjJNybIPiobXZR4nXe5VhiKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQElIQK1323qfhEH7yMqxloxMQOfxx7VhZrl5zso8JRdkhBfH6xRhyICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAA==").unwrap(),
                final_unvault: None,
                initial_emer:
                EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAYaXLfGg2dQ9K7Z5WCwqwckivsB0tbs/wct42zEuG0zsAAAAAAD9////Afye46YAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK4zS46YAAAAAIgAgdfJpF3TIFneDGEawKCIA4oiyxZcQtY90MYPUklUH28UBAwSBAAAAAQVHUiECWC3tv0T0ZWTl2M2wZ1NtYOvjTNHRgBz/Ubv516wom0MhA0cE3stVtaqI/9HvXQY2YkjBMU4ZZVETb/FOq4u6SkkOUq4iBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAAiAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap(),
                final_emer: Some(
                    EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAYaXLfGg2dQ9K7Z5WCwqwckivsB0tbs/wct42zEuG0zsAAAAAAD9////Afye46YAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK4zS46YAAAAAIgAgdfJpF3TIFneDGEawKCIA4oiyxZcQtY90MYPUklUH28UiAgJYLe2/RPRlZOXYzbBnU21g6+NM0dGAHP9Ru/nXrCibQ0gwRQIhAPByVLRaSE7sYQr2tRRs++nK/Ow/6ZIgdGR7mJ2Md2VPAiAqtn37t6/KOl3wsc6O+a1UdJka8G1JnkEAhUY6TcY7DoEiAgNHBN7LVbWqiP/R710GNmJIwTFOGWVRE2/xTquLukpJDkgwRQIhAMu1RAxu3m+CLdAm0eC9d2AprHmvpoNmS5scvEeBTKumAiAw0rBYkbFQfZzv/O6/BadoV/DdY9cP9Q7/zNQK2kJEg4EBAwSBAAAAAQVHUiECWC3tv0T0ZWTl2M2wZ1NtYOvjTNHRgBz/Ubv516wom0MhA0cE3stVtaqI/9HvXQY2YkjBMU4ZZVETb/FOq4u6SkkOUq4iBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAAiAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap(),
                ),
                initial_unvault_emer:
                UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAZ8pm+vF5rxGSF9+DGV18WMpOEDv45AC3cPpy+gzfBudAAAAAAD9////ARgJ46YAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK0RL46YAAAAAIgAgqEBZyjLwTBUGdacvGi8D6UVOqVAsfyyhlPVTKf/86DsBAwSBAAAAAQWoIQICkzqxA36tCqSnhYxtSdZwXh+zvF9msAkYr3ufAOzVJqxRh2R2qRRyqV8ir5obrrhS+alScvjCHZjyZIisa3apFLbJrbicjJNybIPiobXZR4nXe5VhiKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap(),
                final_unvault_emer: Some(
                    UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAZ8pm+vF5rxGSF9+DGV18WMpOEDv45AC3cPpy+gzfBudAAAAAAD9////ARgJ46YAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK0RL46YAAAAAIgAgqEBZyjLwTBUGdacvGi8D6UVOqVAsfyyhlPVTKf/86DsiAgJYLe2/RPRlZOXYzbBnU21g6+NM0dGAHP9Ru/nXrCibQ0cwRAIgIppqYDsvb77lOOqQgs+R/W67n+VX3R4KXhUZOk74GnECIHJpz4QA/xEly1k7SqJyxljbs+LbxqYzzIDHsigDAnzMgSICA0cE3stVtaqI/9HvXQY2YkjBMU4ZZVETb/FOq4u6SkkOSDBFAiEA5SYSLhIdcGaMHo/AFz9ED/BmfywQzw8YLgKjSCB3+koCIBpbFuA7EDvz34wDJ3tgLZNpPvUekBRfzuNtZu01xcDXgQEDBIEAAAABBaghAgKTOrEDfq0KpKeFjG1J1nBeH7O8X2awCRive58A7NUmrFGHZHapFHKpXyKvmhuuuFL5qVJy+MIdmPJkiKxrdqkUtsmtuJyMk3Jsg+KhtdlHidd7lWGIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgiBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAAiAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap(),
                ),
            }),
            Some(TestTransactions {
                initial_cancel:
                CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAARU919uuOZ2HHyRUrQsCrT2s98u7j8/xW6DXMzO7+eYFAAAAAAD9////AaRl6QsAAAAAIgAgp2OS/+Hk2PIc49J6ezFShMrdXWUXMa9LrOwbThd1+zwAAAAAAAEBK9Cn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QBAwSBAAAAAQWoIQIGcwwFZVqf0EVFaTWYlQmxQ4oTCIkj+5KOstDoG1vgOaxRh2R2qRRvoS9lQLcmcOnmhvvrvSYgPxBG3oisa3apFEWuYAoAKnNlB7Zvc0vqNpOAwYMciKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQFHUiEC+5bLJ+gh+zKtPA2hHw3zTNIF18msZ9/4P1coFEvtoQUhAkMWjmB9+vixOk4+9wjjnCvdW1UJOH/LD9KIIloIiOJXUq4iAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap(),
                final_cancel: Some(CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAARU919uuOZ2HHyRUrQsCrT2s98u7j8/xW6DXMzO7+eYFAAAAAAD9////AaRl6QsAAAAAIgAgp2OS/+Hk2PIc49J6ezFShMrdXWUXMa9LrOwbThd1+zwAAAAAAAEBK9Cn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QiAgJDFo5gffr4sTpOPvcI45wr3VtVCTh/yw/SiCJaCIjiV0cwRAIgV8fkyYpVObnygZ74ABmc53lQ2yCfEpQkSsMsUfT4OaICIHTBlPzAyZS0TTDE/+s9uFpsB7/W/s/E5qsJiV+7+j1xgSICAvuWyyfoIfsyrTwNoR8N80zSBdfJrGff+D9XKBRL7aEFSDBFAiEA3QWAAJ0kph9Igr9FMeIAjAhR9jzwvmXU77onyZJG7LkCICcPMk/ycmTKndDJxc7iiA3xBIUsim8cMc+XuuSfuvItgQEDBIEAAAABBaghAgZzDAVlWp/QRUVpNZiVCbFDihMIiSP7ko6y0OgbW+A5rFGHZHapFG+hL2VAtyZw6eaG++u9JiA/EEbeiKxrdqkURa5gCgAqc2UHtm9zS+o2k4DBgxyIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgiBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAABAUdSIQL7lssn6CH7Mq08DaEfDfNM0gXXyaxn3/g/VygUS+2hBSECQxaOYH36+LE6Tj73COOcK91bVQk4f8sP0ogiWgiI4ldSriICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAA==").unwrap()),
                initial_unvault:
                UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAUaovJQUhwegF7P9qJBrWxtPq7dcJVPZ8MTjp9v8LUoDAAAAAAD9////AtCn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QwdQAAAAAAACIAIOD4aW9ds/RNXcNihA2bsw1c+bmg65auhz/3DoPPEg7oAAAAAAABASsYL+oLAAAAACIAIKdjkv/h5NjyHOPSensxUoTK3V1lFzGvS6zsG04Xdfs8AQMEAQAAAAEFR1IhAvuWyyfoIfsyrTwNoR8N80zSBdfJrGff+D9XKBRL7aEFIQJDFo5gffr4sTpOPvcI45wr3VtVCTh/yw/SiCJaCIjiV1KuIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQGoIQIGcwwFZVqf0EVFaTWYlQmxQ4oTCIkj+5KOstDoG1vgOaxRh2R2qRRvoS9lQLcmcOnmhvvrvSYgPxBG3oisa3apFEWuYAoAKnNlB7Zvc0vqNpOAwYMciKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQElIQJYONwJSgKF2+Ox+K8SgruNIwYM+5dbLzkhSvjfoCCjnaxRhyICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAA==").unwrap(),
                final_unvault: Some(UnvaultTransaction::from_psbt_str("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").unwrap()),
                initial_emer:
                EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAUaovJQUhwegF7P9qJBrWxtPq7dcJVPZ8MTjp9v8LUoDAAAAAAD9////AYj76QsAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBKxgv6gsAAAAAIgAgp2OS/+Hk2PIc49J6ezFShMrdXWUXMa9LrOwbThd1+zwBAwSBAAAAAQVHUiEC+5bLJ+gh+zKtPA2hHw3zTNIF18msZ9/4P1coFEvtoQUhAkMWjmB9+vixOk4+9wjjnCvdW1UJOH/LD9KIIloIiOJXUq4iBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAAiAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap(),
                final_emer: Some(EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAUaovJQUhwegF7P9qJBrWxtPq7dcJVPZ8MTjp9v8LUoDAAAAAAD9////AYj76QsAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBKxgv6gsAAAAAIgAgp2OS/+Hk2PIc49J6ezFShMrdXWUXMa9LrOwbThd1+zwiAgJDFo5gffr4sTpOPvcI45wr3VtVCTh/yw/SiCJaCIjiV0gwRQIhALJvF8aQzLHn/ggXqdv3Yxc6DUNcUUfBkp5VDc+mHnLrAiBdzlVaNZA3otm6DyD5GTFQuTPsp+DhIgGc3gkq+CzDKoEiAgL7lssn6CH7Mq08DaEfDfNM0gXXyaxn3/g/VygUS+2hBUcwRAIgIzC2vDhc2kfVPG2EYnMmkgrPHHkxlzyuAe6KQXfNjqsCIALiWWK3tsXR210Y0HOkYNIMmTW/qUKzeGO9aRMqoEdzgQEDBIEAAAABBUdSIQL7lssn6CH7Mq08DaEfDfNM0gXXyaxn3/g/VygUS+2hBSECQxaOYH36+LE6Tj73COOcK91bVQk4f8sP0ogiWgiI4ldSriIGAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAACICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAA==").unwrap()),
                initial_unvault_emer:
                UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAARU919uuOZ2HHyRUrQsCrT2s98u7j8/xW6DXMzO7+eYFAAAAAAD9////AaRl6QsAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK9Cn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QBAwSBAAAAAQWoIQIGcwwFZVqf0EVFaTWYlQmxQ4oTCIkj+5KOstDoG1vgOaxRh2R2qRRvoS9lQLcmcOnmhvvrvSYgPxBG3oisa3apFEWuYAoAKnNlB7Zvc0vqNpOAwYMciKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap(),
                final_unvault_emer: Some(UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAARU919uuOZ2HHyRUrQsCrT2s98u7j8/xW6DXMzO7+eYFAAAAAAD9////AaRl6QsAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK9Cn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QiAgJDFo5gffr4sTpOPvcI45wr3VtVCTh/yw/SiCJaCIjiV0gwRQIhAPSxaISa+1b4SqwfE0WfmXUe3YfIc7zIJfO1PA3ZdUqUAiBJ5JUqCXojmLZilVZGhgVHHwxpu5Kl4z9VftegjciTyoEiAgL7lssn6CH7Mq08DaEfDfNM0gXXyaxn3/g/VygUS+2hBUcwRAIgMval9daakP00a+64tfLtVXcX8iX/RDD+8ds4Ki9qn14CIEeo8hDkwNVJxMiNgM6QQ9I5RLtPPQnVxhzkle3q9lCdgQEDBIEAAAABBaghAgZzDAVlWp/QRUVpNZiVCbFDihMIiSP7ko6y0OgbW+A5rFGHZHapFG+hL2VAtyZw6eaG++u9JiA/EEbeiKxrdqkURa5gCgAqc2UHtm9zS+o2k4DBgxyIrGyTUodnUiEDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lohAqvkdbGZ7D1i+ldvruFqM0/bhv+ybc51vs66rt8yisP+Uq9TsmgiBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAAiAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap()),
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

        let tx_db = db_cancel_transaction(&db_file, vaults[2].id)
            .unwrap()
            .unwrap();
        update_presigned_tx(
            &db_file,
            &vaults[2],
            tx_db,
            &transactions[2]
                .as_ref()
                .unwrap()
                .final_cancel
                .as_ref()
                .unwrap()
                .psbt()
                .inputs[0]
                .partial_sigs,
            &revaultd.secp_ctx,
        );

        let tx_db = db_emer_transaction(&db_file, vaults[2].id)
            .unwrap()
            .unwrap();
        update_presigned_tx(
            &db_file,
            &vaults[2],
            tx_db,
            &transactions[2]
                .as_ref()
                .unwrap()
                .final_emer
                .as_ref()
                .unwrap()
                .psbt()
                .inputs[0]
                .partial_sigs,
            &revaultd.secp_ctx,
        );

        let tx_db = db_unvault_emer_transaction(&db_file, vaults[2].id)
            .unwrap()
            .unwrap();
        update_presigned_tx(
            &db_file,
            &vaults[2],
            tx_db,
            &transactions[2]
                .as_ref()
                .unwrap()
                .final_unvault_emer
                .as_ref()
                .unwrap()
                .psbt()
                .inputs[0]
                .partial_sigs,
            &revaultd.secp_ctx,
        );
        db_exec(&db_file, |tx| {
            tx.execute(
                "UPDATE vaults SET status = (?1), updated_at = strftime('%s','now') \
             WHERE vaults.id = (?2)",
                params![VaultStatus::Secured as u32, vaults[2].id,],
            )
            .unwrap();
            Ok(())
        })
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

        let tx_db = db_cancel_transaction(&db_file, vaults[3].id)
            .unwrap()
            .unwrap();
        update_presigned_tx(
            &db_file,
            &vaults[3],
            tx_db,
            &transactions[3]
                .as_ref()
                .unwrap()
                .final_cancel
                .as_ref()
                .unwrap()
                .psbt()
                .inputs[0]
                .partial_sigs,
            &revaultd.secp_ctx,
        );

        let tx_db = db_emer_transaction(&db_file, vaults[3].id)
            .unwrap()
            .unwrap();
        update_presigned_tx(
            &db_file,
            &vaults[3],
            tx_db,
            &transactions[3]
                .as_ref()
                .unwrap()
                .final_emer
                .as_ref()
                .unwrap()
                .psbt()
                .inputs[0]
                .partial_sigs,
            &revaultd.secp_ctx,
        );

        let tx_db = db_unvault_emer_transaction(&db_file, vaults[3].id)
            .unwrap()
            .unwrap();
        update_presigned_tx(
            &db_file,
            &vaults[3],
            tx_db,
            &transactions[3]
                .as_ref()
                .unwrap()
                .final_unvault_emer
                .as_ref()
                .unwrap()
                .psbt()
                .inputs[0]
                .partial_sigs,
            &revaultd.secp_ctx,
        );

        let tx_db = db_unvault_transaction(&db_file, vaults[3].id)
            .unwrap()
            .unwrap();
        update_presigned_tx(
            &db_file,
            &vaults[3],
            tx_db,
            &transactions[3]
                .as_ref()
                .unwrap()
                .final_unvault
                .as_ref()
                .unwrap()
                .psbt()
                .inputs[0]
                .partial_sigs,
            &revaultd.secp_ctx,
        );
        db_exec(&db_file, |tx| {
            tx.execute(
                "UPDATE vaults SET status = (?1), updated_at = strftime('%s','now') \
             WHERE vaults.id = (?2)",
                params![VaultStatus::Active as u32, vaults[3].id,],
            )
            .unwrap();
            Ok(())
        })
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
        let datadir_stk = test_datadir();
        let datadir_man = test_datadir();
        let mut stake_revaultd = dummy_revaultd(datadir_stk.clone(), UserRole::Stakeholder);
        let mut man_revaultd = dummy_revaultd(datadir_man.clone(), UserRole::Manager);
        setup_db(&mut stake_revaultd).unwrap();
        let vaults = create_vaults(&stake_revaultd);
        setup_db(&mut man_revaultd).unwrap();
        let _ = create_vaults(&man_revaultd);

        // vault[0] is not confirmed, no presigned txs here!
        assert_eq!(
            presigned_txs(&stake_revaultd, vec![vaults[0].db_vault.clone()])
                .unwrap_err()
                .to_string(),
            RpcControlError::TransactionNotFound.to_string()
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

        fs::remove_dir_all(&datadir_stk).unwrap_or_else(|_| ());
        fs::remove_dir_all(&datadir_man).unwrap_or_else(|_| ());
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

    // This time the coordinator won't ack our signatures :(
    #[test]
    fn test_send_sig_msg_not_acked() {
        let txid =
            Txid::from_str("fcb6ab963b654c773de786f4ac92c132b3d2e816ccea37af9592aa0b4aaec04b")
                .unwrap();
        let ctx = secp256k1::Secp256k1::new();
        let (_, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let mut sigs = BTreeMap::new();
        let signature = secp256k1::Signature::from_str("304402201a3109a4a6445c1e56416bc39520aada5c8ad089e69ee4f1a40a0901de1a435302204b281ba97da2ab2e40eb65943ae414cc4307406c5eb177b1c646606839a2e99d").unwrap();
        sigs.insert(public_key.key, signature.clone());

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            let mut cli_transport = KKTransport::connect(addr, &client_privkey, &server_pubkey)
                .expect("Client channel connecting");
            assert!(send_sig_msg(&mut cli_transport, txid.clone(), sigs.clone())
                .unwrap_err()
                .to_string()
                .contains(&CommunicationError::SignatureStorage.to_string()));
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(Sig {
                        pubkey: public_key.key,
                        signature,
                        id: txid
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: false },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    // This time the server likes our signatures! :tada:
    #[test]
    fn test_send_sig_msg() {
        let txid =
            Txid::from_str("fcb6ab963b654c773de786f4ac92c132b3d2e816ccea37af9592aa0b4aaec04b")
                .unwrap();
        let ctx = secp256k1::Secp256k1::new();
        let (_, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let mut sigs = BTreeMap::new();
        let signature = secp256k1::Signature::from_str("304402201a3109a4a6445c1e56416bc39520aada5c8ad089e69ee4f1a40a0901de1a435302204b281ba97da2ab2e40eb65943ae414cc4307406c5eb177b1c646606839a2e99d").unwrap();
        sigs.insert(public_key.key, signature.clone());

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            let mut cli_transport = KKTransport::connect(addr, &client_privkey, &server_pubkey)
                .expect("Client channel connecting");
            send_sig_msg(&mut cli_transport, txid.clone(), sigs.clone()).unwrap();
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(Sig {
                        pubkey: public_key.key,
                        signature,
                        id: txid
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: true },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_share_rev_signatures_not_acked() {
        let ctx = secp256k1::Secp256k1::new();
        let (private_key, public_key) =
            create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let mut cancel =
                CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAASDOvhSZlTSEcEoUq/CT7Cg3ILtc6sqt5qJKvAMq+LbIAAAAAAD9////AXYfpDUAAAAAIgAg9AncsIZc8g7mJdfT9infAeWlqjtxBs93ireDGnQn/DYAAAAAAAEBK7hhpDUAAAAAIgAgFZlOQkpDkFSsLUfyeMGVAOT3T88jZM7L/XlVZoJ2jnABAwSBAAAAAQWpIQMVlEoh50lasMhcdwnrmnCp2ROlGY5CrH+HtxQmfZDZ06xRh2R2qRS/INUX1CaP7Pbn5GmtGYu2wgqjnIisa3apFO/kceq8yo9w69g4VVtlFAf739qTiKxsk1KHZ1IhAnddfXi3N38A+aEQ74sUdeuV7sg+2L3ijTjMHMEAfq3cIQLWP96FqjfC5qKQkC2WhYbbLJx1FbNSAjsnMfwDnK0jD1KvARKyaCIGAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBR1IhA47+JRqdt+oloFosla9hWUYVf5YQKDbuq4KO13JS45KgIQMKcLWzABxb/9YBQe+bJRW3v3om8S2LNMGUKSp5K+PQ+1KuIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap();
        let signature_hash = secp256k1::Message::from_slice(
            &cancel
                .signature_hash(0, SigHashType::AllPlusAnyoneCanPay)
                .unwrap(),
        )
        .unwrap();
        let signature = ctx.sign(&signature_hash, &private_key.key);
        cancel
            .add_cancel_sig(public_key.key, signature, &ctx)
            .unwrap();
        let other_cancel = cancel.clone();
        let db_tx = DbTransaction {
            id: 0,
            vault_id: 0,
            tx_type: TransactionType::Cancel,
            psbt: RevaultTx::Cancel(cancel),
            is_fully_signed: false,
        };

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            assert!(
                share_rev_signatures(addr, &client_privkey, &server_pubkey, &[db_tx])
                    .unwrap_err()
                    .to_string()
                    .contains(&CommunicationError::SignatureStorage.to_string())
            );
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(Sig {
                        pubkey: public_key.key,
                        signature,
                        id: other_cancel.txid(),
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: false },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_share_rev_signatures() {
        let ctx = secp256k1::Secp256k1::new();
        let (privkey, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let mut cancel =
                CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAASDOvhSZlTSEcEoUq/CT7Cg3ILtc6sqt5qJKvAMq+LbIAAAAAAD9////AXYfpDUAAAAAIgAg9AncsIZc8g7mJdfT9infAeWlqjtxBs93ireDGnQn/DYAAAAAAAEBK7hhpDUAAAAAIgAgFZlOQkpDkFSsLUfyeMGVAOT3T88jZM7L/XlVZoJ2jnABAwSBAAAAAQWpIQMVlEoh50lasMhcdwnrmnCp2ROlGY5CrH+HtxQmfZDZ06xRh2R2qRS/INUX1CaP7Pbn5GmtGYu2wgqjnIisa3apFO/kceq8yo9w69g4VVtlFAf739qTiKxsk1KHZ1IhAnddfXi3N38A+aEQ74sUdeuV7sg+2L3ijTjMHMEAfq3cIQLWP96FqjfC5qKQkC2WhYbbLJx1FbNSAjsnMfwDnK0jD1KvARKyaCIGAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBR1IhA47+JRqdt+oloFosla9hWUYVf5YQKDbuq4KO13JS45KgIQMKcLWzABxb/9YBQe+bJRW3v3om8S2LNMGUKSp5K+PQ+1KuIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap();
        let signature_hash = secp256k1::Message::from_slice(
            &cancel
                .signature_hash(0, SigHashType::AllPlusAnyoneCanPay)
                .unwrap(),
        )
        .unwrap();
        let signature_cancel = ctx.sign(&signature_hash, &privkey.key);
        cancel
            .add_cancel_sig(public_key.key, signature_cancel, &ctx)
            .unwrap();
        let mut emer =
                EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAajRZE5yVgzG9McmOyy/WdcYdrGrK15bB5N/Hg8zhKOkAQAAAAD9////AXC1pDUAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBKwDppDUAAAAAIgAg9AncsIZc8g7mJdfT9infAeWlqjtxBs93ireDGnQn/DYBAwSBAAAAAQVHUiEDjv4lGp236iWgWiyVr2FZRhV/lhAoNu6rgo7XclLjkqAhAwpwtbMAHFv/1gFB75slFbe/eibxLYs0wZQpKnkr49D7Uq4iBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAAiAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap();
        let signature_hash = secp256k1::Message::from_slice(
            &emer
                .signature_hash(0, SigHashType::AllPlusAnyoneCanPay)
                .unwrap(),
        )
        .unwrap();
        let signature_emer = ctx.sign(&signature_hash, &privkey.key);
        emer.add_emer_sig(public_key.key, signature_emer, &ctx)
            .unwrap();
        let mut unvault_emer =
                UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAbmw9RR44LLNO5aKs0SOdUDW4aJgM9indHt2KSEVkRNBAAAAAAD9////AaQvhEcAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK9BxhEcAAAAAIgAgMJBZ5AwbSGM9P3Q44qxIeXv5J4UXLnhwdfblfBLn2voBAwSBAAAAAQWoIQL5vFDdmMV/P4SpzIWhDMbHKHMGlMwntZxaWtwUXd9KvKxRh2R2qRTtnZLjf14tI1q08+ZyoIEpuuMqWYisa3apFJKFWLx/I+YKyIXcNmwC0yw69uN9iKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAA==").unwrap();
        let signature_hash = secp256k1::Message::from_slice(
            &unvault_emer
                .signature_hash(0, SigHashType::AllPlusAnyoneCanPay)
                .unwrap(),
        )
        .unwrap();
        let signature_unemer = ctx.sign(&signature_hash, &privkey.key);
        unvault_emer
            .add_emer_sig(public_key.key, signature_unemer, &ctx)
            .unwrap();
        let other_cancel = cancel.clone();
        let other_emer = emer.clone();
        let other_unvault_emer = unvault_emer.clone();
        let db_cancel = DbTransaction {
            id: 0,
            vault_id: 0,
            tx_type: TransactionType::Cancel,
            psbt: RevaultTx::Cancel(cancel),
            is_fully_signed: false,
        };
        let db_emer = DbTransaction {
            id: 0,
            vault_id: 0,
            tx_type: TransactionType::Emergency,
            psbt: RevaultTx::Emergency(emer),
            is_fully_signed: false,
        };
        let db_unemer = DbTransaction {
            id: 0,
            vault_id: 0,
            tx_type: TransactionType::UnvaultEmergency,
            psbt: RevaultTx::UnvaultEmergency(unvault_emer),
            is_fully_signed: false,
        };

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            share_rev_signatures(
                addr,
                &client_privkey,
                &server_pubkey,
                &[db_cancel, db_emer, db_unemer],
            )
            .unwrap();
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(Sig {
                        pubkey: public_key.key,
                        signature: signature_cancel,
                        id: other_cancel.txid(),
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: true },
                ))
            })
            .unwrap();

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(Sig {
                        pubkey: public_key.key,
                        signature: signature_emer,
                        id: other_emer.txid(),
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: true },
                ))
            })
            .unwrap();

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(Sig {
                        pubkey: public_key.key,
                        signature: signature_unemer,
                        id: other_unvault_emer.txid(),
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: true },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_share_unvault_signatures() {
        let mut unvault =
                UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAajRZE5yVgzG9McmOyy/WdcYdrGrK15bB5N/Hg8zhKOkAQAAAAD9////ArhhpDUAAAAAIgAgFZlOQkpDkFSsLUfyeMGVAOT3T88jZM7L/XlVZoJ2jnAwdQAAAAAAACIAILKCCA/RbV3QMPMrwwQmk4Ark4w1WyElM27WtBgftq6ZAAAAAAABASsA6aQ1AAAAACIAIPQJ3LCGXPIO5iXX0/Yp3wHlpao7cQbPd4q3gxp0J/w2AQMEAQAAAAEFR1IhA47+JRqdt+oloFosla9hWUYVf5YQKDbuq4KO13JS45KgIQMKcLWzABxb/9YBQe+bJRW3v3om8S2LNMGUKSp5K+PQ+1KuIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQGpIQMVlEoh50lasMhcdwnrmnCp2ROlGY5CrH+HtxQmfZDZ06xRh2R2qRS/INUX1CaP7Pbn5GmtGYu2wgqjnIisa3apFO/kceq8yo9w69g4VVtlFAf739qTiKxsk1KHZ1IhAnddfXi3N38A+aEQ74sUdeuV7sg+2L3ijTjMHMEAfq3cIQLWP96FqjfC5qKQkC2WhYbbLJx1FbNSAjsnMfwDnK0jD1KvARKyaCICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBJSEDjv4lGp236iWgWiyVr2FZRhV/lhAoNu6rgo7XclLjkqCsUYciAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap();
        let ctx = secp256k1::Secp256k1::new();
        let (privkey, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let signature_hash =
            secp256k1::Message::from_slice(&unvault.signature_hash(0, SigHashType::All).unwrap())
                .unwrap();
        let signature = ctx.sign(&signature_hash, &privkey.key);
        unvault
            .add_signature(0, public_key.key, signature.clone(), &ctx)
            .unwrap();
        let other_unvault = unvault.clone();
        let db_unvault = DbTransaction {
            id: 0,
            vault_id: 0,
            tx_type: TransactionType::Unvault,
            psbt: RevaultTx::Unvault(unvault),
            is_fully_signed: false,
        };

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            share_unvault_signatures(addr, &client_privkey, &server_pubkey, &db_unvault).unwrap();
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(Sig {
                        pubkey: public_key.key,
                        signature,
                        id: other_unvault.txid(),
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: true },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_share_unvault_signatures_not_acked() {
        let mut unvault =
                UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAajRZE5yVgzG9McmOyy/WdcYdrGrK15bB5N/Hg8zhKOkAQAAAAD9////ArhhpDUAAAAAIgAgFZlOQkpDkFSsLUfyeMGVAOT3T88jZM7L/XlVZoJ2jnAwdQAAAAAAACIAILKCCA/RbV3QMPMrwwQmk4Ark4w1WyElM27WtBgftq6ZAAAAAAABASsA6aQ1AAAAACIAIPQJ3LCGXPIO5iXX0/Yp3wHlpao7cQbPd4q3gxp0J/w2AQMEAQAAAAEFR1IhA47+JRqdt+oloFosla9hWUYVf5YQKDbuq4KO13JS45KgIQMKcLWzABxb/9YBQe+bJRW3v3om8S2LNMGUKSp5K+PQ+1KuIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQGpIQMVlEoh50lasMhcdwnrmnCp2ROlGY5CrH+HtxQmfZDZ06xRh2R2qRS/INUX1CaP7Pbn5GmtGYu2wgqjnIisa3apFO/kceq8yo9w69g4VVtlFAf739qTiKxsk1KHZ1IhAnddfXi3N38A+aEQ74sUdeuV7sg+2L3ijTjMHMEAfq3cIQLWP96FqjfC5qKQkC2WhYbbLJx1FbNSAjsnMfwDnK0jD1KvARKyaCICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBJSEDjv4lGp236iWgWiyVr2FZRhV/lhAoNu6rgo7XclLjkqCsUYciAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap();
        let ctx = secp256k1::Secp256k1::new();
        let (privkey, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let signature_hash =
            secp256k1::Message::from_slice(&unvault.signature_hash(0, SigHashType::All).unwrap())
                .unwrap();
        let signature = ctx.sign(&signature_hash, &privkey.key);
        unvault
            .add_signature(0, public_key.key, signature.clone(), &ctx)
            .unwrap();
        let other_unvault = unvault.clone();
        let db_unvault = DbTransaction {
            id: 0,
            vault_id: 0,
            tx_type: TransactionType::Unvault,
            psbt: RevaultTx::Unvault(unvault),
            is_fully_signed: false,
        };

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            assert!(
                share_unvault_signatures(addr, &client_privkey, &server_pubkey, &db_unvault,)
                    .unwrap_err()
                    .to_string()
                    .contains(&CommunicationError::SignatureStorage.to_string())
            );
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(Sig {
                        pubkey: public_key.key,
                        signature,
                        id: other_unvault.txid(),
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: false },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_fetch_cosigs_signatures() {
        let mut spend = SpendTransaction::from_psbt_str("cHNidP8BAN0CAAAAAvvnQeptD/Ppkod15b290euvxLZ152fu+UG6SL6Sn/rKBAAAAAADAAAA++dB6m0P8+mSh3Xlvb3R66/EtnXnZ+75QbpIvpKf+soDAAAAAAMAAAADoEUAAAAAAAAiACDg+GlvXbP0TV3DYoQNm7MNXPm5oOuWroc/9w6DzxIO6ADh9QUAAAAAIgAg4Phpb12z9E1dw2KEDZuzDVz5uaDrlq6HP/cOg88SDujfcPMFAAAAACIAIKdjkv/h5NjyHOPSensxUoTK3V1lFzGvS6zsG04Xdfs8AAAAAAABASvQp+kLAAAAACIAIPEeGS8d2X/wO1TnGez7QM4Ui6OaJZKqmD/r6CwkRZ9kAQMEAQAAAAEFqCECBnMMBWVan9BFRWk1mJUJsUOKEwiJI/uSjrLQ6Btb4DmsUYdkdqkUb6EvZUC3JnDp5ob7670mID8QRt6IrGt2qRRFrmAKACpzZQe2b3NL6jaTgMGDHIisbJNSh2dSIQMPZLkiruL9WX8QS8bLO2cPHKLGxJsQcaGmwBBXXZT+WiECq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5Sr1OyaCIGAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBK9Cn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QBAwQBAAAAAQWoIQIGcwwFZVqf0EVFaTWYlQmxQ4oTCIkj+5KOstDoG1vgOaxRh2R2qRRvoS9lQLcmcOnmhvvrvSYgPxBG3oisa3apFEWuYAoAKnNlB7Zvc0vqNpOAwYMciKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQElIQJYONwJSgKF2+Ox+K8SgruNIwYM+5dbLzkhSvjfoCCjnaxRhyICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAACICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBR1IhAvuWyyfoIfsyrTwNoR8N80zSBdfJrGff+D9XKBRL7aEFIQJDFo5gffr4sTpOPvcI45wr3VtVCTh/yw/SiCJaCIjiV1KuIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap();
        let ctx = secp256k1::Secp256k1::new();
        let (_, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let signature = Vec::<u8>::from_hex("3045022100bfdfc4a5c770414645c7b7bf34b9a8607928164a167a457db59f46a24cc16096022070dc95987d9d43db34d4005c2be89b5626b1a1084ec1081be916ea9dbf4ce13e01").unwrap();
        let signature = secp256k1::Signature::from_der(&signature[..signature.len() - 1]).unwrap();
        let mut other_spend = spend.clone();

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cosigs = vec![(addr, server_pubkey)];

        // client thread
        let cli_thread = thread::spawn(move || {
            // Our spend has no partial sigs...
            assert_eq!(spend.psbt().inputs.get(0).unwrap().partial_sigs.len(), 0);
            fetch_cosigs_signatures(&ctx, &client_privkey, &mut spend, &cosigs).unwrap();
            // Now our spend has one :)
            assert_eq!(spend.psbt().inputs.get(0).unwrap().partial_sigs.len(), 1);
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::Sign(SignRequest {
                        tx: other_spend.clone(),
                    }),
                );
                let ctx = secp256k1::Secp256k1::verification_only();
                other_spend
                    .add_signature(0, public_key.key, signature.clone(), &ctx)
                    .unwrap();
                Some(message::ResponseResult::SignResult(
                    message::cosigner::SignResult {
                        tx: Some(other_spend),
                    },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_fetch_cosigs_signatures_cosigner_already_signed() {
        let secp = secp256k1::Secp256k1::verification_only();
        let mut spend = SpendTransaction::from_psbt_str("cHNidP8BAN0CAAAAAvvnQeptD/Ppkod15b290euvxLZ152fu+UG6SL6Sn/rKBAAAAAADAAAA++dB6m0P8+mSh3Xlvb3R66/EtnXnZ+75QbpIvpKf+soDAAAAAAMAAAADoEUAAAAAAAAiACDg+GlvXbP0TV3DYoQNm7MNXPm5oOuWroc/9w6DzxIO6ADh9QUAAAAAIgAg4Phpb12z9E1dw2KEDZuzDVz5uaDrlq6HP/cOg88SDujfcPMFAAAAACIAIKdjkv/h5NjyHOPSensxUoTK3V1lFzGvS6zsG04Xdfs8AAAAAAABASvQp+kLAAAAACIAIPEeGS8d2X/wO1TnGez7QM4Ui6OaJZKqmD/r6CwkRZ9kAQMEAQAAAAEFqCECBnMMBWVan9BFRWk1mJUJsUOKEwiJI/uSjrLQ6Btb4DmsUYdkdqkUb6EvZUC3JnDp5ob7670mID8QRt6IrGt2qRRFrmAKACpzZQe2b3NL6jaTgMGDHIisbJNSh2dSIQMPZLkiruL9WX8QS8bLO2cPHKLGxJsQcaGmwBBXXZT+WiECq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5Sr1OyaCIGAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBK9Cn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QBAwQBAAAAAQWoIQIGcwwFZVqf0EVFaTWYlQmxQ4oTCIkj+5KOstDoG1vgOaxRh2R2qRRvoS9lQLcmcOnmhvvrvSYgPxBG3oisa3apFEWuYAoAKnNlB7Zvc0vqNpOAwYMciKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQElIQJYONwJSgKF2+Ox+K8SgruNIwYM+5dbLzkhSvjfoCCjnaxRhwAAAQFHUiEC+5bLJ+gh+zKtPA2hHw3zTNIF18msZ9/4P1coFEvtoQUhAkMWjmB9+vixOk4+9wjjnCvdW1UJOH/LD9KIIloIiOJXUq4A").unwrap();
        // Rust newbie: I need the spend but it's moved inside the closure, so I'm cloning
        // it now
        let other_spend = spend.clone();
        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cosigs = vec![(addr, server_pubkey)];

        // client thread
        let cli_thread = thread::spawn(move || {
            assert!(
                fetch_cosigs_signatures(&secp, &client_privkey, &mut spend, &cosigs)
                    .unwrap_err()
                    .to_string()
                    .contains(&CommunicationError::CosigAlreadySigned.to_string())
            );
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::Sign(SignRequest {
                        tx: other_spend.clone(),
                    }),
                );
                Some(message::ResponseResult::SignResult(
                    message::cosigner::SignResult { tx: None },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    /// The cosigner will send us the psbt with an invalid signature
    #[test]
    fn test_fetch_cosigs_signatures_invalid_signature() {
        let ctx = secp256k1::Secp256k1::new();
        let mut spend = SpendTransaction::from_psbt_str("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").unwrap();
        let mut psbt = spend.clone().into_psbt();
        let (_, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        // Not a DER signature
        let invalid_signature = Vec::<u8>::from_hex("1234").unwrap();
        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cosigs = vec![(addr, server_pubkey)];

        psbt.inputs[0]
            .partial_sigs
            .insert(public_key, invalid_signature);
        // FIXME: revault_tx should prevent us from doing this
        let other_spend = SpendTransaction::from_raw_psbt(&encode::serialize(&psbt)).unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            assert!(
                fetch_cosigs_signatures(&ctx, &client_privkey, &mut spend, &cosigs)
                    .unwrap_err()
                    .to_string()
                    .contains(&CommunicationError::CosigInsanePsbt.to_string())
            );
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|_| {
                Some(message::ResponseResult::SignResult(
                    message::cosigner::SignResult {
                        tx: Some(other_spend),
                    },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    #[should_panic(expected = "assertion failed: tx.is_finalized()")]
    fn test_announce_spend_transaction_not_finalized() {
        let spend = SpendTransaction::from_psbt_str("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").unwrap();

        let outpoints = vec![
            OutPoint::new(
                Txid::from_str("fcb6ab963b654c773de786f4ac92c132b3d2e816ccea37af9592aa0b4aaec04b")
                    .unwrap(),
                0,
            ),
            OutPoint::new(
                Txid::from_str("617eab1fc0b03ee7f82ba70166725291783461f1a0e7975eaf8b5f8f674234f2")
                    .unwrap(),
                1,
            ),
            OutPoint::new(
                Txid::from_str("a9735f42110ce529386f612194a1e137a2a2679ac0e789ad7f470cd70c3c2c24")
                    .unwrap(),
                2,
            ),
            OutPoint::new(
                Txid::from_str("cafa9f92be48ba41f9ee67e775b6c4afebd1bdbde5758792e9f30f6dea41e7fb")
                    .unwrap(),
                3,
            ),
        ];

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_thread = thread::spawn(move || {
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");
        });

        announce_spend_transaction(addr, &client_privkey, &server_pubkey, spend, outpoints)
            .unwrap();

        server_thread.join().unwrap();
    }

    #[test]
    fn test_announce_spend_transaction_not_acked() {
        let mut spend = SpendTransaction::from_psbt_str("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").unwrap();
        let ctx = secp256k1::Secp256k1::new();
        spend.finalize(&ctx).unwrap();

        let outpoints = vec![
            OutPoint::new(
                Txid::from_str("fcb6ab963b654c773de786f4ac92c132b3d2e816ccea37af9592aa0b4aaec04b")
                    .unwrap(),
                0,
            ),
            OutPoint::new(
                Txid::from_str("617eab1fc0b03ee7f82ba70166725291783461f1a0e7975eaf8b5f8f674234f2")
                    .unwrap(),
                1,
            ),
            OutPoint::new(
                Txid::from_str("a9735f42110ce529386f612194a1e137a2a2679ac0e789ad7f470cd70c3c2c24")
                    .unwrap(),
                2,
            ),
            OutPoint::new(
                Txid::from_str("cafa9f92be48ba41f9ee67e775b6c4afebd1bdbde5758792e9f30f6dea41e7fb")
                    .unwrap(),
                3,
            ),
        ];

        let other_spend = spend.clone();
        let other_outpoints = outpoints.clone();

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            assert!(announce_spend_transaction(
                addr,
                &client_privkey,
                &server_pubkey,
                spend,
                outpoints,
            )
            .unwrap_err()
            .to_string()
            .contains(&CommunicationError::SpendTxStorage.to_string()));
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::SetSpendTx(SetSpendTx::from_spend_tx(
                        other_outpoints,
                        other_spend,
                    ))
                );
                Some(message::ResponseResult::SetSpend(
                    message::coordinator::SetSpendResult { ack: false },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_announce_spend_transaction() {
        let mut spend = SpendTransaction::from_psbt_str("cHNidP8BAKgCAAAAARU919uuOZ2HHyRUrQsCrT2s98u7j8/xW6DXMzO7+eYFAAAAAAADAAAAA6BCAAAAAAAAIgAg4Phpb12z9E1dw2KEDZuzDVz5uaDrlq6HP/cOg88SDuiAlpgAAAAAABYAFPAj0esIbomyGAolRR1U/vYas0RxhspQCwAAAAAiACCnY5L/4eTY8hzj0np7MVKEyt1dZRcxr0us7BtOF3X7PAAAAAAAAQEr0KfpCwAAAAAiACDxHhkvHdl/8DtU5xns+0DOFIujmiWSqpg/6+gsJEWfZCICAgKTOrEDfq0KpKeFjG1J1nBeH7O8X2awCRive58A7NUmRzBEAiB3KkDDMDY+tFDP/NEp0Qvl7ndg0zeah+aeWC8pcrLedQIgCRgErTVJbFpEXY//cEejA/35u9DDR9Odx0B6CyIETHABIgICA8dJ8CWgfhsrU+VE3or4jMBtvGR/9hLUqLVpL5fBB7tIMEUCIQDlxg6DwLX1ilz36a1aSydMfTCz/Cj5jgDgqk1gogDxiAIgHn85138uFwbEpAI4dfqdaOE4FTjg10c/JepCMJ75nGIBIgICBnMMBWVan9BFRWk1mJUJsUOKEwiJI/uSjrLQ6Btb4DlIMEUCIQCNVIPcowRztg4naOv4SkLlsWE/JK6txS1rhrdEFjgzGwIgd7TQy9C/HytCj46Xr7AShn4lm9AKsIwhcDK+ZRYCZP4BIgICEUcipBjtxtFxFXI6CYvMq/KXtJxTVJETq5tRILViovxIMEUCIQCq1nTvhPAEqpwvT83E7l903TZfeA0wwBd1sdIAaMrzlQIgR7v+TYZxt5GOADgDqMHd20E9ps9yjt38Xx5FEMeRpIEBIgICq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5HMEQCIDs+EJm+1ahGgXUteU0UpiD+pF+byHKgcXuCAGK2cr+dAiAXLnVdMLBT06XA1PNT7pzRYn8YwRuagHsqdFZn1/kqGQEiAgLKu0S06bTqM58ay1TmFWXs+3OwjYhNK8e07OGWSCCnNEgwRQIhAPf5MXo44ra2oHhiS2+mrigZsVwlBHeI8TIUa8nkFsg0AiApIhymkAPpbh1iX5HhKhv7ZSnpDFZCf2MAG0XdKUaA+gEiAgLoIlcyuneynTYaX6GkPZgd6S7+s33mK+GmsoFNFj4f0kcwRAIgZ1LcuP3qnxzMPLDSJKPnKxW9NUEr2FEPxypmfy5Axx0CIEhDmU61ffHePcWxwRB01k9nh1UNjjZcwWv6/7lLReThASICAvbewaqhppKhJmJCtUrXIa2E4HIeghNYUe3jdZpOPyWsRzBEAiB+YisdkzDamRmocVNY1L78iYs6NPTXdXRr9PcXeqYJmQIgcgs1E2bsopySlAlVHNmXVI2AgYNiPK8cFFqR09CQIAwBIgIC+bxQ3ZjFfz+EqcyFoQzGxyhzBpTMJ7WcWlrcFF3fSrxIMEUCIQD0B7BRPDeDOsmvnc0ndozXLlYJgATXvahWi6WtI1loXQIgfxw7aGb7rXyKnL0cCtOt2Mo2shV8mXbYvyIZhVEeP44BIgIDD2S5Iq7i/Vl/EEvGyztnDxyixsSbEHGhpsAQV12U/lpHMEQCIF9+ZZO4AoFaz0WVZbLXNONf0S4pPQJrqRBrTII/nfxmAiBMppaQlftKQNtw2AcmvbFnxdqfXys+TwM0I+Env+0YzQEiAgM10BzuiowG8+zoJisSnHBWMbB2Z7eaB/4FoNWsJyvU9EcwRAIgY/4i6WCy9dKm4bIIFVgo+RmNwMOCxpGBn4o8pmYrqpcCIAM7hMX+az0D10wg0gzwc1ltYuf/JRkCNJfAN3AvA3XgASICA05t+3A0/e1NLMTAIYAg3jdEy4ofmtzSh8emoXMoeusXSDBFAiEAnWN8RXH69QweNR3T3VKpdNEHugiVTL6cIvXcnK6P+AMCIEZy/RkyUxcsXW80/hY4c71KZsCbwIyTcvhhgflGaXGwASICA06OB5pRHoR9/LWGTHq6Sy4Ugc85I1tQyEymGej6/fiNRzBEAiBAXayRXgy0xZ2lR6xTwN8iaDCr//SxLz/biRmdYG1usAIgf9l3przSfZcX2wnkKQPQLFzCeseLvy+w14tOQ/fABjYBIgIDwCr2aH/yTKugv5gL94kaje+nlTukczWC88/V6l4oDo5HMEQCIHzww7Pq/oCNpS1R9aEPGF3AHBlCrx6NE32CA4ZThxCcAiBtsieXalS5Bd4i/+JxytFVn2Le/Pf7/7ko7zhQDE4gUgEBAwQBAAAAAQWoIQIGcwwFZVqf0EVFaTWYlQmxQ4oTCIkj+5KOstDoG1vgOaxRh2R2qRRvoS9lQLcmcOnmhvvrvSYgPxBG3oisa3apFEWuYAoAKnNlB7Zvc0vqNpOAwYMciKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQElIQJYONwJSgKF2+Ox+K8SgruNIwYM+5dbLzkhSvjfoCCjnaxRhwAAAQFHUiEC+5bLJ+gh+zKtPA2hHw3zTNIF18msZ9/4P1coFEvtoQUhAkMWjmB9+vixOk4+9wjjnCvdW1UJOH/LD9KIIloIiOJXUq4A").unwrap();
        let ctx = secp256k1::Secp256k1::new();
        spend.finalize(&ctx).unwrap();

        let outpoints = vec![
            OutPoint::new(
                Txid::from_str("fcb6ab963b654c773de786f4ac92c132b3d2e816ccea37af9592aa0b4aaec04b")
                    .unwrap(),
                0,
            ),
            OutPoint::new(
                Txid::from_str("617eab1fc0b03ee7f82ba70166725291783461f1a0e7975eaf8b5f8f674234f2")
                    .unwrap(),
                1,
            ),
            OutPoint::new(
                Txid::from_str("a9735f42110ce529386f612194a1e137a2a2679ac0e789ad7f470cd70c3c2c24")
                    .unwrap(),
                2,
            ),
            OutPoint::new(
                Txid::from_str("cafa9f92be48ba41f9ee67e775b6c4afebd1bdbde5758792e9f30f6dea41e7fb")
                    .unwrap(),
                3,
            ),
        ];

        let other_spend = spend.clone();
        let other_outpoints = outpoints.clone();

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            announce_spend_transaction(addr, &client_privkey, &server_pubkey, spend, outpoints)
                .unwrap();
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::SetSpendTx(SetSpendTx::from_spend_tx(
                        other_outpoints,
                        other_spend,
                    ))
                );
                Some(message::ResponseResult::SetSpend(
                    message::coordinator::SetSpendResult { ack: true },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_get_presigs() {
        let ctx = secp256k1::Secp256k1::new();
        let (_, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let signature = secp256k1::Signature::from_der(&Vec::<u8>::from_hex("304402201a3109a4a6445c1e56416bc39520aada5c8ad089e69ee4f1a40a0901de1a435302204b281ba97da2ab2e40eb65943ae414cc4307406c5eb177b1c646606839a2e99d").unwrap()).unwrap();
        let mut sigs = BTreeMap::new();
        sigs.insert(public_key.key, signature);
        let other_sigs = sigs.clone();

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let txid =
            Txid::from_str("cafa9f92be48ba41f9ee67e775b6c4afebd1bdbde5758792e9f30f6dea41e7fb")
                .unwrap();
        let another_txid = txid.clone();

        // client thread
        let cli_thread = thread::spawn(move || {
            let signatures = get_presigs(addr, &client_privkey, &server_pubkey, txid).unwrap();
            assert_eq!(signatures, sigs);
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::GetSigs(GetSigs { id: another_txid })
                );
                Some(message::ResponseResult::Sigs(message::coordinator::Sigs {
                    signatures: other_sigs,
                }))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }
}
