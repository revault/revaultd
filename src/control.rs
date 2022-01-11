//! This module contains routines for controlling our actions (checking signatures, communicating
//! with servers, with bitcoind, ..). Requests may originate from the RPC server or the signature
//! fetcher thread.

use crate::{
    bitcoind::{interface::WalletTransaction, BitcoindError},
    database::{
        interface::{
            db_cancel_transaction, db_emer_transaction, db_signed_emer_txs, db_signed_unemer_txs,
            db_unvault_emer_transaction, db_unvault_transaction, db_vault_by_deposit, db_vaults,
            db_vaults_with_txids_in_period,
        },
        schema::DbVault,
        DatabaseError,
    },
    revaultd::{RevaultD, VaultStatus},
    threadmessages::*,
};

use revault_tx::{
    bitcoin::{
        consensus::encode, hashes::hex::FromHex, util::bip32::ChildNumber, Address, Amount,
        OutPoint, Transaction as BitcoinTransaction, Txid,
    },
    miniscript::DescriptorTrait,
    transactions::{
        CancelTransaction, EmergencyTransaction, RevaultTransaction, SpendTransaction,
        UnvaultEmergencyTransaction, UnvaultTransaction,
    },
};

use std::{
    collections::{HashMap, HashSet},
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
    pub funded_at: Option<u32>,
    pub secured_at: Option<u32>,
    pub delegated_at: Option<u32>,
    pub moved_at: Option<u32>,
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
                    funded_at: db_vault.funded_at,
                    secured_at: db_vault.secured_at,
                    delegated_at: db_vault.delegated_at,
                    moved_at: db_vault.moved_at,
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
    db_path: &std::path::Path,
    outpoints: &[OutPoint],
    invalid_statuses: &[VaultStatus],
) -> Result<Vec<DbVault>, RpcControlError> {
    let mut vaults = Vec::with_capacity(outpoints.len());

    for outpoint in outpoints.iter() {
        // Note: being smarter with SQL queries implies enabling the 'table' feature of rusqlite
        // with a shit ton of dependencies.
        if let Some(vault) = db_vault_by_deposit(db_path, outpoint)? {
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

/// get_history retrieves a limited list of events which occured between two given dates.
pub fn get_history<T: BitcoindThread>(
    revaultd: &RevaultD,
    bitcoind_conn: &T,
    start: u32,
    end: u32,
    limit: u64,
    kind: Vec<HistoryEventKind>,
) -> Result<Vec<HistoryEvent>, RpcControlError> {
    let db_path = revaultd.db_file();
    // All vaults which have one transaction (either the funding, the canceling, the unvaulting, the spending)
    // inside the date range are retrieved.
    // This list might include vaults that were consumed again outside the range.
    let vaults = db_vaults_with_txids_in_period(&db_path, start, end, limit)?;

    // Used to retrieve the deposit from the Cancel outputs. Not a vector since the Cancel only
    // ever has a single deposit output.
    let mut vaults_by_outpoint_txid: HashMap<Txid, &DbVault> = HashMap::with_capacity(vaults.len());
    // Used for change detection when computing the deposit events.
    let mut final_txids: HashSet<Txid> = HashSet::with_capacity(vaults.len());
    for vault in &vaults {
        vaults_by_outpoint_txid.insert(vault.deposit_outpoint.txid, vault);
        if let Some(txid) = vault.final_txid {
            final_txids.insert(txid);
        }
    }
    // Map of the id and the vaults consumed by the final transaction.
    let mut spends: HashMap<Txid, Vec<&DbVault>> = HashMap::with_capacity(vaults.len());
    let mut events: Vec<HistoryEvent> = Vec::with_capacity(vaults.len());

    for vault in &vaults {
        if kind.contains(&HistoryEventKind::Deposit)
            // A vault may be retrieved as a change of a cancel or a spend in order to compute
            // change amount but not be in 'funded' state yet (because we usually require >1
            // conf).
            && vault.status != VaultStatus::Unconfirmed
            // Vault could have been moved but not deposited during the period.
            && vault.funded_at.expect("Vault is funded") >= start
            && vault.funded_at.expect("Vault is funded") <= end
            // Only deposits that are not a spend transaction change and not cancel output
            // are considered as history events.
            && !final_txids.contains(&vault.deposit_outpoint.txid)
        {
            events.push(HistoryEvent {
                kind: HistoryEventKind::Deposit,
                date: vault.funded_at.expect("Vault is funded"),
                blockheight: vault.blockheight,
                amount: Some(vault.amount.as_sat()),
                fee: None,
                txid: vault.deposit_outpoint.txid,
                vaults: vec![vault.deposit_outpoint],
            });
        }

        if kind.contains(&HistoryEventKind::Cancel)
            && vault.status == VaultStatus::Canceled
            && vault.moved_at.expect("Vault is canceled") >= start
            && vault.moved_at.expect("Vault is canceled") <= end
        {
            let txid = vault
                .final_txid
                .expect("Canceled vault must have a cancel txid");

            let cancel_tx = bitcoind_conn
                .wallet_tx(txid)?
                .expect("Cancel tx should be here");

            let cancel_height = match cancel_tx.blockheight {
                Some(h) => h,
                None => {
                    // It can only happen if the cancel transaction was just reorg'ed out.
                    // In this super edgy case, just ignore this entry.
                    continue;
                }
            };

            let change_amount = vaults_by_outpoint_txid
                .get(&txid)
                // if the change output did not create a vault because of the dust limit
                // the change_amount is equal to 0.
                .map_or(0, |vault| vault.amount.as_sat());

            events.push(HistoryEvent {
                kind: HistoryEventKind::Cancel,
                date: vault.moved_at.expect("Tx should be confirmed"),
                blockheight: cancel_height,
                amount: None,
                fee: Some(
                    vault
                        .amount
                        .as_sat()
                        .checked_sub(change_amount)
                        .expect("Moved funds include funds going back"),
                ),
                txid,
                vaults: vec![vault.deposit_outpoint],
            });
        }

        // In order to fill the spend map, only vaults that are
        // consumed between the two dates are kept.
        if kind.contains(&HistoryEventKind::Spend)
            && vault.status == VaultStatus::Spent
            && vault.moved_at.expect("Vault is spent") >= start
            && vault.moved_at.expect("Vault is spent") <= end
        {
            let txid = vault
                .final_txid
                .expect("Spent vault must have a spend txid");

            if let Some(vlts) = spends.get_mut(&txid) {
                vlts.push(vault);
            } else {
                spends.insert(txid, vec![vault]);
            }
        }
    }

    if kind.contains(&HistoryEventKind::Spend) {
        for (txid, spent_vaults) in spends {
            let spend_tx = bitcoind_conn
                .wallet_tx(txid)?
                .expect("Spend tx should be here");

            let spend_height = match spend_tx.blockheight {
                Some(h) => h,
                None => {
                    // It can only happen if the spend transaction was just reorg'ed out.
                    // In this super edgy case, just ignore this entry.
                    continue;
                }
            };

            let bytes =
                Vec::from_hex(&spend_tx.hex).expect("bitcoind returned a wrong transaction format");
            let tx: BitcoinTransaction =
                encode::deserialize(&bytes).expect("bitcoind returned a wrong transaction format");

            let derivation_index = spent_vaults
                .iter()
                .map(|v| v.derivation_index)
                .max()
                .expect("Spent vaults should not be empty");

            let cpfp_script_pubkey = revaultd
                .cpfp_descriptor
                .derive(derivation_index, &revaultd.secp_ctx)
                .into_inner()
                .script_pubkey();

            let deposit_address = revaultd
                .deposit_descriptor
                .derive(derivation_index, &revaultd.secp_ctx)
                .into_inner()
                .script_pubkey();

            let mut recipients_amount: u64 = 0;
            let mut change_amount: u64 = 0;
            for txout in tx.output {
                if cpfp_script_pubkey == txout.script_pubkey {
                    // this cpfp output is ignored and its amount is part of the fees
                } else if deposit_address == txout.script_pubkey {
                    change_amount += txout.value;
                } else {
                    recipients_amount += txout.value
                }
            }

            // fees is the total of the deposits minus the total of the spend outputs.
            // Fees include then the unvaulting fees and the spend fees.
            let fees = spent_vaults
                .iter()
                .map(|vlt| vlt.amount.as_sat())
                .sum::<u64>()
                .checked_sub(recipients_amount + change_amount)
                .expect("Funds moving include funds going back");

            events.push(HistoryEvent {
                date: spend_tx.received_time,
                blockheight: spend_height,
                kind: HistoryEventKind::Spend,
                amount: Some(recipients_amount),
                fee: Some(fees),
                txid,
                vaults: spent_vaults
                    .iter()
                    .map(|vault| vault.deposit_outpoint)
                    .collect(),
            })
        }
    }

    // Because a vault represents a deposit event and maybe a second event (cancel or spend),
    // the two timestamp `funded_at and `moved_at` must be taken in account. The list of vaults
    // can not considered as an ordered list of events. All events must be first filtered and
    // stored in a list before being ordered.
    events.sort_by(|a, b| b.date.cmp(&a.date));
    // Because a spend transaction may consume multiple vault and still count as one event,
    // and because the list of events must be first ordered by event date. The limit is enforced
    // at the end. (A limit was applied in the sql query only on the number of txids in the given period)
    events.truncate(limit as usize);
    Ok(events)
}

#[derive(Debug, Serialize)]
pub struct HistoryEvent {
    pub kind: HistoryEventKind,
    pub date: u32,
    pub blockheight: u32,
    pub amount: Option<u64>,
    pub fee: Option<u64>,
    pub txid: Txid,
    pub vaults: Vec<OutPoint>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum HistoryEventKind {
    #[serde(rename = "cancel")]
    Cancel,
    #[serde(rename = "deposit")]
    Deposit,
    #[serde(rename = "spend")]
    Spend,
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
mod tests {
    use crate::{
        control::*,
        database::{
            actions::{
                db_confirm_deposit, db_confirm_unvault, db_insert_new_unconfirmed_vault,
                db_update_presigned_txs,
            },
            bitcointx::RevaultTx,
            interface::{
                db_cancel_transaction, db_emer_transaction, db_exec, db_unvault_emer_transaction,
                db_unvault_transaction, db_vault_by_deposit,
            },
            schema::{DbTransaction, DbVault},
        },
        jsonrpc::UserRole,
        revaultd::{RevaultD, VaultStatus},
        setup_db,
        utils::test_utils::{dummy_revaultd, insert_vault_in_db, test_datadir, MockBitcoindThread},
    };
    use revault_tx::{
        bitcoin::{
            blockdata::transaction::OutPoint,
            hash_types::Txid,
            hashes::hex::FromHex,
            secp256k1,
            util::{amount::Amount, bip32::ChildNumber},
            PublicKey as BitcoinPubKey,
        },
        transactions::{
            CancelTransaction, EmergencyTransaction, RevaultTransaction,
            UnvaultEmergencyTransaction, UnvaultTransaction,
        },
    };
    use rusqlite::params;
    use std::{collections::BTreeMap, fs, str::FromStr};

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
                final_unvault: Some(UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAUaovJQUhwegF7P9qJBrWxtPq7dcJVPZ8MTjp9v8LUoDAAAAAAD9////AtCn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QwdQAAAAAAACIAIOD4aW9ds/RNXcNihA2bsw1c+bmg65auhz/3DoPPEg7oAAAAAAABASsYL+oLAAAAACIAIKdjkv/h5NjyHOPSensxUoTK3V1lFzGvS6zsG04Xdfs8IgICApM6sQN+rQqkp4WMbUnWcF4fs7xfZrAJGK97nwDs1SZIMEUCIQC18W4KdSJgg0w8PaNvCISyIxKXYbMRB6NBDmhz3Ok+hQIgV77oVG62xS9baMrBbp9pdAUjooB2Mqnx5hixZ48kQpoBIgICA8dJ8CWgfhsrU+VE3or4jMBtvGR/9hLUqLVpL5fBB7tIMEUCIQDmjTp2N3Pb7UKLyVy/85lgBa4Et6xMxi1ZeWy14gdVUQIgZu5u5/wDWv0evlPL1NdzINwO6h5yBiaNskl3VOrMGtoBIgICBnMMBWVan9BFRWk1mJUJsUOKEwiJI/uSjrLQ6Btb4DlIMEUCIQDJeX1L12SnJ+SBprTtTo57u3hcuzRTQ/y0AEwcfVSLegIgWrBVPnhhzYh2tw8gk0eGZJ4MaBInKrSiVXUoUuyvspYBIgICEUcipBjtxtFxFXI6CYvMq/KXtJxTVJETq5tRILViovxHMEQCIG5YQZzENXnaYNa57yz95VVFyDdJOU7zrEKAeuXzCtDCAiAH+tzK1BuBv2y1PF/HBOPl70JoCYREuAlmD8/oovZqGgEiAgJDFo5gffr4sTpOPvcI45wr3VtVCTh/yw/SiCJaCIjiV0cwRAIgE73DtQt36NOcekaFMGwuR4tBwuZpfzpT/iBUhVSKC3ECIE3+5Ixb/m1vfGeelQ2YPG24JFF511o9CTPpAySkQLd1ASICAsq7RLTptOoznxrLVOYVZez7c7CNiE0rx7Ts4ZZIIKc0RzBEAiBEWBtW23SxE9S/kpxQwIAAZzjNP+44oRmGJ/uFDW4WqAIgK5o4IsOQ1eYHGhayIzT3drzd2qBzZF/ODhh5b6+XkVEBIgIC6CJXMrp3sp02Gl+hpD2YHeku/rN95ivhprKBTRY+H9JIMEUCIQDtqwsuWxHTP3K+0GadKas1DuRm69MBZc/UpSyWUb/QvQIgczyuvIadVpF8qaGQ0gDYeCtcEGgGjL3mqp3A4fliYeoBIgIC9t7BqqGmkqEmYkK1StchrYTgch6CE1hR7eN1mk4/JaxHMEQCIBkfbFjrWBu2hM4uriAu0QNUeExTsTD8JqBZxo4zkHGzAiBwYMXCzPKBBcY0Wt9h1Au9bBvEdyR0qVt+AQy9ftQ3wQEiAgL5vFDdmMV/P4SpzIWhDMbHKHMGlMwntZxaWtwUXd9KvEcwRAIgc2Yp+nrcf8jozOH0zkoM5DRHA6VfFgeV7LxsUAXAaSACIFKiy1+WoD7cfJviCH6K+eAxdVWHXKr+/59G0GpUAi8UASICAvuWyyfoIfsyrTwNoR8N80zSBdfJrGff+D9XKBRL7aEFSDBFAiEAk5LsVb9ztXJa2boq6j/U+GS8rQ2IZMJMtY1Win7Xf7cCIHn+GWPTxQYlwVlRZjx+1nC8Y+C83hYjNzxeEyNvR1MEASICAzXQHO6KjAbz7OgmKxKccFYxsHZnt5oH/gWg1awnK9T0RzBEAiB2xY5QteSVL/U1Bm8Vv2s5kNBc3dMT2a48+NUzulNX0QIgTz/zcxaerGY+p/Iw8T9WzwLr8icSY2+sWx65a1P2Bm8BIgIDTm37cDT97U0sxMAhgCDeN0TLih+a3NKHx6ahcyh66xdIMEUCIQDyC6YFW72jfFHTeYvRAKB7sl/1ETvSvJQ6oXtvFM2LxwIgWd3pGOipAsisM9/2qGrnoWvvLm8dKqUHrachRGaskyIBIgIDTo4HmlEehH38tYZMerpLLhSBzzkjW1DITKYZ6Pr9+I1HMEQCICTUqQmMyIg6pRpb/rrVyRLxOOnCguqpytPH1cKg0RdiAiAQsgjOTio98PWUNcVqTODBMM2HJvURyN+GhJbUZDL3TwEiAgPAKvZof/JMq6C/mAv3iRqN76eVO6RzNYLzz9XqXigOjkcwRAIgSzN1LbuYv8y6tkZRvTZZeVYC32fXstGvgd7O1gRQEDcCIDTOeB3gocuzJpmBv1P/3Ktt9JCV5NY0DJlJK9012gDzAQEDBAEAAAABBUdSIQL7lssn6CH7Mq08DaEfDfNM0gXXyaxn3/g/VygUS+2hBSECQxaOYH36+LE6Tj73COOcK91bVQk4f8sP0ogiWgiI4ldSriIGAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBqCECBnMMBWVan9BFRWk1mJUJsUOKEwiJI/uSjrLQ6Btb4DmsUYdkdqkUb6EvZUC3JnDp5ob7670mID8QRt6IrGt2qRRFrmAKACpzZQe2b3NL6jaTgMGDHIisbJNSh2dSIQMPZLkiruL9WX8QS8bLO2cPHKLGxJsQcaGmwBBXXZT+WiECq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5Sr1OyaCICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBJSECWDjcCUoChdvjsfivEoK7jSMGDPuXWy85IUr436Ago52sUYciAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap()),
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
            )
            .unwrap();
        }

        // First vault: Funded
        db_confirm_deposit(
            &db_file,
            &outpoints[1],
            9, // blockheight
            9, // blocktime
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
            9, // blocktime
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
                "UPDATE vaults SET status = (?1), secured_at = strftime('%s','now') \
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
            9, // blocktime
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
                "UPDATE vaults SET status = (?1), secured_at = strftime('%s','now'), delegated_at = strftime('%s','now') \
             WHERE vaults.id = (?2)",
                params![VaultStatus::Active as u32, vaults[3].id],
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

    #[test]
    fn test_get_history() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);
        setup_db(&mut revaultd).unwrap();
        let db_file = revaultd.db_file();

        let cancel_tx_hex = "0200000000010158a2f36c1be4e32f59d26930f64c452c81ffb1fc66bb96e8ddb477f0bacfb6660000000000fdffffff011042f4050000000022002025bfbde3ae8bd9381b9ddb837acdab48a3110cbeb05e84cb57b28d77e27794480747304402201b4c8061cb2fb8c086fdedba3787cd30bc765b0f4ba47b22e3b37fe5289ded4602204da79a4637ad85c4d17f9a840c4b50336b7072f5ca482507d9d1070ecf7f105e812103d7c8e6ff708e052a15e4c23f16c7143c2b0c98473a7fd6c1d10850a274319a5a483045022100860539abb4a1172625fcdb913759c54364063a28d707c22204d18ec5b4ffeede0220442e1560b506da56cefd4e4d603c3381c036de777e264f923fe6d81e8d6870cb8121034c8ecf7547552e8c3ca3e0d1189f09b23b92bce3c73186800e7089230cecf6810000ed5121027cf27be4980b5945b1fb4594c0a9cef39278d8a8d59ad0f001acf72a45d17fea21029091080c1f00962c6ef10d0f5346d5aecab6f65543670aa78ae21520b8a3cd2221027fa470475563f20c96b997224fe86bc9564ccad9adb77e083ccd3bdfc94fe9ed53ae6476a914927ea7d35721b017ffed4941ec764b36f730faa288ac6b76a91416b43735b6c445fa5f279c2afa70bfaf375f075388ac6c93528767522102abe475b199ec3d62fa576faee16a334fdb86ffb26dce75becebaaedf328ac3fe21030f64b922aee2fd597f104bc6cb3b670f1ca2c6c49b1071a1a6c010575d94fe5a52af0112b26800000000";
        let spend_tx_hex = "0200000001b4243a48b54cc360e754e0175a985a49b67cf4615d8523ec5aa46d42421cdf7d0000000000504200000280b2010000000000220020b9be8f8574f8da64bb1cb6668f6134bc4706df7936eeab8411f9d82de20a895b08280954020000000000000000";

        let cancel_tx: BitcoinTransaction =
            encode::deserialize(&Vec::from_hex(cancel_tx_hex).unwrap()).unwrap();

        let spend_tx: BitcoinTransaction =
            encode::deserialize(&Vec::from_hex(spend_tx_hex).unwrap()).unwrap();

        let deposit1_outpoint = OutPoint::new(
            Txid::from_str("fcb6ab963b654c773de786f4ac92c132b3d2e816ccea37af9592aa0b4aaec04b")
                .unwrap(),
            0,
        );

        let deposit2_outpoint = OutPoint::new(
            Txid::from_str("cafa9f92be48ba41f9ee67e775b6c4afebd1bdbde5758792e9f30f6dea41e7fb")
                .unwrap(),
            1,
        );

        insert_vault_in_db(
            &db_file,
            1,
            &deposit1_outpoint,
            &Amount::ONE_BTC,
            1,
            ChildNumber::from_normal_idx(0).unwrap(),
            Some(1),
            Some(2),
            VaultStatus::Canceled,
            Some(&cancel_tx.txid()),
        );

        insert_vault_in_db(
            &db_file,
            1,
            &OutPoint::new(cancel_tx.txid(), 0),
            &Amount::from_sat(cancel_tx.output[0].value),
            2,
            ChildNumber::from_normal_idx(1).unwrap(),
            Some(2),
            None,
            VaultStatus::Funded,
            None,
        );

        insert_vault_in_db(
            &db_file,
            1,
            &deposit2_outpoint,
            &Amount::from_sat(200_000_000_000),
            1,
            ChildNumber::from_normal_idx(0).unwrap(),
            Some(3),
            Some(4),
            VaultStatus::Spent,
            Some(&spend_tx.txid()),
        );

        // change of the spend
        insert_vault_in_db(
            &db_file,
            1,
            &OutPoint::new(spend_tx.txid(), 0),
            &Amount::from_sat(spend_tx.output[0].value),
            2,
            ChildNumber::from_normal_idx(1).unwrap(),
            Some(4),
            None,
            VaultStatus::Funded,
            None,
        );

        let mut txs = HashMap::new();
        txs.insert(
            cancel_tx.txid(),
            WalletTransaction {
                hex: cancel_tx_hex.to_string(),
                received_time: 2,
                blocktime: Some(2),
                blockheight: Some(2),
            },
        );
        txs.insert(
            spend_tx.txid(),
            WalletTransaction {
                hex: spend_tx_hex.to_string(),
                received_time: 4,
                blocktime: Some(4),
                blockheight: Some(4),
            },
        );
        let bitcoind_conn = MockBitcoindThread::new(txs);

        let events = get_history(
            &revaultd,
            &bitcoind_conn,
            0,
            4,
            20,
            vec![
                HistoryEventKind::Deposit,
                HistoryEventKind::Cancel,
                HistoryEventKind::Spend,
            ],
        )
        .unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].txid, spend_tx.txid());
        assert_eq!(events[0].kind, HistoryEventKind::Spend);
        assert_eq!(events[0].date, 4);
        assert_eq!(
            events[0].amount.unwrap(),
            spend_tx.output[0].value + spend_tx.output[1].value
        );
        assert_eq!(
            events[0].fee.unwrap(),
            200_000_000_000 - spend_tx.output[0].value - spend_tx.output[1].value,
        );
        assert_eq!(events[0].vaults, vec![deposit2_outpoint]);

        assert_eq!(events[1].txid, deposit2_outpoint.txid);
        assert_eq!(events[1].kind, HistoryEventKind::Deposit);
        assert_eq!(events[1].date, 3);
        assert_eq!(events[1].fee, None);
        assert_eq!(events[1].amount, Some(200_000_000_000));
        assert_eq!(events[1].vaults, vec![deposit2_outpoint]);

        assert_eq!(events[2].txid, cancel_tx.txid());
        assert_eq!(events[2].kind, HistoryEventKind::Cancel);
        assert!(events[2].amount.is_none());
        assert_eq!(events[2].date, 2);
        assert_eq!(
            events[2].fee.unwrap(),
            Amount::ONE_BTC.as_sat() - cancel_tx.output[0].value
        );
        assert_eq!(events[3].txid, deposit1_outpoint.txid);
        assert_eq!(events[3].kind, HistoryEventKind::Deposit);
        assert_eq!(events[3].vaults, vec![deposit1_outpoint]);

        // retrieve events later in history
        let events = get_history(
            &revaultd,
            &bitcoind_conn,
            0,
            2,
            20,
            vec![
                HistoryEventKind::Deposit,
                HistoryEventKind::Cancel,
                HistoryEventKind::Spend,
            ],
        )
        .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].date, 2);
        assert_eq!(events[0].txid, cancel_tx.txid());
        assert_eq!(events[0].kind, HistoryEventKind::Cancel);
        assert!(events[0].amount.is_none());
        assert_eq!(
            events[0].fee.unwrap(),
            Amount::ONE_BTC.as_sat() - cancel_tx.output[0].value
        );
        assert_eq!(events[0].vaults, vec![deposit1_outpoint]);

        assert_eq!(events[1].date, 1);
        assert_eq!(events[1].txid, deposit1_outpoint.txid);
        assert_eq!(events[1].kind, HistoryEventKind::Deposit);
        assert_eq!(events[1].fee, None);
        assert_eq!(events[1].amount, Some(Amount::ONE_BTC.as_sat()));
        assert_eq!(events[1].vaults, vec![deposit1_outpoint]);

        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }
}
