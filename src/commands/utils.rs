//! This module contains routines for controlling our actions (checking signatures, communicating
//! with servers, with bitcoind, ..). Requests may originate from the RPC server or the signature
//! fetcher thread.

use crate::{
    commands::{
        CommandError, HistoryEvent, HistoryEventKind, ListOnchainTxEntry, ListPresignedTxEntry,
        ListVaultsEntry, OnchainTxEntry,
    },
    database::{
        interface::{
            db_cancel_transaction, db_emer_transaction, db_signed_emer_txs, db_signed_unemer_txs,
            db_unvault_emer_transaction, db_unvault_transaction, db_vault_by_deposit, db_vaults,
            db_vaults_with_final_txid, db_vaults_with_txids_in_period,
        },
        schema::DbVault,
        DatabaseError,
    },
    revaultd::{RevaultD, VaultStatus},
    threadmessages::*,
};

use revault_tx::{
    bitcoin::{
        consensus::encode, hashes::hex::FromHex, secp256k1, util::bip32::ChildNumber, Amount,
        OutPoint, Transaction as BitcoinTransaction, Txid,
    },
    miniscript::DescriptorTrait,
    scripts::{CpfpDescriptor, DepositDescriptor},
    transactions::{CpfpableTransaction, RevaultTransaction, UnvaultTransaction},
    txins::{DepositTxIn, RevaultTxIn},
    txouts::{DepositTxOut, RevaultTxOut},
};

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    str::FromStr,
};

use serde::{de, Deserialize, Deserializer, Serializer};

/// Serialize a field as a string
pub fn ser_to_string<T: fmt::Display, S: Serializer>(field: T, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&field.to_string())
}

/// Deserialize a type `S` by deserializing a string, then using the `FromStr`
/// impl of `S` to create the result. The generic type `S` is not required to
/// implement `Deserialize`.
pub fn deser_from_str<'de, S, D>(deserializer: D) -> Result<S, D::Error>
where
    S: FromStr,
    S::Err: fmt::Display,
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    S::from_str(&s).map_err(de::Error::custom)
}

/// Serialize an amount as sats
pub fn ser_amount<S: Serializer>(amount: &Amount, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u64(amount.as_sat())
}

/// Deserialize an amount from sats
pub fn deser_amount_from_sats<'de, D>(deserializer: D) -> Result<Amount, D::Error>
where
    D: Deserializer<'de>,
{
    let a = u64::deserialize(deserializer)?;
    Ok(Amount::from_sat(a))
}

/// List the vaults from DB, and filter out the info the RPC wants
// FIXME: we could make this more efficient with smarter SQL queries
pub fn listvaults_from_db(
    revaultd: &RevaultD,
    statuses: Option<&[VaultStatus]>,
    outpoints: Option<&[OutPoint]>,
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
                let op = db_vault.deposit_outpoint;
                Some(ListVaultsEntry {
                    amount: db_vault.amount,
                    blockheight: db_vault.deposit_blockheight,
                    status: db_vault.status,
                    txid: op.txid,
                    vout: op.vout,
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
) -> Result<Vec<DbVault>, CommandError> {
    let mut vaults = Vec::with_capacity(outpoints.len());

    for outpoint in outpoints.iter() {
        // Note: being smarter with SQL queries implies enabling the 'table' feature of rusqlite
        // with a shit ton of dependencies.
        if let Some(vault) =
            db_vault_by_deposit(db_path, outpoint).expect("Database must be available")
        {
            if invalid_statuses.contains(&vault.status) {
                return Err(CommandError::InvalidStatusFor(vault.status, *outpoint));
            }
            vaults.push(vault);
        } else {
            return Err(CommandError::UnknownOutpoint(*outpoint));
        }
    }

    Ok(vaults)
}

// FIXME: make this a DB query altogether...
/// List all the presigned transactions from these confirmed vaults.
///
/// Will panic on database failure.
/// Will return None if any transaction could not be fetched from DB.
pub fn presigned_txs(
    revaultd: &RevaultD,
    db_vaults: Vec<DbVault>,
) -> Option<Vec<ListPresignedTxEntry>> {
    let db_path = &revaultd.db_file();

    // For each presigned transaction, append it as well as its extracted version if it's final.
    let mut tx_list = Vec::with_capacity(db_vaults.len());
    for db_vault in db_vaults {
        let vault_outpoint = db_vault.deposit_outpoint;

        let unvault = db_unvault_transaction(db_path, db_vault.id)
            .expect("Database must be available")?
            .psbt
            .assert_unvault();
        let cancel = db_cancel_transaction(db_path, db_vault.id)
            .expect("Database must be available")?
            .psbt
            .assert_cancel();

        let mut emergency = None;
        let mut unvault_emergency = None;
        if revaultd.is_stakeholder() {
            emergency = Some(
                db_emer_transaction(db_path, db_vault.id)
                    .expect("Database must be available")?
                    .psbt
                    .assert_emer(),
            );
            unvault_emergency = Some(
                db_unvault_emer_transaction(db_path, db_vault.id)
                    .expect("Database must be available")?
                    .psbt
                    .assert_unvault_emer(),
            );
        }

        tx_list.push(ListPresignedTxEntry {
            vault_outpoint,
            unvault,
            cancel,
            emergency,
            unvault_emergency,
        });
    }

    Some(tx_list)
}

/// Get all the finalized Emergency transactions for each vault, depending on wether the Unvault
/// was already broadcast or not (ie get the one spending from the deposit or the Unvault tx).
pub fn finalized_emer_txs(revaultd: &RevaultD) -> Result<Vec<BitcoinTransaction>, CommandError> {
    let db_path = revaultd.db_file();

    let emer_iter = db_signed_emer_txs(&db_path)
        .expect("Database must be accessible")
        .into_iter()
        .map(|mut tx| {
            tx.finalize(&revaultd.secp_ctx)?;
            Ok(tx.into_psbt().extract_tx())
        });
    let unemer_iter = db_signed_unemer_txs(&db_path)
        .expect("Database must be accessible")
        .into_iter()
        .map(|mut tx| {
            tx.finalize(&revaultd.secp_ctx)?;
            Ok(tx.into_psbt().extract_tx())
        });

    emer_iter
        .chain(unemer_iter)
        .collect::<Result<Vec<BitcoinTransaction>, revault_tx::Error>>()
        .map_err(|e| e.into())
}

/// Finds the cpfp and change output indexes of a spend transaction by deriving the scripts
/// from descriptors and checking them against outputs scripts.
pub fn get_spend_tx_change_and_cpfp_indexes(
    derivation_index: ChildNumber,
    deposit_descriptor: &DepositDescriptor,
    cpfp_descriptor: &CpfpDescriptor,
    secp_ctx: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    tx: &BitcoinTransaction,
) -> (Option<usize>, Option<usize>) {
    let cpfp_script_pubkey = cpfp_descriptor
        .derive(derivation_index, &secp_ctx)
        .into_inner()
        .script_pubkey();
    let deposit_address = deposit_descriptor
        .derive(derivation_index, &secp_ctx)
        .into_inner()
        .script_pubkey();
    let mut cpfp_index = None;
    let mut change_index = None;
    for (i, txout) in tx.output.iter().enumerate() {
        if cpfp_index.is_none() && cpfp_script_pubkey == txout.script_pubkey {
            cpfp_index = Some(i);
        }

        if deposit_address == txout.script_pubkey {
            change_index = Some(i);
        }
    }
    (change_index, cpfp_index)
}

/// list_onchain_txs retrieves onchain transactions linked to the vaults with the given outpoints.
pub fn list_onchain_txs<T: BitcoindThread>(
    revaultd: &RevaultD,
    bitcoind_conn: &T,
    outpoints: &[OutPoint],
) -> Result<Vec<ListOnchainTxEntry>, CommandError> {
    let db_path = revaultd.db_file();

    let db_vaults = if outpoints.is_empty() {
        db_vaults(&db_path).expect("Database must be available")
    } else {
        // We accept any status
        vaults_from_deposits(&db_path, &outpoints, &[])?
    };

    let mut tx_list = Vec::with_capacity(db_vaults.len());

    // Some vaults have the same spend as their final transaction.
    // It is better to cache it for performance.
    let mut spend_tx_cache = BTreeMap::<Txid, OnchainTxEntry>::new();

    for db_vault in db_vaults {
        let vault_outpoint = db_vault.deposit_outpoint;

        // If the vault exist, there must always be a deposit transaction available.
        let deposit = OnchainTxEntry::new(
            bitcoind_conn
                .wallet_tx(db_vault.deposit_outpoint.txid)?
                .expect("Vault exists but not deposit tx?"),
            None,
            None,
        );

        let unvault = if [
            VaultStatus::Unvaulting,
            VaultStatus::Unvaulted,
            VaultStatus::Spending,
            VaultStatus::Spent,
            VaultStatus::Canceling,
            VaultStatus::Canceled,
            VaultStatus::UnvaultEmergencyVaulting,
            VaultStatus::UnvaultEmergencyVaulted,
        ]
        .contains(&db_vault.status)
        {
            let unvault_db_tx = db_unvault_transaction(&db_path, db_vault.id)
                .expect("Database must be available")
                .ok_or(CommandError::Race)?;
            bitcoind_conn
                .wallet_tx(unvault_db_tx.psbt.txid())?
                .map(|tx| {
                    let cpfp_script_pubkey = revaultd
                        .cpfp_descriptor
                        .derive(db_vault.derivation_index, &revaultd.secp_ctx)
                        .into_inner()
                        .script_pubkey();
                    let cpfp_index = unvault_db_tx
                        .psbt
                        .unwrap_unvault()
                        .tx()
                        .output
                        .iter()
                        .enumerate()
                        .find_map(|(i, txout)| {
                            if cpfp_script_pubkey == txout.script_pubkey {
                                Some(i)
                            } else {
                                None
                            }
                        })
                        .expect("Unvault tx must have a cpfp_index");

                    OnchainTxEntry::new(tx, None, Some(cpfp_index))
                })
        } else {
            None
        };

        let cancel = if db_vault.status == VaultStatus::Canceling
            || db_vault.status == VaultStatus::Canceled
        {
            bitcoind_conn
                .wallet_tx(db_vault.final_txid.expect("Must have a cancel txid"))?
                .map(|tx| OnchainTxEntry::new(tx, None, None))
        } else {
            None
        };

        let spend =
            if db_vault.status == VaultStatus::Spending || db_vault.status == VaultStatus::Spent {
                let txid = db_vault.final_txid.expect("Must have a spend txid");
                if let Some(tx) = spend_tx_cache.get(&txid) {
                    Some(tx.clone())
                } else {
                    let tx = bitcoind_conn.wallet_tx(txid)?.map(|tx| {
                        let spend: BitcoinTransaction =
                            encode::deserialize(&Vec::from_hex(&tx.hex).unwrap()).unwrap();
                        let spent_vaults =
                            db_vaults_with_final_txid(&db_path, &txid).expect("Vaults must exist");
                        let derivation_index = spent_vaults
                            .iter()
                            .map(|v| v.derivation_index)
                            .max()
                            .expect("List cannot be empty");
                        let (change_index, cpfp_index) = get_spend_tx_change_and_cpfp_indexes(
                            derivation_index,
                            &revaultd.deposit_descriptor,
                            &revaultd.cpfp_descriptor,
                            &revaultd.secp_ctx,
                            &spend,
                        );
                        OnchainTxEntry::new(tx, change_index, cpfp_index)
                    });
                    // Some vaults have the same spend as their final transaction.
                    // It is better to cache it for performance.
                    if let Some(tx) = &tx {
                        spend_tx_cache.insert(txid, tx.clone());
                    }
                    tx
                }
            } else {
                None
            };

        let emergency = if revaultd.is_stakeholder()
            && (db_vault.status == VaultStatus::EmergencyVaulting
                || db_vault.status == VaultStatus::EmergencyVaulted)
        {
            let emer_db_tx = db_emer_transaction(&db_path, db_vault.id)
                .expect("Database must be available")
                .ok_or(CommandError::Race)?;
            bitcoind_conn
                .wallet_tx(emer_db_tx.psbt.txid())?
                .map(|tx| OnchainTxEntry::new(tx, None, None))
        } else {
            None
        };

        let unvault_emergency = if revaultd.is_stakeholder()
            && (db_vault.status == VaultStatus::UnvaultEmergencyVaulting
                || db_vault.status == VaultStatus::UnvaultEmergencyVaulted)
        {
            let emer_db_tx = db_unvault_emer_transaction(&db_path, db_vault.id)
                .expect("Database must be available")
                .ok_or(CommandError::Race)?;
            bitcoind_conn
                .wallet_tx(emer_db_tx.psbt.txid())?
                .map(|tx| OnchainTxEntry::new(tx, None, None))
        } else {
            None
        };

        tx_list.push(ListOnchainTxEntry {
            vault_outpoint,
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

/// gethistory retrieves a limited list of events which occured between two given dates.
pub fn gethistory<T: BitcoindThread>(
    revaultd: &RevaultD,
    bitcoind_conn: &T,
    start: u32,
    end: u32,
    limit: u64,
    kind: &[HistoryEventKind],
) -> Result<Vec<HistoryEvent>, CommandError> {
    let db_path = revaultd.db_file();
    // All vaults which have one transaction (either the funding, the canceling, the unvaulting, the spending)
    // inside the date range are retrieved.
    // This list might include vaults that were consumed again outside the range.
    let vaults = db_vaults_with_txids_in_period(&db_path, start, end, limit)
        .expect("Database must be accessible");

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
                blockheight: vault.deposit_blockheight.expect("Vault is funded"),
                amount: Some(vault.amount.as_sat()),
                cpfp_amount: None,
                miner_fee: None,
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

            let unvault = UnvaultTransaction::new(
                DepositTxIn::new(
                    vault.deposit_outpoint,
                    DepositTxOut::new(
                        vault.amount,
                        &revaultd
                            .deposit_descriptor
                            .derive(vault.derivation_index, &revaultd.secp_ctx),
                    ),
                ),
                &revaultd
                    .unvault_descriptor
                    .derive(vault.derivation_index, &revaultd.secp_ctx),
                &revaultd
                    .cpfp_descriptor
                    .derive(vault.derivation_index, &revaultd.secp_ctx),
                revaultd.lock_time,
            )
            .expect("Spent vault must have a correct unvault transaction");

            let cpfp_amount = unvault
                .cpfp_txin(&revaultd.cpfp_descriptor, &revaultd.secp_ctx)
                .expect("Unvault tx has always a cpfp output")
                .txout()
                .txout()
                .value;

            events.push(HistoryEvent {
                kind: HistoryEventKind::Cancel,
                date: vault.moved_at.expect("Tx should be confirmed"),
                blockheight: cancel_height,
                amount: None,
                cpfp_amount: Some(cpfp_amount),
                miner_fee: Some(
                    vault
                        .amount
                        .as_sat()
                        .checked_sub(change_amount + cpfp_amount)
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
            let mut cpfp_amount: u64 = 0;
            for txout in tx.output {
                if cpfp_script_pubkey == txout.script_pubkey {
                    cpfp_amount += txout.value;
                } else if deposit_address == txout.script_pubkey {
                    change_amount += txout.value;
                } else {
                    recipients_amount += txout.value
                }
            }

            for vault in &spent_vaults {
                cpfp_amount += UnvaultTransaction::new(
                    DepositTxIn::new(
                        vault.deposit_outpoint,
                        DepositTxOut::new(
                            vault.amount,
                            &revaultd
                                .deposit_descriptor
                                .derive(vault.derivation_index, &revaultd.secp_ctx),
                        ),
                    ),
                    &revaultd
                        .unvault_descriptor
                        .derive(vault.derivation_index, &revaultd.secp_ctx),
                    &revaultd
                        .cpfp_descriptor
                        .derive(vault.derivation_index, &revaultd.secp_ctx),
                    revaultd.lock_time,
                )
                .expect("Spent vault must have a correct unvault transaction")
                .cpfp_txin(&revaultd.cpfp_descriptor, &revaultd.secp_ctx)
                .expect("Unvault tx has always a cpfp output")
                .txout()
                .txout()
                .value;
            }

            // fees is the total of the deposits minus the total of the spend outputs.
            // Fees include then the unvaulting fees and the spend fees.
            let fees = spent_vaults
                .iter()
                .map(|vlt| vlt.amount.as_sat())
                .sum::<u64>()
                .checked_sub(recipients_amount + change_amount + cpfp_amount)
                .expect("Funds moving include funds going back");

            events.push(HistoryEvent {
                date: spend_tx.received_time,
                blockheight: spend_height,
                kind: HistoryEventKind::Spend,
                amount: Some(recipients_amount),
                cpfp_amount: Some(cpfp_amount),
                miner_fee: Some(fees),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bitcoind::interface::WalletTransaction,
        database::{
            actions::{
                db_confirm_deposit, db_confirm_unvault, db_insert_new_unconfirmed_vault,
                db_mark_spent_unvault, db_update_presigned_txs,
            },
            bitcointx::RevaultTx,
            interface::{
                db_cancel_transaction, db_emer_transaction, db_exec, db_unvault_emer_transaction,
                db_unvault_transaction, db_vault_by_deposit,
            },
            schema::{DbTransaction, DbVault},
        },
        revaultd::{RevaultD, UserRole, VaultStatus},
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
        scripts::UnvaultDescriptor,
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
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::StakeholderManager);
        setup_db(&mut revaultd).unwrap();
        let vaults = create_vaults(&revaultd);

        // Checking that the result is sane
        for v in &vaults {
            let res = &listvaults_from_db(
                &revaultd,
                Some(&[v.db_vault.status]),
                Some(&[v.db_vault.deposit_outpoint]),
            )
            .unwrap()[0];
            assert_eq!(res.amount, v.db_vault.amount);
            assert_eq!(res.blockheight, v.db_vault.deposit_blockheight);
            assert_eq!(res.status, v.db_vault.status);
            assert_eq!(res.txid, v.db_vault.deposit_outpoint.txid);
            assert_eq!(res.vout, v.db_vault.deposit_outpoint.vout);
            assert_eq!(
                res.derivation_index,
                ChildNumber::from_normal_idx(0).unwrap()
            );
        }

        // Checking that filters work
        assert_eq!(listvaults_from_db(&revaultd, None, None).unwrap().len(), 4);
        assert_eq!(
            listvaults_from_db(&revaultd, Some(&[VaultStatus::Unconfirmed]), None)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            listvaults_from_db(
                &revaultd,
                Some(&[VaultStatus::Unconfirmed]),
                Some(&[vaults[1].db_vault.deposit_outpoint])
            )
            .unwrap()
            .len(),
            0
        );
        assert_eq!(
            listvaults_from_db(
                &revaultd,
                None,
                Some(&[
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
                Some(&[
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
                Some(&[
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
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::StakeholderManager);
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
                    &CommandError::InvalidStatusFor(VaultStatus::Unconfirmed, outpoints[0])
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
                .contains(&CommandError::UnknownOutpoint(wrong_outpoint).to_string())
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
        assert!(presigned_txs(&stake_revaultd, vec![vaults[0].db_vault.clone()]).is_none());

        // vault[1] is funded, no txs is final
        // The stakeholder has all the txs
        let stake_txs = presigned_txs(&stake_revaultd, vec![vaults[1].db_vault.clone()]).unwrap();
        assert_eq!(stake_txs.len(), 1);
        assert_eq!(
            stake_txs[0].vault_outpoint,
            vaults[1].db_vault.deposit_outpoint
        );
        assert_eq!(
            stake_txs[0].cancel,
            vaults[1].transactions.as_ref().unwrap().initial_cancel
        );
        assert_eq!(
            stake_txs[0].unvault,
            vaults[1].transactions.as_ref().unwrap().initial_unvault
        );
        assert_eq!(
            stake_txs[0].emergency.as_ref().unwrap(),
            &vaults[1].transactions.as_ref().unwrap().initial_emer
        );
        assert_eq!(
            stake_txs[0].unvault_emergency.as_ref().unwrap(),
            &vaults[1]
                .transactions
                .as_ref()
                .unwrap()
                .initial_unvault_emer
        );

        // The manager has the same txs, but no emergency
        let man_txs = presigned_txs(&man_revaultd, vec![vaults[1].db_vault.clone()]).unwrap();
        assert_eq!(man_txs.len(), 1);
        assert_eq!(
            man_txs[0].vault_outpoint,
            vaults[1].db_vault.deposit_outpoint
        );
        assert_eq!(
            man_txs[0].cancel,
            vaults[1].transactions.as_ref().unwrap().initial_cancel
        );
        assert_eq!(
            man_txs[0].unvault,
            vaults[1].transactions.as_ref().unwrap().initial_unvault
        );
        assert!(man_txs[0].emergency.is_none());
        assert!(man_txs[0].unvault_emergency.is_none());

        // vault[2] is secured, the unvault tx is not final
        // The stakeholder has all the txs
        let stake_txs = presigned_txs(&stake_revaultd, vec![vaults[2].db_vault.clone()]).unwrap();
        assert_eq!(stake_txs.len(), 1);
        assert_eq!(
            stake_txs[0].vault_outpoint,
            vaults[2].db_vault.deposit_outpoint
        );
        assert_eq!(
            &stake_txs[0].cancel,
            vaults[2]
                .transactions
                .as_ref()
                .unwrap()
                .final_cancel
                .as_ref()
                .unwrap()
        );
        assert_eq!(
            stake_txs[0].unvault,
            vaults[2].transactions.as_ref().unwrap().initial_unvault
        );
        assert_eq!(
            stake_txs[0].emergency.as_ref().unwrap(),
            vaults[2]
                .transactions
                .as_ref()
                .unwrap()
                .final_emer
                .as_ref()
                .unwrap()
        );
        assert_eq!(
            stake_txs[0].unvault_emergency.as_ref().unwrap(),
            vaults[2]
                .transactions
                .as_ref()
                .unwrap()
                .final_unvault_emer
                .as_ref()
                .unwrap()
        );

        // The manager has the same txs, but no emergency
        let man_txs = presigned_txs(&man_revaultd, vec![vaults[2].db_vault.clone()]).unwrap();
        assert_eq!(man_txs.len(), 1);
        assert_eq!(
            man_txs[0].vault_outpoint,
            vaults[2].db_vault.deposit_outpoint
        );
        assert_eq!(
            &man_txs[0].cancel,
            vaults[2]
                .transactions
                .as_ref()
                .unwrap()
                .final_cancel
                .as_ref()
                .unwrap()
        );
        assert_eq!(
            man_txs[0].unvault,
            vaults[2].transactions.as_ref().unwrap().initial_unvault
        );
        assert!(man_txs[0].emergency.is_none());
        assert!(man_txs[0].unvault_emergency.is_none());

        // vault[3] is active, every tx is final
        // The stakeholder has all the txs
        let stake_txs = presigned_txs(&stake_revaultd, vec![vaults[3].db_vault.clone()]).unwrap();
        assert_eq!(stake_txs.len(), 1);
        assert_eq!(
            stake_txs[0].vault_outpoint,
            vaults[3].db_vault.deposit_outpoint
        );
        assert_eq!(
            &stake_txs[0].cancel,
            vaults[3]
                .transactions
                .as_ref()
                .unwrap()
                .final_cancel
                .as_ref()
                .unwrap()
        );
        assert_eq!(
            &stake_txs[0].unvault,
            vaults[3]
                .transactions
                .as_ref()
                .unwrap()
                .final_unvault
                .as_ref()
                .unwrap()
        );
        assert_eq!(
            stake_txs[0].emergency.as_ref().unwrap(),
            vaults[3]
                .transactions
                .as_ref()
                .unwrap()
                .final_emer
                .as_ref()
                .unwrap()
        );
        assert_eq!(
            stake_txs[0].unvault_emergency.as_ref().unwrap(),
            vaults[3]
                .transactions
                .as_ref()
                .unwrap()
                .final_unvault_emer
                .as_ref()
                .unwrap()
        );

        // The manager has the same txs, but no emergency
        let man_txs = presigned_txs(&man_revaultd, vec![vaults[3].db_vault.clone()]).unwrap();
        assert_eq!(man_txs.len(), 1);
        assert_eq!(
            man_txs[0].vault_outpoint,
            vaults[3].db_vault.deposit_outpoint
        );
        assert_eq!(
            &man_txs[0].cancel,
            vaults[3]
                .transactions
                .as_ref()
                .unwrap()
                .final_cancel
                .as_ref()
                .unwrap()
        );
        assert_eq!(
            &man_txs[0].unvault,
            vaults[3]
                .transactions
                .as_ref()
                .unwrap()
                .final_unvault
                .as_ref()
                .unwrap()
        );
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
        let unvault_height = 153;
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
            unvault_height,
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
            unvault_height,
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
    fn test_list_onchain_txs() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::StakeholderManager);
        setup_db(&mut revaultd).unwrap();
        let db_file = revaultd.db_file();
        revaultd.cpfp_descriptor = CpfpDescriptor::from_str("wsh(multi(1,tpubD6NzVbkrYhZ4XkehE7ghxNboGmT4Pd1SZ9RWLN5dG5vgRKXQgSxYtsmUgAYsqzdbK9petorBFceU36PNAfkVmrMhfNsJRSoiyWpu6NJA1BQ/*,tpubD6NzVbkrYhZ4XyJXPpnkwCpTazWgerTFgXLtVehbPyoNKVFfPgXRcoxLGupEES1tSteVGsJon85AxEzGyWVSxm8LX8bdZsz87GWt585X2wf/*))#8h972ae2").unwrap();
        revaultd.deposit_descriptor = DepositDescriptor::from_str("wsh(multi(2,tpubD6NzVbkrYhZ4WmzFjvQrp7sDa4ECUxTi9oby8K4FZkd3XCBtEdKwUiQyYJaxiJo5y42gyDWEczrFpozEjeLxMPxjf2WtkfcbpUdfvNnozWF/*,tpubD6NzVbkrYhZ4XyJXPpnkwCpTazWgerTFgXLtVehbPyoNKVFfPgXRcoxLGupEES1tSteVGsJon85AxEzGyWVSxm8LX8bdZsz87GWt585X2wf/*))#36w5x8qy").unwrap();
        revaultd.unvault_descriptor = UnvaultDescriptor::from_str("wsh(andor(multi(1,tpubD6NzVbkrYhZ4XcB3kRJVob8bmjMvA2zBuagidVzh7ASY5FyAEtq4nTzx9wHYu5XDQAg7vdFNiF6yX38kTCK8zjVVmFTiQR2YKAqZBTGjnoD/*,tpubD6NzVbkrYhZ4XkehE7ghxNboGmT4Pd1SZ9RWLN5dG5vgRKXQgSxYtsmUgAYsqzdbK9petorBFceU36PNAfkVmrMhfNsJRSoiyWpu6NJA1BQ/*),older(10),thresh(2,pkh(tpubD6NzVbkrYhZ4WmzFjvQrp7sDa4ECUxTi9oby8K4FZkd3XCBtEdKwUiQyYJaxiJo5y42gyDWEczrFpozEjeLxMPxjf2WtkfcbpUdfvNnozWF/*),a:pkh(tpubD6NzVbkrYhZ4XyJXPpnkwCpTazWgerTFgXLtVehbPyoNKVFfPgXRcoxLGupEES1tSteVGsJon85AxEzGyWVSxm8LX8bdZsz87GWt585X2wf/*))))#lej6yrsc").unwrap();

        let deposit1_tx_hex = "02000000000102a97dfa121adf217ff633ec600d8f2d10544ad83f4081dc5edb15b267dc8780770000000000feffffffa97dfa121adf217ff633ec600d8f2d10544ad83f4081dc5edb15b267dc8780770100000000feffffff0200ab90410000000022002024c9386efc4c8adef217b2931caed1cf4891f49770526ad5703d6893b49102ce17d0f0080000000016001474afe13dccd961647c8a394d0ff32f2b1bad78d702473044022049a2319c7f317774ddeb41e2656b92fefc418234230ae20d115ef353326b01d70220269deb1f678c8dd9f179b6caab6d762b33d28316eeb325fc87857005042cf56d012103d2258b9d4e626e65dc23bcfac159bbf98d4903d04aefab54f89584ce9b06fd9f0247304402204daba18162118a244e9d4ef565faeac79b828eba62498f46e3110263f4da2a5c02205b9df53c1ce2228e5a0bdc90522c92eb8862b9109ec3626b6a23648ede11750c012102356c17877be6c3fec0118c5dac22115effccabacca9ce18fbfa7bc457a599ea69a010000";
        let unvault1_tx_hex = "02000000000101f6d328bf7481f5d31706c42ef026703f4db6baaf3f8e1847a67aafcd78c22a060000000000fdffffff02b8239041000000002200206c1c9b72e836a6dec99014406cf88b4df54da9c57b214b99464b987b447a05723075000000000000220020362dcc982d454a66b2e8febd8740769ce23e2030dda9d7f35c08444f8775ab8f0400483045022100e7b6c5b403accb76705726c31b7c8955ef414ac6e63edea7c16107612aa72f79022017bf607b26e876b87b1ee12311b14911c04f99ca5e396e2995e5ffeaacc840c301483045022100f213ea174468a26e868e2986f50782b0bca388ddd28f7be47367448f63f32dac02204250489c6833d7a35f2cb82c6973327a528d6bb7363beb7d3cfd68f0726cd4b30147522103614f52e6ff874bed71cdadeb0ca7bedace71b40f3e8045982c8222fcf2e444fb2102becc5ebd0649c836922ce8a72b54cf9dbdc9d7de56163dcf706368b3b5ade30952ae00000000";

        let deposit1_tx: BitcoinTransaction =
            encode::deserialize(&Vec::from_hex(deposit1_tx_hex).unwrap()).unwrap();
        let deposit1_outpoint = OutPoint::new(deposit1_tx.txid(), 0);
        let unvault1_tx: BitcoinTransaction =
            encode::deserialize(&Vec::from_hex(unvault1_tx_hex).unwrap()).unwrap();

        let deposit2_tx_hex = "0200000000010147717eb181bfd25afb66336f4503fa8fc84c82245c60e3b50e9f56bdff25d4a00000000000feffffff02008c8647000000002200200071401c8209b9cddce78d4a7f0447ac5ae7ff1aaaf0b23c47d039b515602aede7effa020000000016001434cd89de7d114dc13038e26cc14a01707a683bfc0247304402203ca3fd9eb4d9eb7b3bc42ec735c7c14378e81e1f3f0f69b13627e18290573d7d022009123ae42eeb131d5c8c4f7f47c0aa1c5b3b59fa5999c8cd63dea6ab80609672012102356c17877be6c3fec0118c5dac22115effccabacca9ce18fbfa7bc457a599ea6ae010000";
        let unvault2_tx_hex = "020000000001017ecdf28b7b4e4939ead4d56270da0e5c4759c9fe00373e21f3e9ccff9ec1a8b40000000000fdffffff02b804864700000000220020c8874f9efdb6d53ee465a21e72d2b86a01aadc37f043286e3b539d6365b0a4d330750000000000002200200d70a091ea22dc0db14ff09c2f5a7504f7ea73bde8cdff194f1cea7687dc288004004730440220009f709afc5434815c750b7bbce32e59346a4e16e0528ca2c1fc01f325d8df8602205f415a961cf4fe6ff80aa786e40bb79ba390afa46b029b8eba516dc7754fc31901483045022100d751a34966fb7117e2a5096f1090281449a6e88b8e8f1555f2c9876c2fd022f00220164153055db4f8777660d17c15b8a4d3537ae926153172f9cbebac6ab788731e0147522102f6df74980f0df6e6de298f00798ce53df31594709bc95014bb0f9374d106b57f2102aa12b2ebe1e812fda873df2739d78bff8760814370acb15cad2fded3012490f052ae00000000";

        let deposit2_tx: BitcoinTransaction =
            encode::deserialize(&Vec::from_hex(deposit2_tx_hex).unwrap()).unwrap();
        let deposit2_outpoint = OutPoint::new(deposit2_tx.txid(), 0);
        let unvault2_tx: BitcoinTransaction =
            encode::deserialize(&Vec::from_hex(unvault2_tx_hex).unwrap()).unwrap();

        let spend_tx_hex = "020000000001028b2106819c6f2cbd26af2e556befe7b1079127d3b495a224a89f7df44eee99e200000000000a000000a74d921ac547f00c4db2897f810c3d498e9bde30c86dfea232a91f7b1bea8ad600000000000a0000000360600000000000002200200d70a091ea22dc0db14ff09c2f5a7504f7ea73bde8cdff194f1cea7687dc288000562183000000001600142b739d57d75b45b45dce32c53f5d99a5b47f49217d5ef405000000002200200071401c8209b9cddce78d4a7f0447ac5ae7ff1aaaf0b23c47d039b515602aed0300483045022100c51595a7c75fd63a896fdf21ef841e20b8549268a3830fbe3736539e5748352a02207576e4a7975d4692ed11f45f014aa767c3abc56464e59484384757c29d2ad1b90183512103f9af2d4e21bc6e1e30f7974146fd728f0dcfa280521172aee1afba659a7290662103b9ad21981e42c41f38df5f8f3ddb80a597d0d3df230818203a8f50e6be443a2652ae6476a914b5e60d45ce94c86e4acace579dbab85fccf05b7288ac6b76a914f6fbf60a5629321aa8dfe9f7d7ce41447ccc670388ac6c935287675ab268030047304402205100815ad2c60fea53e5b8bebdc336393c40b372815bfb014ad5ec442df77d5a02202397189481a1597b4b5589fa9e8671b25fc04633456d0ec824ac6e0f48419f620183512102a6db8d9cdb53da7175ae9df456499c24ed569b96918f8bb560f0343833d70f092102fe8334ab977d4f6cd14ba25f1dc5153954329d4a68a050e59362884d1141b70552ae6476a914270cbdbbc948dbd56f28a6265c86b31153bacc5388ac6b76a914959beb32358ccd19fb93e9fd25542d0c8d9a2f7c88ac6c935287675ab26800000000";

        let spend_tx: BitcoinTransaction =
            encode::deserialize(&Vec::from_hex(spend_tx_hex).unwrap()).unwrap();

        insert_vault_in_db(
            &db_file,
            1,
            &deposit1_outpoint,
            &Amount::from_sat(deposit1_tx.output[deposit1_outpoint.vout as usize].value),
            1,
            ChildNumber::from_normal_idx(0).unwrap(),
            Some(2),
            Some(6),
            VaultStatus::Spent,
            Some(&spend_tx.txid()),
        );

        // UnvaultTransaction is required in database.
        db_confirm_deposit(
            &db_file,
            &deposit1_outpoint,
            1, // blockheight
            1, // blocktime
            &UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAfbTKL90gfXTFwbELvAmcD9NtrqvP44YR6Z6r814wioGAAAAAAD9////ArgjkEEAAAAAIgAgbBybcug2pt7JkBRAbPiLTfVNqcV7IUuZRkuYe0R6BXIwdQAAAAAAACIAIDYtzJgtRUpmsuj+vYdAdpziPiAw3anX81wIRE+HdauPAAAAAAABASsAq5BBAAAAACIAICTJOG78TIre8heykxyu0c9IkfSXcFJq1XA9aJO0kQLOAQMEAQAAAAEFR1IhA2FPUub/h0vtcc2t6wynvtrOcbQPPoBFmCyCIvzy5ET7IQK+zF69BknINpIs6KcrVM+dvcnX3lYWPc9wY2izta3jCVKuIgYCvsxevQZJyDaSLOinK1TPnb3J195WFj3PcGNos7Wt4wkI5wT/vgAAAAAiBgNhT1Lm/4dL7XHNresMp77aznG0Dz6ARZgsgiL88uRE+wiKZPKpAAAAAAAiAgKm242c21PacXWunfRWSZwk7VablpGPi7Vg8DQ4M9cPCQh+CFEoAAAAACICAr7MXr0GScg2kizopytUz529ydfeVhY9z3BjaLO1reMJCOcE/74AAAAAIgIC/oM0q5d9T2zRS6JfHcUVOVQynUpooFDlk2KITRFBtwUImCBmZgAAAAAiAgNhT1Lm/4dL7XHNresMp77aznG0Dz6ARZgsgiL88uRE+wiKZPKpAAAAAAAiAgK+zF69BknINpIs6KcrVM+dvcnX3lYWPc9wY2izta3jCQjnBP++AAAAACICAv6DNKuXfU9s0UuiXx3FFTlUMp1KaKBQ5ZNiiE0RQbcFCJggZmYAAAAAAA==").unwrap(),
            &CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAAadNkhrFR/AMTbKJf4EMPUmOm94wyG3+ojKpH3sb6orWAAAAAAD9////ARLlj0EAAAAAIgAgJMk4bvxMit7yF7KTHK7Rz0iR9JdwUmrVcD1ok7SRAs4AAAAAAAEBK7gjkEEAAAAAIgAgbBybcug2pt7JkBRAbPiLTfVNqcV7IUuZRkuYe0R6BXIBAwSBAAAAAQWDUSECptuNnNtT2nF1rp30VkmcJO1Wm5aRj4u1YPA0ODPXDwkhAv6DNKuXfU9s0UuiXx3FFTlUMp1KaKBQ5ZNiiE0RQbcFUq5kdqkUJwy9u8lI29VvKKYmXIazEVO6zFOIrGt2qRSVm+syNYzNGfuT6f0lVC0MjZovfIisbJNSh2dasmgiBgKm242c21PacXWunfRWSZwk7VablpGPi7Vg8DQ4M9cPCQh+CFEoAAAAACIGAr7MXr0GScg2kizopytUz529ydfeVhY9z3BjaLO1reMJCOcE/74AAAAAIgYC/oM0q5d9T2zRS6JfHcUVOVQynUpooFDlk2KITRFBtwUImCBmZgAAAAAiBgNhT1Lm/4dL7XHNresMp77aznG0Dz6ARZgsgiL88uRE+wiKZPKpAAAAAAAiAgK+zF69BknINpIs6KcrVM+dvcnX3lYWPc9wY2izta3jCQjnBP++AAAAACICA2FPUub/h0vtcc2t6wynvtrOcbQPPoBFmCyCIvzy5ET7CIpk8qkAAAAAAA==").unwrap(),
            None,
            None,
        )
        .unwrap();

        let db_vault = db_vault_by_deposit(&db_file, &deposit1_outpoint)
            .unwrap()
            .unwrap();
        db_mark_spent_unvault(&db_file, db_vault.id, 6, 6).unwrap();

        insert_vault_in_db(
            &db_file,
            1,
            &deposit2_outpoint,
            &Amount::from_sat(deposit2_tx.output[deposit2_outpoint.vout as usize].value),
            1,
            ChildNumber::from_normal_idx(1).unwrap(),
            Some(3),
            Some(6),
            VaultStatus::Spent,
            Some(&spend_tx.txid()),
        );

        // UnvaultTransaction is required in database.
        db_confirm_deposit(
            &db_file,
            &deposit2_outpoint,
            1, // blockheight
            1, // blocktime
            &UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAX7N8ot7Tkk56tTVYnDaDlxHWcn+ADc+IfPpzP+ewai0AAAAAAD9////ArgEhkcAAAAAIgAgyIdPnv221T7kZaIectK4agGq3DfwQyhuO1OdY2WwpNMwdQAAAAAAACIAIA1woJHqItwNsU/wnC9adQT36nO96M3/GU8c6naH3CiAAAAAAAABASsAjIZHAAAAACIAIABxQByCCbnN3OeNSn8ER6xa5/8aqvCyPEfQObUVYCrtAQMEAQAAAAEFR1IhAvbfdJgPDfbm3imPAHmM5T3zFZRwm8lQFLsPk3TRBrV/IQKqErLr4egS/ahz3yc514v/h2CBQ3CssVytL97TASSQ8FKuIgYCqhKy6+HoEv2oc98nOdeL/4dggUNwrLFcrS/e0wEkkPAI5wT/vgEAAAAiBgL233SYDw325t4pjwB5jOU98xWUcJvJUBS7D5N00Qa1fwiKZPKpAQAAAAAiAgKqErLr4egS/ahz3yc514v/h2CBQ3CssVytL97TASSQ8AjnBP++AQAAACICAvbfdJgPDfbm3imPAHmM5T3zFZRwm8lQFLsPk3TRBrV/CIpk8qkBAAAAIgIDua0hmB5CxB8431+PPduApZfQ098jCBggOo9Q5r5EOiYImCBmZgEAAAAiAgP5ry1OIbxuHjD3l0FG/XKPDc+igFIRcq7hr7plmnKQZgh+CFEoAQAAAAAiAgKqErLr4egS/ahz3yc514v/h2CBQ3CssVytL97TASSQ8AjnBP++AQAAACICA7mtIZgeQsQfON9fjz3bgKWX0NPfIwgYIDqPUOa+RDomCJggZmYBAAAAAA==").unwrap(),
            &CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAAYshBoGcbyy9Jq8uVWvv57EHkSfTtJWiJKifffRO7pniAAAAAAD9////ARLGhUcAAAAAIgAgAHFAHIIJuc3c541KfwRHrFrn/xqq8LI8R9A5tRVgKu0AAAAAAAEBK7gEhkcAAAAAIgAgyIdPnv221T7kZaIectK4agGq3DfwQyhuO1OdY2WwpNMBAwSBAAAAAQWDUSED+a8tTiG8bh4w95dBRv1yjw3PooBSEXKu4a+6ZZpykGYhA7mtIZgeQsQfON9fjz3bgKWX0NPfIwgYIDqPUOa+RDomUq5kdqkUteYNRc6UyG5Kys5Xnbq4X8zwW3KIrGt2qRT2+/YKVikyGqjf6ffXzkFEfMxnA4isbJNSh2dasmgiBgKqErLr4egS/ahz3yc514v/h2CBQ3CssVytL97TASSQ8AjnBP++AQAAACIGAvbfdJgPDfbm3imPAHmM5T3zFZRwm8lQFLsPk3TRBrV/CIpk8qkBAAAAIgYDua0hmB5CxB8431+PPduApZfQ098jCBggOo9Q5r5EOiYImCBmZgEAAAAiBgP5ry1OIbxuHjD3l0FG/XKPDc+igFIRcq7hr7plmnKQZgh+CFEoAQAAAAAiAgKqErLr4egS/ahz3yc514v/h2CBQ3CssVytL97TASSQ8AjnBP++AQAAACICAvbfdJgPDfbm3imPAHmM5T3zFZRwm8lQFLsPk3TRBrV/CIpk8qkBAAAAAA==").unwrap(),
            None,
            None,
        )
        .unwrap();

        let db_vault = db_vault_by_deposit(&db_file, &deposit2_outpoint)
            .unwrap()
            .unwrap();
        db_mark_spent_unvault(&db_file, db_vault.id, 6, 6).unwrap();

        let mut txs = HashMap::new();
        txs.insert(
            deposit1_tx.txid(),
            WalletTransaction {
                hex: deposit1_tx_hex.to_string(),
                received_time: 2,
                blocktime: Some(2),
                blockheight: Some(2),
            },
        );
        txs.insert(
            deposit2_tx.txid(),
            WalletTransaction {
                hex: deposit2_tx_hex.to_string(),
                received_time: 3,
                blocktime: Some(3),
                blockheight: Some(3),
            },
        );
        txs.insert(
            unvault1_tx.txid(),
            WalletTransaction {
                hex: unvault1_tx_hex.to_string(),
                received_time: 4,
                blocktime: Some(4),
                blockheight: Some(4),
            },
        );
        txs.insert(
            unvault2_tx.txid(),
            WalletTransaction {
                hex: unvault2_tx_hex.to_string(),
                received_time: 4,
                blocktime: Some(4),
                blockheight: Some(4),
            },
        );
        txs.insert(
            spend_tx.txid(),
            WalletTransaction {
                hex: spend_tx_hex.to_string(),
                received_time: 4,
                blocktime: Some(6),
                blockheight: Some(6),
            },
        );
        let bitcoind_conn = MockBitcoindThread::new(txs);

        let list = list_onchain_txs(
            &revaultd,
            &bitcoind_conn,
            &[deposit1_outpoint, deposit2_outpoint],
        )
        .unwrap();
        assert_eq!(list.len(), 2);

        let txs = &list[0];
        assert_eq!(txs.vault_outpoint, deposit1_outpoint);
        assert_eq!(txs.deposit.hex, deposit1_tx_hex);
        let unvault = txs.unvault.as_ref().unwrap();
        assert_eq!(unvault.hex, unvault1_tx_hex);
        assert_eq!(unvault.cpfp_index, Some(1));
        assert_eq!(unvault.change_index, None);
        let spend = txs.spend.as_ref().unwrap();
        assert_eq!(spend.hex, spend_tx_hex);
        assert_eq!(spend.cpfp_index, Some(0));
        assert_eq!(spend.change_index, Some(2));

        let txs = &list[1];
        assert_eq!(txs.vault_outpoint, deposit2_outpoint);
        assert_eq!(txs.deposit.hex, deposit2_tx_hex);
        let unvault = txs.unvault.as_ref().unwrap();
        assert_eq!(unvault.hex, unvault2_tx_hex);
        assert_eq!(unvault.cpfp_index, Some(1));
        assert_eq!(unvault.change_index, None);
        let spend = txs.spend.as_ref().unwrap();
        assert_eq!(spend.hex, spend_tx_hex);
        assert_eq!(spend.cpfp_index, Some(0));
        assert_eq!(spend.change_index, Some(2));

        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }

    #[test]
    fn test_gethistory() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::StakeholderManager);
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

        let events = gethistory(
            &revaultd,
            &bitcoind_conn,
            0,
            4,
            20,
            &[
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
        assert!(events[0].cpfp_amount.is_some());
        assert_eq!(
            events[0].miner_fee.unwrap(),
            200_000_000_000
                - spend_tx.output[0].value
                - spend_tx.output[1].value
                - events[0].cpfp_amount.unwrap(),
        );
        assert_eq!(events[0].vaults, vec![deposit2_outpoint]);

        assert_eq!(events[1].txid, deposit2_outpoint.txid);
        assert_eq!(events[1].kind, HistoryEventKind::Deposit);
        assert_eq!(events[1].date, 3);
        assert_eq!(events[1].miner_fee, None);
        assert_eq!(events[1].amount, Some(200_000_000_000));
        assert_eq!(events[1].cpfp_amount, None);
        assert_eq!(events[1].vaults, vec![deposit2_outpoint]);

        assert_eq!(events[2].txid, cancel_tx.txid());
        assert_eq!(events[2].kind, HistoryEventKind::Cancel);
        assert!(events[2].amount.is_none());
        assert!(events[0].cpfp_amount.is_some());
        assert_eq!(events[2].date, 2);
        assert_eq!(
            events[2].miner_fee.unwrap(),
            Amount::ONE_BTC.as_sat() - cancel_tx.output[0].value - events[0].cpfp_amount.unwrap()
        );
        assert_eq!(events[3].txid, deposit1_outpoint.txid);
        assert_eq!(events[3].kind, HistoryEventKind::Deposit);
        assert_eq!(events[3].vaults, vec![deposit1_outpoint]);

        // retrieve events later in history
        let events = gethistory(
            &revaultd,
            &bitcoind_conn,
            0,
            2,
            20,
            &[
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
        assert!(events[0].cpfp_amount.is_some());
        assert_eq!(
            events[0].miner_fee.unwrap(),
            Amount::ONE_BTC.as_sat() - cancel_tx.output[0].value - events[0].cpfp_amount.unwrap()
        );
        assert_eq!(events[0].vaults, vec![deposit1_outpoint]);

        assert_eq!(events[1].date, 1);
        assert_eq!(events[1].txid, deposit1_outpoint.txid);
        assert_eq!(events[1].kind, HistoryEventKind::Deposit);
        assert_eq!(events[1].miner_fee, None);
        assert_eq!(events[1].amount, Some(Amount::ONE_BTC.as_sat()));
        assert_eq!(events[1].cpfp_amount, None);
        assert_eq!(events[1].vaults, vec![deposit1_outpoint]);

        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }
}
