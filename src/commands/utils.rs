//! This module contains routines for controlling our actions (checking signatures, communicating
//! with servers, with bitcoind, ..). Requests may originate from the RPC server or the signature
//! fetcher thread.

use crate::{
    commands::{
        CommandError, HistoryEvent, HistoryEventKind, ListPresignedTxEntry, ListVaultsEntry,
    },
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
        consensus::encode, hashes::hex::FromHex, Amount, OutPoint,
        Transaction as BitcoinTransaction, Txid,
    },
    miniscript::DescriptorTrait,
    transactions::{CpfpableTransaction, RevaultTransaction, UnvaultTransaction},
    txins::{DepositTxIn, RevaultTxIn},
    txouts::{DepositTxOut, RevaultTxOut},
};

use std::{
    collections::{HashMap, HashSet},
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

/// Get the Unvault transaction for a given vault
pub fn unvault_tx(
    revaultd: &RevaultD,
    vault: &DbVault,
) -> Result<UnvaultTransaction, revault_tx::error::TransactionCreationError> {
    // Derive the descriptors needed to create the UnvaultTransaction
    let deposit_descriptor = revaultd
        .deposit_descriptor
        .derive(vault.derivation_index, &revaultd.secp_ctx);
    let deposit_txin = DepositTxIn::new(
        vault.deposit_outpoint,
        DepositTxOut::new(vault.amount, &deposit_descriptor),
    );
    let unvault_descriptor = revaultd
        .unvault_descriptor
        .derive(vault.derivation_index, &revaultd.secp_ctx);
    let cpfp_descriptor = revaultd
        .cpfp_descriptor
        .derive(vault.derivation_index, &revaultd.secp_ctx);

    UnvaultTransaction::new(deposit_txin, &unvault_descriptor, &cpfp_descriptor)
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

            let unvault = unvault_tx(revaultd, vault)
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
                cpfp_amount += unvault_tx(revaultd, vault)
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
                db_update_presigned_txs,
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
        transactions::{
            CancelTransaction, EmergencyTransaction, RevaultPresignedTransaction,
            RevaultTransaction, UnvaultEmergencyTransaction, UnvaultTransaction,
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
                    tx.add_sig(key.key, sig, secp).unwrap();
                }
                RevaultTx::Cancel(ref mut tx) => {
                    tx.add_sig(key.key, sig, secp).unwrap();
                }
                RevaultTx::Emergency(ref mut tx) => {
                    tx.add_sig(key.key, sig, secp).unwrap();
                }
                RevaultTx::UnvaultEmergency(ref mut tx) => {
                    tx.add_sig(key.key, sig, secp).unwrap();
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
                initial_cancel: CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAARU919uuOZ2HHyRUrQsCrT2s98u7j8/xW6DXMzO7+eYFAAAAAAD9////AaRl6QsAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK9Cn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QBAwQBAAAAAQWoIQIGcwwFZVqf0EVFaTWYlQmxQ4oTCIkj+5KOstDoG1vgOaxRh2R2qRRvoS9lQLcmcOnmhvvrvSYgPxBG3oisa3apFEWuYAoAKnNlB7Zvc0vqNpOAwYMciKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap(),
                final_cancel: None,
                initial_unvault: UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAajRZE5yVgzG9McmOyy/WdcYdrGrK15bB5N/Hg8zhKOkAQAAAAD9////ArhhpDUAAAAAIgAgFZlOQkpDkFSsLUfyeMGVAOT3T88jZM7L/XlVZoJ2jnAwdQAAAAAAACIAILKCCA/RbV3QMPMrwwQmk4Ark4w1WyElM27WtBgftq6ZAAAAAAABASsA6aQ1AAAAACIAIPQJ3LCGXPIO5iXX0/Yp3wHlpao7cQbPd4q3gxp0J/w2AQMEAQAAAAEFR1IhA47+JRqdt+oloFosla9hWUYVf5YQKDbuq4KO13JS45KgIQMKcLWzABxb/9YBQe+bJRW3v3om8S2LNMGUKSp5K+PQ+1KuIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQGpIQMVlEoh50lasMhcdwnrmnCp2ROlGY5CrH+HtxQmfZDZ06xRh2R2qRS/INUX1CaP7Pbn5GmtGYu2wgqjnIisa3apFO/kceq8yo9w69g4VVtlFAf739qTiKxsk1KHZ1IhAnddfXi3N38A+aEQ74sUdeuV7sg+2L3ijTjMHMEAfq3cIQLWP96FqjfC5qKQkC2WhYbbLJx1FbNSAjsnMfwDnK0jD1KvARKyaCICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBJSEDjv4lGp236iWgWiyVr2FZRhV/lhAoNu6rgo7XclLjkqCsUYciAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap(),
                final_unvault: None,
                initial_emer: EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAVPUadsP07dfqN8wQ6WbZV3hAo7Q3tw4S1n9oPZO7n2AAAAAAAD9////AXjeBQAAAAAAIgAgEaEDTnaMMqX5CbGLBd3KXK7etE4u+k7juf00mFty39AAAAAAAAEBK2goCAAAAAAAIgAgEaEDTnaMMqX5CbGLBd3KXK7etE4u+k7juf00mFty39ABAwQBAAAAAQVHUiEDXRZKI7Fh3Ae/tPZHiseWfnY93NWAn4PY/U+Ay0WEhHMhAx6G08T++OMOViP1DX9JReTltFKhtDGVYbgHAmKVmZGtUq4iBgMehtPE/vjjDlYj9Q1/SUXk5bRSobQxlWG4BwJilZmRrQi7yFjpCgAAACIGA10WSiOxYdwHv7T2R4rHln52PdzVgJ+D2P1PgMtFhIRzCAyCer0KAAAAAAA=").unwrap(),
                final_emer: None,
                initial_unvault_emer: UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAfLPLsGf/+70fSHiPbQiM5aJrOtndudpadrOgdZ5PnS2AAAAAAD9////AT6uBAAAAAAAIgAguM3vgiOH/6u9I8nTLwPbaEsTYdqHJ7ENIXAldH5ok8MAAAAAAAEBKyChBwAAAAAAIgAgQZJGXUK//DRcNebkSEuwN0C1B30f0AUWA1nmByk6kTABAwQBAAAAAQWrIQN8NAd5Z6KCw/KsgfkzLeUF0HBPAUZs36GQNT9jRrPk8axRh2R2qRSfmJdvXYm6nWeCYapmPyeyj3jJC4isa3apFExRN5b7rVj6Id8bNwFZu6+KJ3Z2iKxsk1KHZ1IhA/Ko9qfPZwynympCEEtUQYic3ColFTH7HAnMNkFnvyQ2IQJYf+U61FvAsSe6HN9l2RKOBTBXRl9WRXhZxg3wEtn0RlKvA7S4ALJoIgYCWH/lOtRbwLEnuhzfZdkSjgUwV0ZfVkV4WcYN8BLZ9EYIbR1QcAoAAAAiBgKJFUjwHL/poloMl/uLgn+VJwIj6IF8TfYvNLz1kOi6NQgYBpOOCgAAACIGAtJYCY56bqmbAPPjX6l3kLwhBdyfgmzVkuwNOo4YrFJ9CG1inkgKAAAAIgYDfDQHeWeigsPyrIH5My3lBdBwTwFGbN+hkDU/Y0az5PEIa+nEzQoAAAAiBgPyqPanz2cMp8pqQhBLVEGInNwqJRUx+xwJzDZBZ78kNggECDSWCgAAAAAA").unwrap(),
                final_unvault_emer: None,
            }),
            Some(TestTransactions {
                initial_cancel:CancelTransaction::from_psbt_str("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").unwrap(),
                final_cancel: Some(CancelTransaction::from_psbt_str("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").unwrap()),
                initial_unvault: UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAYaXLfGg2dQ9K7Z5WCwqwckivsB0tbs/wct42zEuG0zsAAAAAAD9////AkRL46YAAAAAIgAgqEBZyjLwTBUGdacvGi8D6UVOqVAsfyyhlPVTKf/86DswdQAAAAAAACIAIOniShp5bwss5CGCLRzAcEA5KKKpDQ4vUb5VVspfq2ExAAAAAAABASuM0uOmAAAAACIAIHXyaRd0yBZ3gxhGsCgiAOKIssWXELWPdDGD1JJVB9vFAQMEAQAAAAEFR1IhAlgt7b9E9GVk5djNsGdTbWDr40zR0YAc/1G7+desKJtDIQNHBN7LVbWqiP/R710GNmJIwTFOGWVRE2/xTquLukpJDlKuIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQGoIQICkzqxA36tCqSnhYxtSdZwXh+zvF9msAkYr3ufAOzVJqxRh2R2qRRyqV8ir5obrrhS+alScvjCHZjyZIisa3apFLbJrbicjJNybIPiobXZR4nXe5VhiKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQElIQK1323qfhEH7yMqxloxMQOfxx7VhZrl5zso8JRdkhBfH6xRhyICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAA==").unwrap(),
                final_unvault: None,
                initial_emer: EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAARWFbAfyeJqGlN6Lvdp4zQBnBbPTgrhRpabNQv/oOoByAAAAAAD9////ASgi8QUAAAAAIgAgn2Gta1wp810CnYfJRof2Oaos02SQnoaHlRJ+fqWZfv0AAAAAAAEBKwDh9QUAAAAAIgAgn2Gta1wp810CnYfJRof2Oaos02SQnoaHlRJ+fqWZfv0BAwQBAAAAAQX9EwFYIQLh9dHpizr36R75ELwuMD8ogU01GLg2rJlXJP9cmRuMjCEDr0wYdgwqSapt4EOOkg+Ck2JFN1chOd72JFvYtZUMehshA2HE+2ODv/zT8xm5nj2pmA/yGY6lVJjBOnj+ut8wR16LIQJS0dpq5KjZClBZItks8cCp2LX0MLTd1eSaK497+BlkCCEC+1F+rhtosZIeJA2liXtlaS6UFDAFzW7pM9FwzZ2jcuchAyBWLaod5JOgbAM2SiRArXbT9yvp0Mbjbfucl2Gp5+xjIQOFlKzbStqoohpch92y+I4FS64rNFfmaU1h7nDKAPgu6yEDxHhc4Lrf0Bd8yLG3pswnvVGJ+KkJZ/lXzm9H3uv5bWJYriIGAlLR2mrkqNkKUFki2SzxwKnYtfQwtN3V5Jorj3v4GWQICFnM8p8KAAAAIgYC4fXR6Ys69+ke+RC8LjA/KIFNNRi4NqyZVyT/XJkbjIwIAUzMNgoAAAAiBgL7UX6uG2ixkh4kDaWJe2VpLpQUMAXNbukz0XDNnaNy5whf4LC5CgAAACIGAyBWLaod5JOgbAM2SiRArXbT9yvp0Mbjbfucl2Gp5+xjCHuwiDIKAAAAIgYDYcT7Y4O//NPzGbmePamYD/IZjqVUmME6eP663zBHXosIzc8xWAoAAAAiBgOFlKzbStqoohpch92y+I4FS64rNFfmaU1h7nDKAPgu6wgEQka/CgAAACIGA69MGHYMKkmqbeBDjpIPgpNiRTdXITne9iRb2LWVDHobCGfrbDYKAAAAIgYDxHhc4Lrf0Bd8yLG3pswnvVGJ+KkJZ/lXzm9H3uv5bWIIEpRKtQoAAAAAAA==").unwrap(),
                final_emer: Some(
                    EmergencyTransaction::from_psbt_str("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").unwrap(),
                ),
                initial_unvault_emer: UnvaultEmergencyTransaction::from_psbt_str("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").unwrap(),
                final_unvault_emer: Some(
                    UnvaultEmergencyTransaction::from_psbt_str("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").unwrap(),
                ),
            }),
            Some(TestTransactions {
                initial_cancel: CancelTransaction::from_psbt_str("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").unwrap(),
                final_cancel: Some(CancelTransaction::from_psbt_str("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").unwrap()),
                initial_unvault: UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAUaovJQUhwegF7P9qJBrWxtPq7dcJVPZ8MTjp9v8LUoDAAAAAAD9////AtCn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QwdQAAAAAAACIAIOD4aW9ds/RNXcNihA2bsw1c+bmg65auhz/3DoPPEg7oAAAAAAABASsYL+oLAAAAACIAIKdjkv/h5NjyHOPSensxUoTK3V1lFzGvS6zsG04Xdfs8AQMEAQAAAAEFR1IhAvuWyyfoIfsyrTwNoR8N80zSBdfJrGff+D9XKBRL7aEFIQJDFo5gffr4sTpOPvcI45wr3VtVCTh/yw/SiCJaCIjiV1KuIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQGoIQIGcwwFZVqf0EVFaTWYlQmxQ4oTCIkj+5KOstDoG1vgOaxRh2R2qRRvoS9lQLcmcOnmhvvrvSYgPxBG3oisa3apFEWuYAoAKnNlB7Zvc0vqNpOAwYMciKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQElIQJYONwJSgKF2+Ox+K8SgruNIwYM+5dbLzkhSvjfoCCjnaxRhyICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAA==").unwrap(),
                final_unvault: Some(UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAUaovJQUhwegF7P9qJBrWxtPq7dcJVPZ8MTjp9v8LUoDAAAAAAD9////AtCn6QsAAAAAIgAg8R4ZLx3Zf/A7VOcZ7PtAzhSLo5olkqqYP+voLCRFn2QwdQAAAAAAACIAIOD4aW9ds/RNXcNihA2bsw1c+bmg65auhz/3DoPPEg7oAAAAAAABASsYL+oLAAAAACIAIKdjkv/h5NjyHOPSensxUoTK3V1lFzGvS6zsG04Xdfs8IgICApM6sQN+rQqkp4WMbUnWcF4fs7xfZrAJGK97nwDs1SZIMEUCIQC18W4KdSJgg0w8PaNvCISyIxKXYbMRB6NBDmhz3Ok+hQIgV77oVG62xS9baMrBbp9pdAUjooB2Mqnx5hixZ48kQpoBIgICA8dJ8CWgfhsrU+VE3or4jMBtvGR/9hLUqLVpL5fBB7tIMEUCIQDmjTp2N3Pb7UKLyVy/85lgBa4Et6xMxi1ZeWy14gdVUQIgZu5u5/wDWv0evlPL1NdzINwO6h5yBiaNskl3VOrMGtoBIgICBnMMBWVan9BFRWk1mJUJsUOKEwiJI/uSjrLQ6Btb4DlIMEUCIQDJeX1L12SnJ+SBprTtTo57u3hcuzRTQ/y0AEwcfVSLegIgWrBVPnhhzYh2tw8gk0eGZJ4MaBInKrSiVXUoUuyvspYBIgICEUcipBjtxtFxFXI6CYvMq/KXtJxTVJETq5tRILViovxHMEQCIG5YQZzENXnaYNa57yz95VVFyDdJOU7zrEKAeuXzCtDCAiAH+tzK1BuBv2y1PF/HBOPl70JoCYREuAlmD8/oovZqGgEiAgJDFo5gffr4sTpOPvcI45wr3VtVCTh/yw/SiCJaCIjiV0cwRAIgE73DtQt36NOcekaFMGwuR4tBwuZpfzpT/iBUhVSKC3ECIE3+5Ixb/m1vfGeelQ2YPG24JFF511o9CTPpAySkQLd1ASICAsq7RLTptOoznxrLVOYVZez7c7CNiE0rx7Ts4ZZIIKc0RzBEAiBEWBtW23SxE9S/kpxQwIAAZzjNP+44oRmGJ/uFDW4WqAIgK5o4IsOQ1eYHGhayIzT3drzd2qBzZF/ODhh5b6+XkVEBIgIC6CJXMrp3sp02Gl+hpD2YHeku/rN95ivhprKBTRY+H9JIMEUCIQDtqwsuWxHTP3K+0GadKas1DuRm69MBZc/UpSyWUb/QvQIgczyuvIadVpF8qaGQ0gDYeCtcEGgGjL3mqp3A4fliYeoBIgIC9t7BqqGmkqEmYkK1StchrYTgch6CE1hR7eN1mk4/JaxHMEQCIBkfbFjrWBu2hM4uriAu0QNUeExTsTD8JqBZxo4zkHGzAiBwYMXCzPKBBcY0Wt9h1Au9bBvEdyR0qVt+AQy9ftQ3wQEiAgL5vFDdmMV/P4SpzIWhDMbHKHMGlMwntZxaWtwUXd9KvEcwRAIgc2Yp+nrcf8jozOH0zkoM5DRHA6VfFgeV7LxsUAXAaSACIFKiy1+WoD7cfJviCH6K+eAxdVWHXKr+/59G0GpUAi8UASICAvuWyyfoIfsyrTwNoR8N80zSBdfJrGff+D9XKBRL7aEFSDBFAiEAk5LsVb9ztXJa2boq6j/U+GS8rQ2IZMJMtY1Win7Xf7cCIHn+GWPTxQYlwVlRZjx+1nC8Y+C83hYjNzxeEyNvR1MEASICAzXQHO6KjAbz7OgmKxKccFYxsHZnt5oH/gWg1awnK9T0RzBEAiB2xY5QteSVL/U1Bm8Vv2s5kNBc3dMT2a48+NUzulNX0QIgTz/zcxaerGY+p/Iw8T9WzwLr8icSY2+sWx65a1P2Bm8BIgIDTm37cDT97U0sxMAhgCDeN0TLih+a3NKHx6ahcyh66xdIMEUCIQDyC6YFW72jfFHTeYvRAKB7sl/1ETvSvJQ6oXtvFM2LxwIgWd3pGOipAsisM9/2qGrnoWvvLm8dKqUHrachRGaskyIBIgIDTo4HmlEehH38tYZMerpLLhSBzzkjW1DITKYZ6Pr9+I1HMEQCICTUqQmMyIg6pRpb/rrVyRLxOOnCguqpytPH1cKg0RdiAiAQsgjOTio98PWUNcVqTODBMM2HJvURyN+GhJbUZDL3TwEiAgPAKvZof/JMq6C/mAv3iRqN76eVO6RzNYLzz9XqXigOjkcwRAIgSzN1LbuYv8y6tkZRvTZZeVYC32fXstGvgd7O1gRQEDcCIDTOeB3gocuzJpmBv1P/3Ktt9JCV5NY0DJlJK9012gDzAQEDBAEAAAABBUdSIQL7lssn6CH7Mq08DaEfDfNM0gXXyaxn3/g/VygUS+2hBSECQxaOYH36+LE6Tj73COOcK91bVQk4f8sP0ogiWgiI4ldSriIGAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBqCECBnMMBWVan9BFRWk1mJUJsUOKEwiJI/uSjrLQ6Btb4DmsUYdkdqkUb6EvZUC3JnDp5ob7670mID8QRt6IrGt2qRRFrmAKACpzZQe2b3NL6jaTgMGDHIisbJNSh2dSIQMPZLkiruL9WX8QS8bLO2cPHKLGxJsQcaGmwBBXXZT+WiECq+R1sZnsPWL6V2+u4WozT9uG/7JtznW+zrqu3zKKw/5Sr1OyaCICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBJSECWDjcCUoChdvjsfivEoK7jSMGDPuXWy85IUr436Ago52sUYciAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap()),
                initial_emer: EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAd9r3O9xA5N+TcsPgEYJJ2p5ALzt/a6ncSIenQSd7nKeAAAAAAD9////ASgi8QUAAAAAIgAgWudY8DE0KrSi8SYBBJCaYP8sZLnmB+DrXM2/yktWGv0AAAAAAAEBKwDh9QUAAAAAIgAgWudY8DE0KrSi8SYBBJCaYP8sZLnmB+DrXM2/yktWGv0BAwQBAAAAAQX9EwFYIQKu9Nrb2ugb2I3zVkyeS3shfTKak36418MZdsqTRNCy5CEDfhJZsmD7HbMm6byhrqiW+C1C98VOMRIXQFKljOdBcYwhA/eiZTyRcPPdbWFNySMvTTmwOlNgUzJFaPdeQEH9E1p7IQJbsdB1tEJ7tHWfbTfz323GYJ2zUxO3tUilmjoL2WRQ5yEDmVsqUgCFA/pMl4tCRoLOqttSYPilBAhfH+LBId/QadAhAvTSHunZ3O2jxw2OX5Tqu5VcNeNdtOiOFjv3ZnSJ0R0/IQKZyJxFZmJdod8D5hfvfdS5ew8FrT4HHVzSlpzYEGPu7yECgCktfaZh/4r49DGKXemb3miPTWbcTNkUxFhy/zQJhb9YriIGAlux0HW0Qnu0dZ9tN/PfbcZgnbNTE7e1SKWaOgvZZFDnCI4QM/wKAAAAIgYCgCktfaZh/4r49DGKXemb3miPTWbcTNkUxFhy/zQJhb8Imggi4woAAAAiBgKZyJxFZmJdod8D5hfvfdS5ew8FrT4HHVzSlpzYEGPu7wjCM9WxCgAAACIGAq702tva6BvYjfNWTJ5LeyF9MpqTfrjXwxl2ypNE0LLkCBwXzQEKAAAAIgYC9NIe6dnc7aPHDY5flOq7lVw141206I4WO/dmdInRHT8IDUzGGQoAAAAiBgN+ElmyYPsdsybpvKGuqJb4LUL3xU4xEhdAUqWM50FxjAib3zj+CgAAACIGA5lbKlIAhQP6TJeLQkaCzqrbUmD4pQQIXx/iwSHf0GnQCEWQ6rsKAAAAIgYD96JlPJFw891tYU3JIy9NObA6U2BTMkVo915AQf0TWnsI7i9RaAoAAAAAAA==").unwrap(),
                final_emer: Some(EmergencyTransaction::from_psbt_str("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").unwrap()),
                initial_unvault_emer: UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAeN/n8FI2cvQICES+DXsMLdTQsHEa2jZxRf1PgNaqe5KAAAAAAD9////ARo37gUAAAAAIgAgWudY8DE0KrSi8SYBBJCaYP8sZLnmB+DrXM2/yktWGv0AAAAAAAEBK6BK9QUAAAAAIgAg6b4UHF7fBtLC70P87oL1GKJDmPg2/4m6lFw3OQw2XUsBAwQBAAAAAQX9YwJTIQPIPVM2aiWOz5HIAwdkzkHBOPJVFXsXVARxTAvPopq+kSEDn9PsEB1rdonAzIg5Ni+csYYKXTj5sFAICRPz1WWuGqohAxh05aiVcU1LLBjz/6svo+9XR2p6egL5VKER6+3knBipU65kdqkU2O5y7o9pDeR1qejOEuQr9EEk1laIrGt2qRROCYvlx/GPcO3arO8g9JJeBzfnaYisbJNrdqkUNZ9BmmalM1Mtf0Hi/m6uHaKCyxWIrGyTa3apFIC5b4RDiMxdcuLxUc55FHN37dkNiKxsk2t2qRTJwx4nHCKIq6SIUvj13E8YCVpQC4isbJNrdqkUg03hs/lZJ4WdSMB8qrciyeSaX0yIrGyTa3apFBk9W8pIT7zaxeA2NICom1L1DD+siKxsk2t2qRQvwoSFAWDrnPY93G5GWfD2z0zHkoisbJNYh2dYIQIh2EIwWhi20JqUfWA0QYISgGmjWgSLVQm1MWXwOPNa2CEDHLv3x7lGL2TiC5sUG/XtyOUW7RyhzPr+fz9NaWAK3qQhA+kBDTU9oMpao0gvJLjkXoQv+6LAyPpP/ClzeWnr4WeOIQPCC7Bbg8IHiuWZ0rhqPUA14oKGDDd1kEF7eaRrcWJ1eCECzesaUv/7u85DeNxhSon3gx8ubeu+rjhM+wDNC2gkVb8hAzX38gGXIN22RZkdjJRtjiT6JsFRDXChCuZwHDzo5kNXIQOlp1qkyuTq8X9m/QN5f7q78RDrjmu3pHYqDbALY/+lACEDou+7W4xDrntj4ku5tyq58HQ2PmHdhfrVoEz8RKx0H7JYrwOylwCyaCIGAiHYQjBaGLbQmpR9YDRBghKAaaNaBItVCbUxZfA481rYCKk2QngKAAAAIgYCW7HQdbRCe7R1n203899txmCds1MTt7VIpZo6C9lkUOcIjhAz/AoAAAAiBgKAKS19pmH/ivj0MYpd6ZveaI9NZtxM2RTEWHL/NAmFvwiaCCLjCgAAACIGApnInEVmYl2h3wPmF+991Ll7DwWtPgcdXNKWnNgQY+7vCMIz1bEKAAAAIgYCrvTa29roG9iN81ZMnkt7IX0ympN+uNfDGXbKk0TQsuQIHBfNAQoAAAAiBgLN6xpS//u7zkN43GFKifeDHy5t676uOEz7AM0LaCRVvwjYszFGCgAAACIGAvTSHunZ3O2jxw2OX5Tqu5VcNeNdtOiOFjv3ZnSJ0R0/CA1MxhkKAAAAIgYDGHTlqJVxTUssGPP/qy+j71dHanp6AvlUoRHr7eScGKkI3enjSwoAAAAiBgMcu/fHuUYvZOILmxQb9e3I5RbtHKHM+v5/P01pYArepAjYPmjfCgAAACIGAzX38gGXIN22RZkdjJRtjiT6JsFRDXChCuZwHDzo5kNXCEwY7vEKAAAAIgYDfhJZsmD7HbMm6byhrqiW+C1C98VOMRIXQFKljOdBcYwIm984/goAAAAiBgOZWypSAIUD+kyXi0JGgs6q21Jg+KUECF8f4sEh39Bp0AhFkOq7CgAAACIGA5/T7BAda3aJwMyIOTYvnLGGCl04+bBQCAkT89VlrhqqCCfbaCsKAAAAIgYDou+7W4xDrntj4ku5tyq58HQ2PmHdhfrVoEz8RKx0H7IInbRItAoAAAAiBgOlp1qkyuTq8X9m/QN5f7q78RDrjmu3pHYqDbALY/+lAAhK+xOXCgAAACIGA8ILsFuDwgeK5ZnSuGo9QDXigoYMN3WQQXt5pGtxYnV4CFwg7vEKAAAAIgYDyD1TNmoljs+RyAMHZM5BwTjyVRV7F1QEcUwLz6KavpEIVPQU2goAAAAiBgPpAQ01PaDKWqNILyS45F6EL/uiwMj6T/wpc3lp6+FnjgjdBchJCgAAACIGA/eiZTyRcPPdbWFNySMvTTmwOlNgUzJFaPdeQEH9E1p7CO4vUWgKAAAAAAA=").unwrap(),
                final_unvault_emer: Some(UnvaultEmergencyTransaction::from_psbt_str("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").unwrap()),
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
            &[transactions[1].as_ref().unwrap().initial_cancel.clone()],
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
            &[transactions[2].as_ref().unwrap().initial_cancel.clone()],
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
                .signatures(),
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
                .signatures(),
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
                .signatures(),
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
            &[transactions[3].as_ref().unwrap().initial_cancel.clone()],
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
                .signatures(),
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
                .signatures(),
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
                .signatures(),
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
                .signatures(),
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
