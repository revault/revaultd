use crate::{
    database::{
        interface::*,
        schema::{DbTransaction, RevaultTx, TransactionType, SCHEMA},
        DatabaseError, DB_VERSION,
    },
    revaultd::{BlockchainTip, RevaultD, VaultStatus},
};
use revault_tx::{
    bitcoin::{
        secp256k1, util::bip32::ChildNumber, Amount, OutPoint, PublicKey as BitcoinPubKey, Txid,
    },
    miniscript::descriptor::DescriptorTrait,
    transactions::{
        CancelTransaction, EmergencyTransaction, RevaultTransaction, SpendTransaction,
        UnvaultEmergencyTransaction, UnvaultTransaction,
    },
};

use std::{
    collections::BTreeMap,
    convert::TryInto,
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::params;

// Sqlite supports up to i64, thus rusqlite prevents us from inserting u64's.
// We use this to panic rather than inserting a truncated integer into the database (as we'd have
// done by using `n as u32`).
fn timestamp_to_u32(n: u64) -> u32 {
    n.try_into()
        .expect("Is this the year 2106 yet? Misconfigured system clock.")
}

// For some reasons rust-bitcoin store amounts as u64 instead of i64 (as does bitcoind), but SQLite
// does only support integers up to i64.
fn amount_to_i64(amount: &Amount) -> i64 {
    if amount.as_sat() > i64::MAX as u64 {
        log::error!("Invalid amount, larger than i64::MAX : {:?}", amount);
        std::process::exit(1);
    }
    amount.as_sat() as i64
}

// Create the db file with RW permissions only for the user
fn create_db_file(db_path: &Path) -> Result<(), std::io::Error> {
    let mut options = fs::OpenOptions::new();
    let options = options.read(true).write(true).create_new(true);

    #[cfg(unix)]
    return {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600).open(db_path)?;
        Ok(())
    };

    #[cfg(not(unix))]
    return {
        // FIXME: make Windows secure (again?)
        options.open(db_path)?;
        Ok(())
    };
}

// No database yet ? In a single tx, create a new one from the schema and populate with current
// information
fn create_db(revaultd: &RevaultD) -> Result<(), DatabaseError> {
    let db_path = revaultd.db_file();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| timestamp_to_u32(dur.as_secs()))
        .map_err(|e| DatabaseError(format!("Computing time since epoch: {}", e.to_string())))?;
    let deposit_descriptor = revaultd.deposit_descriptor.to_string();
    let unvault_descriptor = revaultd.unvault_descriptor.to_string();
    let cpfp_descriptor = revaultd.cpfp_descriptor.to_string();
    let our_man_xpub_str = revaultd.our_man_xpub.as_ref().map(|xpub| xpub.to_string());
    let our_stk_xpub_str = revaultd.our_stk_xpub.as_ref().map(|xpub| xpub.to_string());
    let raw_unused_index: u32 = revaultd.current_unused_index.into();

    // Rusqlite could create it for us, but we want custom permissions
    create_db_file(&db_path)
        .map_err(|e| DatabaseError(format!("Creating db file: {}", e.to_string())))?;

    db_exec(&db_path, |tx| {
        tx.execute_batch(&SCHEMA)
            .map_err(|e| DatabaseError(format!("Creating database: {}", e.to_string())))?;
        tx.execute(
            "INSERT INTO version (version) VALUES (?1)",
            params![DB_VERSION],
        )
        .map_err(|e| DatabaseError(format!("Inserting version: {}", e.to_string())))?;
        tx.execute(
            "INSERT INTO tip (network, blockheight, blockhash) VALUES (?1, ?2, ?3)",
            params![
                revaultd.bitcoind_config.network.to_string(),
                0,
                vec![0u8; 32]
            ],
        )
        .map_err(|e| DatabaseError(format!("Inserting version: {}", e.to_string())))?;
        tx.execute(
            "INSERT INTO wallets (timestamp, deposit_descriptor, unvault_descriptor,\
            cpfp_descriptor, our_manager_xpub, our_stakeholder_xpub, deposit_derivation_index) \
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                timestamp,
                deposit_descriptor,
                unvault_descriptor,
                cpfp_descriptor,
                our_man_xpub_str,
                our_stk_xpub_str,
                raw_unused_index,
            ],
        )
        .map_err(|e| DatabaseError(format!("Inserting wallet: {}", e.to_string())))?;

        Ok(())
    })
}

// Called on startup to check database integrity
fn check_db(revaultd: &RevaultD) -> Result<(), DatabaseError> {
    let db_path = revaultd.db_file();
    let wallet = db_wallet(&db_path)?;

    // Check if their database is not from the future.
    // We'll eventually do migration here if version < VERSION, but be strict until then.
    let version = db_version(&db_path)?;
    if version != DB_VERSION {
        return Err(DatabaseError(format!(
            "Unexpected database version: got '{}', expected '{}'",
            version, DB_VERSION
        )));
    }

    // Then that we are on the right network..
    let db_net = db_network(&db_path)?;
    if db_net != revaultd.bitcoind_config.network {
        return Err(DatabaseError(format!(
            "Invalid network. Database is on '{}' but config says '{}'.",
            db_net, revaultd.bitcoind_config.network
        )));
    }

    // .. And managing the same Scripts!
    if revaultd.deposit_descriptor != wallet.deposit_descriptor {
        return Err(DatabaseError(format!(
            "Database Deposit descriptor mismatch: '{}' (config) vs '{}' (database)",
            revaultd.deposit_descriptor, wallet.deposit_descriptor
        )));
    }
    if revaultd.unvault_descriptor != wallet.unvault_descriptor {
        return Err(DatabaseError(format!(
            "Database Unvault descriptor mismatch: '{}' (config) vs '{}' (database)",
            revaultd.unvault_descriptor, wallet.unvault_descriptor
        )));
    }
    if revaultd.cpfp_descriptor != wallet.cpfp_descriptor {
        return Err(DatabaseError(format!(
            "Database Cpfp descriptor mismatch: '{}' (config) vs '{}' (database)",
            revaultd.cpfp_descriptor, wallet.cpfp_descriptor
        )));
    }

    Ok(())
}

// Called on startup to populate our cache from the database
fn state_from_db(revaultd: &mut RevaultD) -> Result<(), DatabaseError> {
    let db_path = revaultd.db_file();
    let wallet = db_wallet(&db_path)?;

    revaultd.tip = Some(db_tip(&db_path)?);

    revaultd.current_unused_index = wallet.deposit_derivation_index;
    // Of course, it's no good... Miniscript on bitcoind soon :tm:
    // FIXME: in the meantime, reversed gap limit?
    let raw_index: u32 = revaultd.current_unused_index.into();
    (0..raw_index + revaultd.gap_limit()).for_each(|i| {
        // FIXME: this should fail instead of creating a hardened index
        let index = ChildNumber::from(i);
        revaultd.derivation_index_map.insert(
            revaultd
                .deposit_descriptor
                .derive(index, &revaultd.secp_ctx)
                .inner()
                .address(revaultd.bitcoind_config.network)
                .expect("deposit_descriptor is a wsh")
                .script_pubkey(),
            index,
        );
    });
    revaultd.wallet_id = Some(wallet.id);

    Ok(())
}

/// This integrity checks the database, creates it if it doesn't exist, and populates miniscript
/// descriptors in the global state. They are already parsed at compile time in order to be able
/// to populate the wallets table if the database does not exist and are always replaced here by
/// the one from the database (compilation from config policy is non-deterministic!)
pub fn setup_db(revaultd: &mut RevaultD) -> Result<(), DatabaseError> {
    let db_path = revaultd.db_file();
    if !db_path.exists() {
        log::info!("No database at {:?}, creating a new one.", db_path);
        create_db(&revaultd)?;
    }

    check_db(&revaultd)?;
    state_from_db(revaultd)?;

    Ok(())
}

pub fn db_update_tip_dbtx(
    db_tx: &rusqlite::Transaction,
    tip: &BlockchainTip,
) -> Result<(), DatabaseError> {
    db_tx
        .execute(
            "UPDATE tip SET blockheight = (?1), blockhash = (?2)",
            params![tip.height, tip.hash.to_vec()],
        )
        .map_err(|e| DatabaseError(format!("Inserting new tip: {}", e.to_string())))
        .map(|_| ())
}

/// Set the current best block hash and height
pub fn db_update_tip(db_path: &Path, tip: &BlockchainTip) -> Result<(), DatabaseError> {
    db_exec(db_path, |db_tx| db_update_tip_dbtx(db_tx, tip))
}

pub fn db_update_deposit_index(
    db_path: &Path,
    new_index: ChildNumber,
) -> Result<(), DatabaseError> {
    let new_index: u32 = new_index.into();
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE wallets SET deposit_derivation_index = (?1)",
            params![new_index],
        )
        .map_err(|e| DatabaseError(format!("Inserting new derivation index: {}", e.to_string())))?;

        Ok(())
    })
}

/// Insert a new deposit in the database
#[allow(clippy::too_many_arguments)]
pub fn db_insert_new_unconfirmed_vault(
    db_path: &Path,
    wallet_id: u32,
    deposit_outpoint: &OutPoint,
    amount: &Amount,
    derivation_index: ChildNumber,
    received_at: u32,
) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        let derivation_index: u32 = derivation_index.into();
        tx.execute(
            "INSERT INTO vaults ( \
                wallet_id, status, blockheight, deposit_txid, deposit_vout, amount, derivation_index, \
                received_at, updated_at, spend_txid \
            ) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
            params![
                wallet_id,
                VaultStatus::Unconfirmed as u32,
                0, // FIXME: it should probably be NULL instead, but no big deal
                deposit_outpoint.txid.to_vec(),
                deposit_outpoint.vout,
                amount_to_i64(amount),
                derivation_index,
                received_at,
                received_at,
            ],
        )
        .map_err(|e| DatabaseError(format!("Inserting vault: {}", e.to_string())))?;

        Ok(())
    })
}

macro_rules! db_store_unsigned_transactions {
    ($db_tx:ident, $vault_id:ident, [$( $tx:ident ),*]) => {
            $(
                // We store the transactions without any feebump input. Note that this assertion
                // would fail if/when we implement multi-inputs Unvaults.
                assert_eq!($tx.psbt().inputs.len(), 1);
                // They must be freshly generated..
                assert!($tx.psbt().inputs[0].partial_sigs.is_empty());

                let tx_type = TransactionType::from($tx);
                let txid = $tx.txid();
                $db_tx
                    .execute(
                        "INSERT INTO presigned_transactions (vault_id, type, psbt, txid, fullysigned) VALUES (?1, ?2, ?3 , ?4, ?5)",
                        params![$vault_id, tx_type as u32, $tx.as_psbt_serialized(), txid.to_vec(), false as u32],
                    )
                    .map_err(|e| {
                        DatabaseError(format!("Inserting psbt in vault '{}': {}", $vault_id, e))
                    })?;
            )*
    };
}

/// Mark an unconfirmed deposit as being in 'Funded' state (confirmed), as well as storing the
/// unsigned "presigned-transactions".
/// The `emer_tx` and `unemer_tx` may only be passed for stakeholders.
pub fn db_confirm_deposit(
    db_path: &Path,
    outpoint: &OutPoint,
    blockheight: u32,
    unvault_tx: &UnvaultTransaction,
    cancel_tx: &CancelTransaction,
    emer_tx: Option<&EmergencyTransaction>,
    unemer_tx: Option<&UnvaultEmergencyTransaction>,
) -> Result<(), DatabaseError> {
    let vault_id = db_vault_by_deposit(db_path, outpoint)?
        .ok_or_else(|| {
            DatabaseError(format!(
                "Confirming '{}' but it does not exist in db?",
                outpoint
            ))
        })?
        .id;

    db_exec(db_path, |db_tx| {
        db_tx
            .execute(
                "UPDATE vaults SET status = (?1), blockheight = (?2), updated_at = strftime('%s','now') WHERE id = (?3)",
                params![VaultStatus::Funded as u32, blockheight, vault_id,],
            )
            .map_err(|e| DatabaseError(format!("Updating vault to 'funded': {}", e.to_string())))?;

        match (emer_tx, unemer_tx) {
            (Some(emer_tx), Some(unemer_tx)) => {
                db_store_unsigned_transactions!(
                    db_tx,
                    vault_id,
                    [unvault_tx, cancel_tx, emer_tx, unemer_tx]
                );
            }
            (None, None) => {
                db_store_unsigned_transactions!(db_tx, vault_id, [unvault_tx, cancel_tx]);
            }
            _ => unreachable!(),
        }

        Ok(())
    })
}

/// Drop all presigned transactions for a vault, therefore dropping all Spend attempts as well and mark
/// it as unconfirmed. The opposite of [db_confirm_deposit].
pub fn db_unconfirm_deposit_dbtx(
    db_tx: &rusqlite::Transaction,
    vault_id: u32,
) -> Result<(), DatabaseError> {
    // FIXME: don't delete everything. This is unnecessary and confusing.

    // This is going to cascade and DELETE the spend_inputs.
    db_tx.execute(
        "DELETE FROM spend_transactions WHERE id = ( \
            SELECT sin.spend_id FROM presigned_transactions as ptx \
            INNER JOIN spend_inputs as sin ON ptx.id = sin.unvault_id \
            WHERE ptx.vault_id = (?1) \
         )",
        params![vault_id],
    )?;
    db_tx.execute(
        "DELETE FROM presigned_transactions WHERE vault_id = (?1)",
        params![vault_id],
    )?;
    db_tx.execute(
        "UPDATE vaults SET status = (?1), blockheight = (?2), updated_at = strftime('%s','now') \
         WHERE id = (?3)",
        params![VaultStatus::Unconfirmed as u32, 0, vault_id],
    )?;

    Ok(())
}

fn dbtx_downgrade(
    db_tx: &rusqlite::Transaction,
    vault_id: u32,
    status: VaultStatus,
) -> Result<(), DatabaseError> {
    db_tx.execute(
        "UPDATE vaults SET status = (?1), updated_at = strftime('%s','now') WHERE id = (?2)",
        params![status as u32, vault_id],
    )?;

    Ok(())
}

/// Downgrade a vault from 'unvaulted' to 'unvaulting'
pub fn db_unconfirm_unvault_dbtx(
    db_tx: &rusqlite::Transaction,
    vault_id: u32,
) -> Result<(), DatabaseError> {
    dbtx_downgrade(db_tx, vault_id, VaultStatus::Unvaulting)
}

/// Downgrade a vault from 'spent' to 'spending'
pub fn db_unconfirm_spend_dbtx(
    db_tx: &rusqlite::Transaction,
    vault_id: u32,
) -> Result<(), DatabaseError> {
    dbtx_downgrade(db_tx, vault_id, VaultStatus::Spending)
}

/// Downgrade a vault from 'canceled' to 'canceling'
pub fn db_unconfirm_cancel_dbtx(
    db_tx: &rusqlite::Transaction,
    vault_id: u32,
) -> Result<(), DatabaseError> {
    dbtx_downgrade(db_tx, vault_id, VaultStatus::Canceling)
}

/// Downgrade a vault from 'emergencied' to 'emergencying'
pub fn db_unconfirm_emer_dbtx(
    db_tx: &rusqlite::Transaction,
    vault_id: u32,
) -> Result<(), DatabaseError> {
    dbtx_downgrade(db_tx, vault_id, VaultStatus::EmergencyVaulting)
}

/// Downgrade a vault from 'unvaultemergencied' to 'unvaultemergencying'
pub fn db_unconfirm_unemer_dbtx(
    db_tx: &rusqlite::Transaction,
    vault_id: u32,
) -> Result<(), DatabaseError> {
    dbtx_downgrade(db_tx, vault_id, VaultStatus::UnvaultEmergencyVaulting)
}

fn db_status_from_unvault_txid(
    db_path: &Path,
    unvault_txid: &Txid,
    status: VaultStatus,
) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE vaults SET status = (?1), updated_at = strftime('%s','now') \
             WHERE vaults.id IN (SELECT vault_id FROM presigned_transactions WHERE txid = (?2))",
            params![status as u32, unvault_txid.to_vec(),],
        )
        .map_err(|e| DatabaseError(format!("Updating vault to '{}': {}", status, e.to_string())))?;

        Ok(())
    })
}

/// Mark an active vault as being in 'unvaulting' state from the Unvault txid
pub fn db_unvault_deposit(db_path: &Path, unvault_txid: &Txid) -> Result<(), DatabaseError> {
    db_status_from_unvault_txid(db_path, unvault_txid, VaultStatus::Unvaulting)
}

/// Mark a vault as being in the 'unvaulted' state, out of the Unvault txid
pub fn db_confirm_unvault(db_path: &Path, unvault_txid: &Txid) -> Result<(), DatabaseError> {
    db_status_from_unvault_txid(db_path, unvault_txid, VaultStatus::Unvaulted)
}

/// Mark a vault as being in the 'canceling' state, out of the Unvault txid
pub fn db_cancel_unvault(db_path: &Path, unvault_txid: &Txid) -> Result<(), DatabaseError> {
    db_status_from_unvault_txid(db_path, unvault_txid, VaultStatus::Canceling)
}

/// Mark a vault as being in the 'spending' state, out of the Unvault txid
pub fn db_spend_unvault(
    db_path: &Path,
    unvault_txid: &Txid,
    spend_txid: &Txid,
) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE vaults SET status = (?1), updated_at = strftime('%s','now'), spend_txid = (?2) \
             WHERE vaults.id IN (SELECT vault_id FROM presigned_transactions WHERE txid = (?3))",
            params![VaultStatus::Spending as u32, spend_txid.to_vec(), unvault_txid.to_vec(),],
        )
        .map_err(|e| DatabaseError(format!("Updating vault to 'spending': {}", e.to_string())))?;

        Ok(())
    })
}

/// Mark a vault as being in the 'unvault_emergency_vaulting' state, out of the Unvault txid
pub fn db_emer_unvault(db_path: &Path, unvault_txid: &Txid) -> Result<(), DatabaseError> {
    db_status_from_unvault_txid(db_path, unvault_txid, VaultStatus::UnvaultEmergencyVaulting)
}

fn db_mark_vault_as(
    db_path: &Path,
    vault_id: u32,
    status: VaultStatus,
) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE vaults SET status = (?1), updated_at = strftime('%s','now') \
             WHERE vaults.id = (?2)",
            params![status as u32, vault_id,],
        )
        .map_err(|e| DatabaseError(format!("Updating vault to '{}': {}", status, e.to_string())))?;

        Ok(())
    })
}

pub fn db_mark_spent_unvault(db_path: &Path, vault_id: u32) -> Result<(), DatabaseError> {
    db_mark_vault_as(&db_path, vault_id, VaultStatus::Spent)
}

pub fn db_mark_canceled_unvault(db_path: &Path, vault_id: u32) -> Result<(), DatabaseError> {
    db_mark_vault_as(&db_path, vault_id, VaultStatus::Canceled)
}

pub fn db_mark_emergencied_unvault(db_path: &Path, vault_id: u32) -> Result<(), DatabaseError> {
    db_mark_vault_as(&db_path, vault_id, VaultStatus::UnvaultEmergencyVaulted)
}

pub fn db_mark_emergencying_vault(db_path: &Path, vault_id: u32) -> Result<(), DatabaseError> {
    db_mark_vault_as(&db_path, vault_id, VaultStatus::EmergencyVaulting)
}

pub fn db_mark_emergencied_vault(db_path: &Path, vault_id: u32) -> Result<(), DatabaseError> {
    db_mark_vault_as(&db_path, vault_id, VaultStatus::EmergencyVaulted)
}

/// Mark that we actually signed this vault's revocation txs, and stored the signatures for it.
pub fn db_mark_securing_vault(db_path: &Path, vault_id: u32) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE vaults SET status = (?1), updated_at = strftime('%s','now') \
             WHERE vaults.id = (?2) AND vaults.status = (?3)",
            params![
                VaultStatus::Securing as u32,
                vault_id,
                VaultStatus::Funded as u32
            ],
        )
        .map_err(|e| DatabaseError(format!("Updating vault to 'securing': {}", e.to_string())))?;

        Ok(())
    })
}

/// Mark that we actually signed this vault's Unvault tx, and stored the signature for it.
pub fn db_mark_activating_vault(db_path: &Path, vault_id: u32) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE vaults SET status = (?1), updated_at = strftime('%s','now') \
             WHERE vaults.id = (?2) AND vaults.status = (?3)",
            params![
                VaultStatus::Activating as u32,
                vault_id,
                VaultStatus::Secured as u32
            ],
        )
        .map_err(|e| DatabaseError(format!("Updating vault to 'securing': {}", e.to_string())))?;

        Ok(())
    })
}

fn revault_tx_merge_sigs(
    tx: &mut impl RevaultTransaction,
    sigs: BTreeMap<BitcoinPubKey, Vec<u8>>,
    secp_ctx: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
) -> Result<(bool, Vec<u8>), DatabaseError> {
    tx.psbt_mut().inputs[0].partial_sigs.extend(sigs);
    let fully_signed = tx.is_finalizable(secp_ctx);
    let raw_psbt = tx.as_psbt_serialized();
    Ok((fully_signed, raw_psbt))
}

/// Update the presigned transaction in-db. If the transaction is valid and no more revocation
/// transactions are remaining unsigned for this vault, it will update the vault status as well in
/// the same database transaction.
pub fn db_update_presigned_tx(
    db_path: &Path,
    vault_id: u32,
    tx_db_id: u32,
    sigs: BTreeMap<BitcoinPubKey, Vec<u8>>,
    secp_ctx: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
) -> Result<(), DatabaseError> {
    db_exec(db_path, move |db_tx| {
        let mut is_unvault = false;

        // Fetch the PSBT in the transaction, to avoid someone else to modify it under our feet..
        let presigned_tx: DbTransaction = db_tx
            .prepare("SELECT * FROM presigned_transactions WHERE id = (?1)")?
            .query(params![tx_db_id])?
            .next()?
            .ok_or_else(|| {
                DatabaseError(format!(
                    "Transaction with id '{}' (vault id '{}') not found in db",
                    tx_db_id, vault_id
                ))
            })?
            .try_into()?;
        // Now we are safe merging the signatures on what is the latest version of the PSBT
        let (fully_signed, raw_psbt) = match presigned_tx.psbt {
            RevaultTx::Cancel(mut tx) => revault_tx_merge_sigs(&mut tx, sigs, secp_ctx)?,
            RevaultTx::Emergency(mut tx) => revault_tx_merge_sigs(&mut tx, sigs, secp_ctx)?,

            RevaultTx::UnvaultEmergency(mut tx) => revault_tx_merge_sigs(&mut tx, sigs, secp_ctx)?,
            RevaultTx::Unvault(mut tx) => {
                is_unvault = true;
                revault_tx_merge_sigs(&mut tx, sigs, secp_ctx)?
            }
        };

        db_tx.execute(
            "UPDATE presigned_transactions SET psbt = (?1), fullysigned = (?2) WHERE id = (?3)",
            params![raw_psbt, fully_signed, tx_db_id],
        )?;

        if fully_signed {
            // Are there some remaining unsigned revocation txs?
            if db_tx
                .prepare(
                    "SELECT * FROM presigned_transactions WHERE fullysigned = 0 AND type != (?1) AND vault_id = (?2)",
                )?
                // All presigned transactions but the Unvault are revocation txs
                .query(params![TransactionType::Unvault as u32, vault_id])?
                .next()?
                .is_none()
            {
                // Nope. Mark the vault as 'secured'
                db_tx
                    .execute(
                        "UPDATE vaults SET status = (?1), updated_at = strftime('%s','now') WHERE id = (?2) ",
                        params![VaultStatus::Secured as u32, vault_id],
                    )
                    .map_err(|e| {
                        DatabaseError(format!("Updating vault to 'secured': {}", e.to_string()))
                    })?;
            }

            // Was it the unvault that was fully signed ? If so, mark the vault as active.
            if is_unvault {
                db_tx
                    .execute(
                        "UPDATE vaults SET status = (?1), updated_at = strftime('%s','now') WHERE id = (?2) ",
                        params![VaultStatus::Active as u32, vault_id],
                    )
                    .map_err(|e| {
                        DatabaseError(format!("Updating vault to 'active': {}", e.to_string()))
                    })?;
            }
        }

        Ok(())
    })
}

/// Insert a new Spend transaction in the database
pub fn db_insert_spend(
    db_path: &Path,
    // FIXME: Rust newbie: i *don't* need to be moving this. So i want to take &[&T] but i can't
    // have it working in a generic manner (eg once by passing a slice the second time by passing a
    // Vec<T> somehow)
    unvault_txs: &[DbTransaction],
    spend_tx: &SpendTransaction,
) -> Result<(), DatabaseError> {
    let spend_txid = spend_tx.txid();
    let spend_psbt = spend_tx.as_psbt_serialized();

    db_exec(db_path, |db_tx| {
        db_tx.execute(
            "INSERT INTO spend_transactions (psbt, txid, broadcasted) VALUES (?1, ?2, NULL)",
            params![spend_psbt, spend_txid.to_vec()],
        )?;
        let spend_id = db_tx.last_insert_rowid();

        for unvault_tx in unvault_txs.into_iter() {
            db_tx.execute(
                "INSERT INTO spend_inputs (unvault_id, spend_id) VALUES (?1, ?2)",
                params![unvault_tx.id, spend_id],
            )?;
        }

        Ok(())
    })
}

pub fn db_update_spend(db_path: &Path, spend_tx: &SpendTransaction) -> Result<(), DatabaseError> {
    let spend_txid = spend_tx.txid();
    let spend_psbt = spend_tx.as_psbt_serialized();

    db_exec(db_path, |db_tx| {
        db_tx.execute(
            "UPDATE spend_transactions SET psbt = (?1) WHERE txid = (?2)",
            params![spend_psbt, spend_txid.to_vec()],
        )?;
        Ok(())
    })
}

pub fn db_delete_spend(db_path: &Path, spend_txid: &Txid) -> Result<(), DatabaseError> {
    db_exec(db_path, |db_tx| {
        db_tx.execute(
            "DELETE FROM spend_inputs WHERE spend_id = (SELECT id FROM \
                spend_transactions WHERE txid = (?1))",
            params![spend_txid.to_vec()],
        )?;
        db_tx.execute(
            "DELETE FROM spend_transactions WHERE txid = (?1)",
            params![spend_txid.to_vec()],
        )?;
        Ok(())
    })
}

pub fn db_mark_broadcastable_spend(db_path: &Path, spend_txid: &Txid) -> Result<(), DatabaseError> {
    db_exec(db_path, |db_tx| {
        db_tx.execute(
            "UPDATE spend_transactions SET broadcasted = 0 WHERE txid = (?1)",
            params![spend_txid.to_vec()],
        )?;
        Ok(())
    })
}

pub fn db_mark_broadcasted_spend(db_path: &Path, spend_txid: &Txid) -> Result<(), DatabaseError> {
    db_exec(db_path, |db_tx| {
        db_tx.execute(
            "UPDATE spend_transactions SET broadcasted = 1 WHERE txid = (?1)",
            params![spend_txid.to_vec()],
        )?;
        Ok(())
    })
}

/// Downgrade a Spend transaction that was broadcasted to being broadcastable
pub fn db_mark_rebroadcastable_spend(
    db_tx: &rusqlite::Transaction,
    unvault_txid: &Txid,
) -> Result<(), DatabaseError> {
    db_tx.execute(
        "UPDATE spend_transactions SET broadcasted = 0 WHERE id = ( \
                SELECT sin.spend_id FROM spend_inputs as sin \
                INNER JOIN presigned_transactions as ptx ON ptx.id = sin.unvault_id \
                INNER JOIN spend_transactions as stx ON stx.id = sin.spend_id \
                WHERE ptx.txid = (?1) AND stx.broadcasted = 1 \
            )",
        params![unvault_txid.to_vec()],
    )?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::database::schema::DbSpendTransaction;
    use crate::jsonrpc::UserRole;
    use crate::utils::test_utils::{dummy_revaultd, test_datadir};
    use revault_tx::{
        bitcoin::{Network, OutPoint, PublicKey},
        transactions::{CancelTransaction, EmergencyTransaction, UnvaultEmergencyTransaction},
    };

    use std::{fs, str::FromStr};

    fn revault_tx_add_dummy_sig(tx: &mut impl RevaultTransaction, input_index: usize) {
        let pubkey = PublicKey::from_str(
            "022634c3c8001a9e7700905281ae601dd73a4375e0e7801c22ffcc0443f5599935",
        )
        .unwrap();
        let sig = vec![
            48, 68, 2, 32, 104, 77, 230, 162, 30, 201, 33, 78, 96, 13, 165, 229, 132, 246, 129,
            200, 125, 122, 177, 58, 8, 201, 76, 192, 149, 116, 228, 71, 144, 48, 41, 92, 2, 32, 30,
            61, 121, 165, 139, 95, 6, 255, 221, 169, 135, 102, 29, 158, 231, 222, 117, 31, 200, 27,
            178, 145, 230, 171, 54, 181, 12, 196, 182, 23, 175, 86, 129,
        ];
        tx.psbt_mut().inputs[input_index]
            .partial_sigs
            .insert(pubkey, sig);
    }

    fn test_db_creation() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);

        create_db(&mut revaultd).unwrap();
        // There must be a wallet entry now, and there is only one so its id must
        // be 0.
        assert_eq!(db_wallet(&revaultd.db_file()).unwrap().id, 1);
        // We can't create it twice
        create_db(&mut revaultd).unwrap_err();
        // The version is right
        check_db(&mut revaultd).unwrap();
        // But it would not open a database created for a different network
        revaultd.bitcoind_config.network = Network::Testnet;
        check_db(&mut revaultd).unwrap_err();
        revaultd.bitcoind_config.network = Network::Bitcoin;
        // Neither would it accept to open a database from the future!
        db_exec(&revaultd.db_file(), |tx| {
            tx.execute("UPDATE version SET version = (?1)", params![DB_VERSION + 1])
                .unwrap();
            Ok(())
        })
        .unwrap();
        check_db(&mut revaultd).unwrap_err();

        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }

    fn test_db_fetch_deposits() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);
        let db_path = revaultd.db_file();

        setup_db(&mut revaultd).unwrap();

        let wallet_id = 1;
        let first_deposit_outpoint = OutPoint::from_str(
            "4d799e993665149109682555ba482b386aea03c5dbd62c059b48eb8f40f2f040:0",
        )
        .unwrap();
        let amount = Amount::from_sat(123456);
        let received_at = 1615297315;
        let derivation_index = ChildNumber::from(3);
        db_insert_new_unconfirmed_vault(
            &db_path,
            wallet_id,
            &first_deposit_outpoint,
            &amount,
            derivation_index,
            received_at,
        )
        .unwrap();

        let wallet_id = 1;
        let second_deposit_outpoint = OutPoint::from_str(
            "e56808d17a866de5a1d0874894c84a759a7cabc8763694966cc6423f4c597a7f:0",
        )
        .unwrap();
        let amount = Amount::from_sat(456789);
        let received_at = 1615297315;
        let derivation_index = ChildNumber::from(12);
        db_insert_new_unconfirmed_vault(
            &db_path,
            wallet_id,
            &second_deposit_outpoint,
            &amount,
            derivation_index,
            received_at,
        )
        .unwrap();

        let wallet_id = 1;
        let third_deposit_outpoint = OutPoint::from_str(
            "616efc37747c8cafc2f99692177a5400bad81b671d8d35ffa347d84b246e9a83:0",
        )
        .unwrap();
        let amount = Amount::from_sat(428000);
        let received_at = 1615297315;
        let derivation_index = ChildNumber::from(15);
        db_insert_new_unconfirmed_vault(
            &db_path,
            wallet_id,
            &third_deposit_outpoint,
            &amount,
            derivation_index,
            received_at,
        )
        .unwrap();

        // By the way, trying to insert for an inexistant wallet will fail the
        // db constraint
        db_insert_new_unconfirmed_vault(
            &db_path,
            wallet_id + 1,
            &third_deposit_outpoint,
            &amount,
            derivation_index,
            received_at,
        )
        .unwrap_err();

        // Now retrieve the deposits; there must all be there
        let deposit_outpoints: Vec<OutPoint> = db_deposits(&db_path)
            .unwrap()
            .into_iter()
            .map(|db_vault| db_vault.deposit_outpoint)
            .collect();
        assert_eq!(deposit_outpoints.len(), 3);
        assert!(deposit_outpoints.contains(&first_deposit_outpoint));
        assert!(deposit_outpoints.contains(&second_deposit_outpoint));
        assert!(deposit_outpoints.contains(&third_deposit_outpoint));

        // Now if we mark the first as being unvaulted we'll only fetch the two last ones
        db_exec(&db_path, |tx| {
            tx.execute(
                "UPDATE vaults SET status = (?1), updated_at = strftime('%s','now') \
                 WHERE deposit_txid = (?2) AND deposit_vout = (?3) ",
                params![
                    VaultStatus::Unvaulting as u32,
                    first_deposit_outpoint.txid.to_vec(),
                    first_deposit_outpoint.vout
                ],
            )
            .unwrap();
            Ok(())
        })
        .unwrap();
        let deposit_outpoints: Vec<OutPoint> = db_deposits(&db_path)
            .unwrap()
            .into_iter()
            .map(|db_vault| db_vault.deposit_outpoint)
            .collect();
        assert_eq!(deposit_outpoints.len(), 2);
        assert!(!deposit_outpoints.contains(&first_deposit_outpoint));
        assert!(deposit_outpoints.contains(&second_deposit_outpoint));
        assert!(deposit_outpoints.contains(&third_deposit_outpoint));

        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }

    fn test_db_store_presigned_txs() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);
        let db_path = revaultd.db_file();

        setup_db(&mut revaultd).unwrap();

        // There is no fully signed Emergency transaction at this point.
        assert!(db_signed_emer_txs(&db_path).unwrap().is_empty());
        assert!(db_signed_unemer_txs(&db_path).unwrap().is_empty());

        // Let's insert a deposit
        let wallet_id = 1;
        let outpoint = OutPoint::from_str(
            "4d799e993665149109682555ba482b386aea03c5dbd62c059b48eb8f40f2f040:0",
        )
        .unwrap();
        let amount = Amount::from_sat(123456);
        let received_at = 1615297315;
        let derivation_index = ChildNumber::from(33334);
        db_insert_new_unconfirmed_vault(
            &db_path,
            wallet_id,
            &outpoint,
            &amount,
            derivation_index,
            received_at,
        )
        .unwrap();
        let db_vault = db_vault_by_deposit(&db_path, &outpoint).unwrap().unwrap();

        // We can store unsigned transactions
        let fresh_emer_tx = EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAVqQwvZ+XLjEW+P90WnqdbVWkC1riPNhF8j9Ca4dM0RiAAAAAAD9////AfhgAwAAAAAAIgAgB6abzQJ4vo5CO9XW3r3JnNumTwlpQbZm9FVICsLHPYQAAAAAAAEBK4iUAwAAAAAAIgAgB6abzQJ4vo5CO9XW3r3JnNumTwlpQbZm9FVICsLHPYQBAwSBAAAAAQVHUiED35umh5GhiToV6GS7lTokWfq/Rvy+rRI9XMQuf+foOoEhA9GtXpHhUvxcj9DJWbaRvz59CNsMwH2NEvmRa8gc2WRkUq4AAA==").unwrap();
        let fresh_cancel_tx = CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAARoHs0elD2sCfWV4+b7PH3aRA+BkRVNf3m/P+Epjx2fNAAAAAAD9////AdLKAgAAAAAAIgAgB6abzQJ4vo5CO9XW3r3JnNumTwlpQbZm9FVICsLHPYQAAAAAAAEBK0ANAwAAAAAAIgAglEs6phQpv+twnAQSdjDvAEic65OtUIijeePBzAAqr50BAwSBAAAAAQWrIQO4lrAuffeRLuEEuwp2hAMZIPmqaHMTUySM3OwdA2hIW6xRh2R2qRTflccImFIy5NdTqwPuPZFB7g1pvYisa3apFOQxXoLeQv/aDFfav/l6YnYRKt+1iKxsk1KHZ1IhA32Q1DEqQ/kUP2MvQYFW46RCexZ5aYk17Arhp01th+37IQNrXQtfIXQdrv+RyyHLilJsb4ujlUMddG9X2jYkeXiWoFKvA3nxALJoAAEBR1IhA9+bpoeRoYk6Fehku5U6JFn6v0b8vq0SPVzELn/n6DqBIQPRrV6R4VL8XI/QyVm2kb8+fQjbDMB9jRL5kWvIHNlkZFKuAA==").unwrap();
        let fresh_unemer_tx = UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAZHNg0DZSHTBSpVaGwH2apdYBRu88ZeeB/XmrijJpvH5AAAAAAD9////AdLKAgAAAAAAIgAg8Wcu+wsgQXcO9MAiWSMtqsVSQkptpfTXJ51MFSdhJAoAAAAAAAEBK0ANAwAAAAAAIgAgtSqMFDOQ2FkdNrt/yUTzVjikth3tOm+um6yLFzLTilcBAwSBAAAAAQWrIQJF6Amv78N3ctJ3+oSlIasXN3/N8H/bu2si9Vu3QNBRuKxRh2R2qRS77fZRBsFKSf1uP2HBT3uhL1oRloisa3apFIPfFe62NUR/RApmlyj0VsJJdJ4CiKxsk1KHZ1IhA5scAvk3lvCVQmoWDTHhcd8utuA6Swf2PolVbdB7yVwnIQIXS76HRC/hWucQkpC43HriwIukm1se8QRc9nIlODCN81KvA37BALJoAAA=").unwrap();
        let fresh_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAcRWqIPG85zGye1nuRlbwWKkko4g91Vd/508Ff6vKklpAAAAAAD9////AkANAwAAAAAAIgAgsT7u0Lo8o2WEfxS1nXWtQzsdJTMJnnOC5fwg0nYPvpowdQAAAAAAACIAIAx0DegrXfBr4D0XdetrGgAT2Q3AZANYm0rJL8L/Epp/AAAAAAABASuIlAMAAAAAACIAIGaHQ5brMNbT+WCtfE/WPW8gkmMir5NXAKRsQZAs9cT2AQMEAQAAAAEFR1IhAwYSJ4FeXdf/XPw6lFHpeMFeGvh88f+rWN2VtnaW75TNIQOn5Sg6nytLwT5FT9z5KmV/LMN1pZRsqbworUMwRdRN0lKuAAEBqiEDdDY+WLVpanVLROFc6wsvXyFG4FUgYknnTic2GPQNIy6sUYdkdqkUNlKGE2FxZM1sR08UC7GJfzRqXlSIrGt2qRQoTG+3hS6ElXzBw+21PRDtEJ9sKoisbJNSh2dSIQNiqGzCWTbNvmnTm7l6YNTctgzoP5xaOW6hiXSWVkoClCEC/w0jRRlaB3Oa5c0OPrRAxbxE1kdfzV24OWsaSCGLgIVSrwLWNLJoAAEBJSEDdDY+WLVpanVLROFc6wsvXyFG4FUgYknnTic2GPQNIy6sUYcA").unwrap();

        let blockheight = 700000;
        db_confirm_deposit(
            &db_path,
            &outpoint,
            blockheight,
            &fresh_unvault_tx,
            &fresh_cancel_tx,
            Some(&fresh_emer_tx),
            Some(&fresh_unemer_tx),
        )
        .unwrap();

        // There is still no *fully signed* Emergency transaction at this point!
        assert!(db_signed_emer_txs(&db_path).unwrap().is_empty());
        assert!(db_signed_unemer_txs(&db_path).unwrap().is_empty());

        // Sanity check we can add sigs to them now
        let (tx_db_id, stored_cancel_tx) = db_cancel_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        assert_eq!(stored_cancel_tx.psbt().inputs[0].partial_sigs.len(), 0);
        let mut cancel_tx = fresh_cancel_tx.clone();
        revault_tx_add_dummy_sig(&mut cancel_tx, 0);
        db_update_presigned_tx(
            &db_path,
            db_vault.id,
            tx_db_id,
            cancel_tx.psbt().inputs[0].partial_sigs.clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();
        let (_, stored_cancel_tx) = db_cancel_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        assert_eq!(stored_cancel_tx.psbt().inputs[0].partial_sigs.len(), 1);

        let (tx_db_id, stored_emer_tx) =
            db_emer_transaction(&db_path, db_vault.id).unwrap().unwrap();
        assert_eq!(stored_emer_tx.psbt().inputs[0].partial_sigs.len(), 0);
        let mut emer_tx = fresh_emer_tx.clone();
        revault_tx_add_dummy_sig(&mut emer_tx, 0);
        db_update_presigned_tx(
            &db_path,
            db_vault.id,
            tx_db_id,
            emer_tx.psbt().inputs[0].partial_sigs.clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();
        let (_, stored_emer_tx) = db_emer_transaction(&db_path, db_vault.id).unwrap().unwrap();
        assert_eq!(stored_emer_tx.psbt().inputs[0].partial_sigs.len(), 1);

        let (tx_db_id, stored_unemer_tx) = db_unvault_emer_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        assert_eq!(stored_unemer_tx.psbt().inputs[0].partial_sigs.len(), 0);
        let mut unemer_tx = fresh_unemer_tx.clone();
        revault_tx_add_dummy_sig(&mut unemer_tx, 0);
        db_update_presigned_tx(
            &db_path,
            db_vault.id,
            tx_db_id,
            unemer_tx.psbt().inputs[0].partial_sigs.clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();
        let (_, stored_unemer_tx) = db_unvault_emer_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        assert_eq!(stored_unemer_tx.psbt().inputs[0].partial_sigs.len(), 1);

        let (tx_db_id, stored_unvault_tx) = db_unvault_transaction(&db_path, db_vault.id).unwrap();
        assert_eq!(stored_unvault_tx.psbt().inputs[0].partial_sigs.len(), 0);
        let mut unvault_tx = fresh_unvault_tx.clone();
        revault_tx_add_dummy_sig(&mut unvault_tx, 0);
        db_update_presigned_tx(
            &db_path,
            db_vault.id,
            tx_db_id,
            unvault_tx.psbt().inputs[0].partial_sigs.clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();
        let (_, stored_unvault_tx) = db_unvault_transaction(&db_path, db_vault.id).unwrap();
        assert_eq!(stored_unvault_tx.psbt().inputs[0].partial_sigs.len(), 1);

        // They can also be queried
        assert_eq!(
            emer_tx,
            db_emer_transaction(&db_path, db_vault.id)
                .unwrap()
                .unwrap()
                .1
        );
        assert_eq!(
            cancel_tx,
            db_cancel_transaction(&db_path, db_vault.id)
                .unwrap()
                .unwrap()
                .1
        );
        assert_eq!(
            unemer_tx,
            db_unvault_emer_transaction(&db_path, db_vault.id)
                .unwrap()
                .unwrap()
                .1
        );
        assert_eq!(
            unvault_tx,
            db_unvault_transaction(&db_path, db_vault.id).unwrap().1
        );

        // And removed, if there is eg a reorg.
        db_exec(&db_path, |db_tx| {
            db_unconfirm_deposit_dbtx(&db_tx, db_vault.id).unwrap();
            Ok(())
        })
        .unwrap();
        assert!(db_emer_transaction(&db_path, db_vault.id)
            .unwrap()
            .is_none());
        assert!(db_cancel_transaction(&db_path, db_vault.id)
            .unwrap()
            .is_none());
        assert!(db_unvault_emer_transaction(&db_path, db_vault.id)
            .unwrap()
            .is_none());
        db_unvault_transaction(&db_path, db_vault.id).unwrap_err();

        // And re-added of course
        db_confirm_deposit(
            &db_path,
            &outpoint,
            blockheight,
            &fresh_unvault_tx,
            &fresh_cancel_tx,
            Some(&fresh_emer_tx),
            Some(&fresh_unemer_tx),
        )
        .unwrap();
        // But not twice! (UNIQUE on the psbt field)
        db_confirm_deposit(
            &db_path,
            &outpoint,
            blockheight,
            &fresh_unvault_tx,
            &fresh_cancel_tx,
            Some(&fresh_emer_tx),
            Some(&fresh_unemer_tx),
        )
        .unwrap_err();

        // If we mark the Emergency transaction as fully signed, it'll get returned by the
        // fetcher.
        db_exec(&db_path, |tx| {
            tx.execute(
                "UPDATE presigned_transactions SET fullysigned = 1 WHERE txid = (?1)",
                params![fresh_emer_tx.txid().to_vec()],
            )?;
            Ok(())
        })
        .unwrap();
        assert_eq!(db_signed_emer_txs(&db_path).unwrap().len(), 1);
        assert!(db_signed_unemer_txs(&db_path).unwrap().is_empty());
        // If we mark the UnvaultEmergency transaction as fully signed and the vault as
        // Unvaulting, it'll get returned by the unemer fetcher instead.
        db_unvault_deposit(&db_path, &fresh_unvault_tx.txid()).unwrap();
        db_exec(&db_path, |tx| {
            tx.execute(
                "UPDATE presigned_transactions SET fullysigned = 1 WHERE txid = (?1)",
                params![fresh_unemer_tx.txid().to_vec()],
            )?;
            Ok(())
        })
        .unwrap();
        assert!(db_signed_emer_txs(&db_path).unwrap().is_empty());
        assert_eq!(db_signed_unemer_txs(&db_path).unwrap().len(), 1);

        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }

    // There we trigger a concurrent write access to the database by inserting a deposit and
    // updating its presigned transaction in two different thread. It should be fine and one of
    // them just lock thanks to the unlock_notify feature of SQLite https://sqlite.org/unlock_notify.html
    fn test_db_concurrent_write() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);
        let db_path = revaultd.db_file();

        setup_db(&mut revaultd).unwrap();

        // Let's insert a deposit
        let wallet_id = 1;
        let outpoint = OutPoint::from_str(
            "adaa5a4b9fb07c860f8de460727b6bad4b5ab01d2e7f90f6f3f15a0080020168:0",
        )
        .unwrap();
        let amount = Amount::from_sat(123456);
        let received_at = 1615297315;
        let derivation_index = ChildNumber::from(33334);
        db_insert_new_unconfirmed_vault(
            &db_path,
            wallet_id,
            &outpoint,
            &amount,
            derivation_index,
            received_at,
        )
        .unwrap();
        let db_vault = db_vault_by_deposit(&db_path, &outpoint).unwrap().unwrap();

        let fresh_cancel_tx = CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAARoHs0elD2sCfWV4+b7PH3aRA+BkRVNf3m/P+Epjx2fNAAAAAAD9////AdLKAgAAAAAAIgAgB6abzQJ4vo5CO9XW3r3JnNumTwlpQbZm9FVICsLHPYQAAAAAAAEBK0ANAwAAAAAAIgAglEs6phQpv+twnAQSdjDvAEic65OtUIijeePBzAAqr50BAwSBAAAAAQWrIQO4lrAuffeRLuEEuwp2hAMZIPmqaHMTUySM3OwdA2hIW6xRh2R2qRTflccImFIy5NdTqwPuPZFB7g1pvYisa3apFOQxXoLeQv/aDFfav/l6YnYRKt+1iKxsk1KHZ1IhA32Q1DEqQ/kUP2MvQYFW46RCexZ5aYk17Arhp01th+37IQNrXQtfIXQdrv+RyyHLilJsb4ujlUMddG9X2jYkeXiWoFKvA3nxALJoAAEBR1IhA9+bpoeRoYk6Fehku5U6JFn6v0b8vq0SPVzELn/n6DqBIQPRrV6R4VL8XI/QyVm2kb8+fQjbDMB9jRL5kWvIHNlkZFKuAA==").unwrap();
        let fresh_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAT7KJ+fkvbKBDobFTsm31LqtMUfhTiR5tWA5XJA9oYgOAAAAAAD9////AkANAwAAAAAAIgAgbMJH4U4sOCdd1R9PVUuEbmS4bkbnNNlJaqxZBqXHwCcwdQAAAAAAACIAIM8vNQyMFHWpzTmNSefLOTf0spivub9JuegPqYdx0rLvAAAAAAABASuIlAMAAAAAACIAIONmt9fso2OE03OxwV4EkzSucRgHSh3ylMy/KcBayrRaAQMEAQAAAAEFR1IhAum/3N5NY9BZnqXIJxEBNzNEhHwCOY4WQ5xdZZ9XN4+dIQNwiQrXHbeULZ18BN3FOfnYK48NrsVzMDAXVEiu7HfvylKuAAEBqiEDsTozyBugih4LqhjAbDEbxv0SImcwm7uxgzAxpprx+hasUYdkdqkUq3ciI2+fP8tZgD/nHHJDhb3wHtOIrGt2qRQHsYoc0BfpfAKimvmP+V1XXUmr1YisbJNSh2dSIQMDsoKW2AvcnJM8c2BZo1U7OHGc2kUyfe5wh8GxWejwmiECwXo562TGRJPfOC0ooMYiE0XPegUlr7E9sCVTApCykntSrwJQBbJoAAEBJSEDsTozyBugih4LqhjAbDEbxv0SImcwm7uxgzAxpprx+hasUYcA").unwrap();

        let blockheight = 2300000;
        db_confirm_deposit(
            &db_path,
            &outpoint,
            blockheight,
            &fresh_unvault_tx,
            &fresh_cancel_tx,
            None,
            None,
        )
        .unwrap();

        let (tx_db_id, _) = db_cancel_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        let mut cancel_tx = fresh_cancel_tx.clone();
        revault_tx_add_dummy_sig(&mut cancel_tx, 0);
        let handle = std::thread::spawn({
            let db_path = db_path.clone();
            let cancel_tx = cancel_tx.clone();
            let secp = revaultd.secp_ctx.clone();
            move || {
                for _ in 0..10 {
                    db_update_presigned_tx(
                        &db_path,
                        db_vault.id,
                        tx_db_id,
                        cancel_tx.psbt().inputs[0].partial_sigs.clone(),
                        &secp,
                    )
                    .unwrap();
                }
            }
        });
        for _ in 0..10 {
            db_update_presigned_tx(
                &db_path,
                db_vault.id,
                tx_db_id,
                cancel_tx.psbt().inputs[0].partial_sigs.clone(),
                &revaultd.secp_ctx,
            )
            .unwrap();
        }
        handle.join().unwrap();
        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }

    fn test_db_spend_storage() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);
        let db_path = revaultd.db_file();
        let fresh_cancel_tx = CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAARoHs0elD2sCfWV4+b7PH3aRA+BkRVNf3m/P+Epjx2fNAAAAAAD9////AdLKAgAAAAAAIgAgB6abzQJ4vo5CO9XW3r3JnNumTwlpQbZm9FVICsLHPYQAAAAAAAEBK0ANAwAAAAAAIgAglEs6phQpv+twnAQSdjDvAEic65OtUIijeePBzAAqr50BAwSBAAAAAQWrIQO4lrAuffeRLuEEuwp2hAMZIPmqaHMTUySM3OwdA2hIW6xRh2R2qRTflccImFIy5NdTqwPuPZFB7g1pvYisa3apFOQxXoLeQv/aDFfav/l6YnYRKt+1iKxsk1KHZ1IhA32Q1DEqQ/kUP2MvQYFW46RCexZ5aYk17Arhp01th+37IQNrXQtfIXQdrv+RyyHLilJsb4ujlUMddG9X2jYkeXiWoFKvA3nxALJoAAEBR1IhA9+bpoeRoYk6Fehku5U6JFn6v0b8vq0SPVzELn/n6DqBIQPRrV6R4VL8XI/QyVm2kb8+fQjbDMB9jRL5kWvIHNlkZFKuAA==").unwrap();
        let fresh_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAfF2iPeJqz13zFlW6eLAM+uDu5IhUqcQxtMWQx7z5Y8lAAAAAAD9////AkANAwAAAAAAIgAgKb0SdnuqeHAJpRuZTbk3r81qbXpuHrMEmxT9Kph47HQwdQAAAAAAACIAIIMbpoIz4DI+aB1p/EJLyqjyDdDeZ7gG8kPhRIDiWaY8AAAAAAABASuIlAMAAAAAACIAIA9CgZ1cg/hn3iy3buDZvU5zUnQ9NzutToR/r42YZyu3AQMEAQAAAAEFR1IhA9P6hV8yf6HkNofzleom06eqkUxZayWHJnOMNlMtqvD3IQJo5Mj6Wf3ktrwEB3IQXFmgApibojplpNykg0hA8XV6SFKuAAEBqiEDH7uO3i4mHhzemNwtVZNHJIJlonzMuSFIWjx2zRC1fd2sUYdkdqkU7YhsQQ+SqzEEFOlBsds7CjDH+pyIrGt2qRQgyrXvSLg3hdA+BgPyUVDV+MYLfoisbJNSh2dSIQM0zz54678zxZovq2jUerGPFk7dSjbrFcKfNrlnm81g8CECpdtZmV+1gEIUb3YYcKlALkHyHpoPc5EwgsjEPkPAlRVSrwKlAbJoAAEBJSEDH7uO3i4mHhzemNwtVZNHJIJlonzMuSFIWjx2zRC1fd2sUYcA").unwrap();
        let fullysigned_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAfF2iPeJqz13zFlW6eLAM+uDu5IhUqcQxtMWQx7z5Y8lAAAAAAD9////AkANAwAAAAAAIgAgKb0SdnuqeHAJpRuZTbk3r81qbXpuHrMEmxT9Kph47HQwdQAAAAAAACIAIIMbpoIz4DI+aB1p/EJLyqjyDdDeZ7gG8kPhRIDiWaY8AAAAAAABASuIlAMAAAAAACIAIA9CgZ1cg/hn3iy3buDZvU5zUnQ9NzutToR/r42YZyu3IgICaOTI+ln95La8BAdyEFxZoAKYm6I6ZaTcpINIQPF1ekhHMEQCIGwH+/OfgUAbJwthOxnMAR4zoLf/ispCH50wqin3TERrAiBak0Xw5+dQ3Od68PWZ65UPLQXG070wCX9pfcInGVUiagEiAgPT+oVfMn+h5DaH85XqJtOnqpFMWWslhyZzjDZTLarw90cwRAIgA/69zvbYYHbKpBId51MVBeS0xIMF/DZJJ+9/UytAh/0CIBG6NR6AulGTLlMGP6bYMqMQ9HRKlAVFSvEK8dVQ2FdeAQEDBAEAAAABBUdSIQPT+oVfMn+h5DaH85XqJtOnqpFMWWslhyZzjDZTLarw9yECaOTI+ln95La8BAdyEFxZoAKYm6I6ZaTcpINIQPF1ekhSrgABAaohAx+7jt4uJh4c3pjcLVWTRySCZaJ8zLkhSFo8ds0QtX3drFGHZHapFO2IbEEPkqsxBBTpQbHbOwowx/qciKxrdqkUIMq170i4N4XQPgYD8lFQ1fjGC36IrGyTUodnUiEDNM8+eOu/M8WaL6to1HqxjxZO3Uo26xXCnza5Z5vNYPAhAqXbWZlftYBCFG92GHCpQC5B8h6aD3ORMILIxD5DwJUVUq8CpQGyaAABASUhAx+7jt4uJh4c3pjcLVWTRySCZaJ8zLkhSFo8ds0QtX3drFGHAA==").unwrap();

        setup_db(&mut revaultd).unwrap();

        // Let's insert a deposit
        let wallet_id = 1;
        let outpoint = OutPoint::from_str(
            "c9cf38058b720050bcba47490ee27f4a29d57a5aa2ee0f3c97731e140dbeced7:1",
        )
        .unwrap();
        let amount = Amount::from_sat(612345);
        let derivation_index = ChildNumber::from(349874);
        let received_at = 17890233;
        db_insert_new_unconfirmed_vault(
            &db_path,
            wallet_id,
            &outpoint,
            &amount,
            derivation_index,
            received_at,
        )
        .unwrap();
        let db_vault = db_vault_by_deposit(&db_path, &outpoint).unwrap().unwrap();

        // Have the Unvault tx fully signed
        db_confirm_deposit(
            &db_path,
            &outpoint,
            9,
            &fresh_unvault_tx,
            &fresh_cancel_tx,
            None,
            None,
        )
        .unwrap();
        db_update_presigned_tx(
            &db_path,
            db_vault.id,
            db_unvault_transaction(&db_path, db_vault.id).unwrap().0,
            fullysigned_unvault_tx.psbt().inputs[0].partial_sigs.clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();

        // We can store a Spend tx spending a single unvault and query it
        let spend_tx = SpendTransaction::from_psbt_str("cHNidP8BAGcCAAAAAciTbKS43sH49TJWX6xJ+MxqWfNQhRl+vkttRZ9sLUkHAAAAAAClAQAAAoAyAAAAAAAAIgAggxumgjPgMj5oHWn8QkvKqPIN0N5nuAbyQ+FEgOJZpjygjAIAAAAAAAAAAAAAAAEBK0ANAwAAAAAAIgAgKb0SdnuqeHAJpRuZTbk3r81qbXpuHrMEmxT9Kph47HQBAwQBAAAAAQWqIQMfu47eLiYeHN6Y3C1Vk0ckgmWifMy5IUhaPHbNELV93axRh2R2qRTtiGxBD5KrMQQU6UGx2zsKMMf6nIisa3apFCDKte9IuDeF0D4GA/JRUNX4xgt+iKxsk1KHZ1IhAzTPPnjrvzPFmi+raNR6sY8WTt1KNusVwp82uWebzWDwIQKl21mZX7WAQhRvdhhwqUAuQfIemg9zkTCCyMQ+Q8CVFVKvAqUBsmgAAQElIQMfu47eLiYeHN6Y3C1Vk0ckgmWifMy5IUhaPHbNELV93axRhwAA").unwrap();
        let spend_tx_inputs = &spend_tx.tx().input;
        assert_eq!(spend_tx_inputs.len(), 1);
        let (_, db_unvault) =
            db_vault_by_unvault_txid(&db_path, &spend_tx_inputs[0].previous_output.txid)
                .unwrap()
                .unwrap();
        db_insert_spend(&db_path, &[db_unvault.clone()], &spend_tx).unwrap();
        let spend_txid = spend_tx.txid();
        assert_eq!(
            db_list_spends(&db_path).unwrap().get(&spend_txid),
            Some(&(
                DbSpendTransaction {
                    id: 1,
                    psbt: spend_tx.clone(),
                    broadcasted: None
                },
                vec![outpoint]
            ))
        );

        // We can update it, eg with a Spend with more sigs
        let spend_tx = SpendTransaction::from_psbt_str("cHNidP8BAGcCAAAAAciTbKS43sH49TJWX6xJ+MxqWfNQhRl+vkttRZ9sLUkHAAAAAAClAQAAAoAyAAAAAAAAIgAggxumgjPgMj5oHWn8QkvKqPIN0N5nuAbyQ+FEgOJZpjygjAIAAAAAAAAAAAAAAAEBK0ANAwAAAAAAIgAgKb0SdnuqeHAJpRuZTbk3r81qbXpuHrMEmxT9Kph47HQiAgKl21mZX7WAQhRvdhhwqUAuQfIemg9zkTCCyMQ+Q8CVFUgwRQIhAJynJJuu8tq0mN1SEeWUZRN67KlKL0zHOyrWuPRUp6UjAiAjYDl5/pwMHns9XUYHzrHfLaxjHFg419NFQPCX2wfHrQEiAgMfu47eLiYeHN6Y3C1Vk0ckgmWifMy5IUhaPHbNELV93UcwRAIgF4HaNIfFLQ537aR9opqlY4SN+v3dt7GnSKR2kIGp8n4CIBQQQg13scqRYVQHJf1oS4N8cb6PHmyzGpcDCp6rIbMNASICAzTPPnjrvzPFmi+raNR6sY8WTt1KNusVwp82uWebzWDwRzBEAiBuu/TH4/aBrZPy/+TtpJLxztEJQWcYxjEpPe2s6iChCAIgfE09pqQAcDhYaoEVG7tPOUsc3B/HuOrHOyDfCzSz5kABAQMEAQAAAAEFqiEDH7uO3i4mHhzemNwtVZNHJIJlonzMuSFIWjx2zRC1fd2sUYdkdqkU7YhsQQ+SqzEEFOlBsds7CjDH+pyIrGt2qRQgyrXvSLg3hdA+BgPyUVDV+MYLfoisbJNSh2dSIQM0zz54678zxZovq2jUerGPFk7dSjbrFcKfNrlnm81g8CECpdtZmV+1gEIUb3YYcKlALkHyHpoPc5EwgsjEPkPAlRVSrwKlAbJoAAEBJSEDH7uO3i4mHhzemNwtVZNHJIJlonzMuSFIWjx2zRC1fd2sUYcAAA==").unwrap();
        db_update_spend(&db_path, &spend_tx).unwrap();
        let spend_txid = spend_tx.txid();
        assert_eq!(
            db_list_spends(&db_path).unwrap().get(&spend_txid),
            Some(&(
                DbSpendTransaction {
                    id: 1,
                    psbt: spend_tx.clone(),
                    broadcasted: None
                },
                vec![outpoint]
            ))
        );

        // And delete it
        db_delete_spend(&db_path, &spend_tx.txid()).unwrap();
        assert!(db_list_spends(&db_path).unwrap().get(&spend_txid).is_none());

        // And this works with multiple unvaults too

        // Re-insert the previous one so we have many references to the first Unvault
        db_insert_spend(&db_path, &[db_unvault.clone()], &spend_tx).unwrap();

        // Same as above with a new vault
        let cancel_tx = CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAAc+BIbsSvYK/BWRNOAjazIlLfjlVzCCtXvoyN5/bydgEAAAAAAD9////AdLKAgAAAAAAIgAgFy2HNuxbT516bQQBY3R04IkEja348wJveLmF73Tj/owAAAAAAAEBK0ANAwAAAAAAIgAgZw+cwq8wJzworIDuy6s8cpOo3uF8fYyL5pECqg0UVagBAwSBAAAAAQWrIQLDtCYN0BlQw/h5zAcF0yXft2G7vAjkRsD9B9uoiyr1x6xRh2R2qRTGFACwvLOTrJHUPKb3ifnio7mt0Yisa3apFOZTIiKdGP+9rilwd09H1kOsfB/PiKxsk1KHZ1IhAtGKwcs21FeGy2qY+fzQ9uvI4X5ThtCqkwHsGtKQx0jYIQP93zm1sGAtxTNxsYQTkoXt26FoyKWNh1sx6hmk1yVzYlKvA8aOALJoAAEBR1IhA8HKPHwUwdE4CMkbosklbbI6mPPzzVnOom7LFxQbvCfYIQJ358C4w7CQrcz3UUcpo8eqsRn5JTM0Y0ge5Fz3CApS7lKuAA==").unwrap();
        let fresh_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAe7jtZYQ3avFhc+JxU4paq8e26NIkAB1zHLgv6mKWxgBAAAAAAD9////AkANAwAAAAAAIgAgdS3fC7QX+PKWZBful8J229uixPOW012CYpKMH7rU8T4wdQAAAAAAACIAIAGCzzZ7K80GkoO2mUdCVIFx7Tum52UXob8ascs1uZucAAAAAAABASuIlAMAAAAAACIAIFvpTQQruW8AB+k+csGMaThNLBAzppkxo+k4Hb2SZ4hKAQMEAQAAAAEFR1IhAvkWJfB/ssW9YaE7llH/y/1FBJ/LK+ybOJiT8j+O4cnhIQIS4abTQKWATfsTrVsEPfkCUHvxY4M0F+ZDz502NXMy1FKuAAEBqiEC262VFMR0zQS8kl+14wQWuWrsU347lEh8RN7ydSV33ZWsUYdkdqkUvIrspFvJQ2XUVl4CuFGNICwJI1+IrGt2qRSfpUNGG4+BIoO9/dUxLcYpID+Aw4isbJNSh2dSIQKkxJmDMXYy1OdMI/x8PV9j3+1kQ0gpzuD+KqSeYfjzTiEDtqfLJXVbB4YRIpsvmVtBNS971+XfZqkNHdNV1Xcdw1lSrwKHG7JoAAEBJSEC262VFMR0zQS8kl+14wQWuWrsU347lEh8RN7ydSV33ZWsUYcA").unwrap();
        let fullysigned_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAe7jtZYQ3avFhc+JxU4paq8e26NIkAB1zHLgv6mKWxgBAAAAAAD9////AkANAwAAAAAAIgAgdS3fC7QX+PKWZBful8J229uixPOW012CYpKMH7rU8T4wdQAAAAAAACIAIAGCzzZ7K80GkoO2mUdCVIFx7Tum52UXob8ascs1uZucAAAAAAABASuIlAMAAAAAACIAIFvpTQQruW8AB+k+csGMaThNLBAzppkxo+k4Hb2SZ4hKIgICEuGm00ClgE37E61bBD35AlB78WODNBfmQ8+dNjVzMtRHMEQCID2my9yVWxgLSDKDBL5PmF9FVZC6b8mLu598Rq8oebjQAiB3FC3br7rS6bkKOKa4h9Ml1nicuPWpXTWjAWrALVTd+gEiAgL5FiXwf7LFvWGhO5ZR/8v9RQSfyyvsmziYk/I/juHJ4UcwRAIgGfJBreyXt5Isv9PjLRJCFy5jVrMGieGsvV01LTPf3/gCICS81/Mvot0WYdlXC+FnAQ4AprXIQH+g1pnDomBGO+UZAQEDBAEAAAABBUdSIQL5FiXwf7LFvWGhO5ZR/8v9RQSfyyvsmziYk/I/juHJ4SECEuGm00ClgE37E61bBD35AlB78WODNBfmQ8+dNjVzMtRSrgABAaohAtutlRTEdM0EvJJfteMEFrlq7FN+O5RIfETe8nUld92VrFGHZHapFLyK7KRbyUNl1FZeArhRjSAsCSNfiKxrdqkUn6VDRhuPgSKDvf3VMS3GKSA/gMOIrGyTUodnUiECpMSZgzF2MtTnTCP8fD1fY9/tZENIKc7g/iqknmH4804hA7anyyV1WweGESKbL5lbQTUve9fl32apDR3TVdV3HcNZUq8ChxuyaAABASUhAtutlRTEdM0EvJJfteMEFrlq7FN+O5RIfETe8nUld92VrFGHAA==").unwrap();
        let wallet_id = 1;
        let outpoint_b = OutPoint::from_str(
            "2117d7c3461ca013a099d8e60b0bcc6c33aec95db49f636c479ab85117479a91:0",
        )
        .unwrap();
        let amount = Amount::from_sat(112245);
        let derivation_index = ChildNumber::from(643874);
        let received_at = 2615297315;
        db_insert_new_unconfirmed_vault(
            &db_path,
            wallet_id,
            &outpoint_b,
            &amount,
            derivation_index,
            received_at,
        )
        .unwrap();
        let db_vault = db_vault_by_deposit(&db_path, &outpoint_b).unwrap().unwrap();
        db_confirm_deposit(
            &db_path,
            &outpoint_b,
            9,
            &fresh_unvault_tx,
            &cancel_tx,
            None,
            None,
        )
        .unwrap();
        db_update_presigned_tx(
            &db_path,
            db_vault.id,
            db_unvault_transaction(&db_path, db_vault.id).unwrap().0,
            fullysigned_unvault_tx.psbt().inputs[0].partial_sigs.clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();

        let spend_tx_b = SpendTransaction::from_psbt_str("cHNidP8BAGcCAAAAAXHqOcTAJnPyXEF1cxFATe4S6yHLGZm+s0aj9mUTtKgVAAAAAACHGwAAAoAyAAAAAAAAIgAgAYLPNnsrzQaSg7aZR0JUgXHtO6bnZRehvxqxyzW5m5ygjAIAAAAAAAAAAAAAAAEBK0ANAwAAAAAAIgAgdS3fC7QX+PKWZBful8J229uixPOW012CYpKMH7rU8T4BAwQBAAAAAQWqIQLbrZUUxHTNBLySX7XjBBa5auxTfjuUSHxE3vJ1JXfdlaxRh2R2qRS8iuykW8lDZdRWXgK4UY0gLAkjX4isa3apFJ+lQ0Ybj4Eig7391TEtxikgP4DDiKxsk1KHZ1IhAqTEmYMxdjLU50wj/Hw9X2Pf7WRDSCnO4P4qpJ5h+PNOIQO2p8sldVsHhhEimy+ZW0E1L3vX5d9mqQ0d01XVdx3DWVKvAocbsmgAAQElIQLbrZUUxHTNBLySX7XjBBa5auxTfjuUSHxE3vJ1JXfdlaxRhwAA").unwrap();
        let spend_tx_b_inputs = &spend_tx_b.tx().input;
        assert_eq!(spend_tx_b_inputs.len(), 1);
        let (_, db_unvault_b) =
            db_vault_by_unvault_txid(&db_path, &spend_tx_b_inputs[0].previous_output.txid)
                .unwrap()
                .unwrap();
        db_insert_spend(&db_path, &[db_unvault, db_unvault_b], &spend_tx_b).unwrap();
        let spend_txid = spend_tx.txid();
        assert_eq!(
            db_list_spends(&db_path).unwrap().get(&spend_txid),
            Some(&(
                DbSpendTransaction {
                    id: 1,
                    psbt: spend_tx.clone(),
                    broadcasted: None
                },
                vec![outpoint]
            ))
        );
        let spend_txid_b = spend_tx_b.txid();
        assert_eq!(
            db_list_spends(&db_path).unwrap().get(&spend_txid_b),
            Some(&(
                DbSpendTransaction {
                    id: 2,
                    psbt: spend_tx_b.clone(),
                    broadcasted: None
                },
                vec![outpoint, outpoint_b]
            ))
        );

        let spend_tx_b = SpendTransaction::from_psbt_str("cHNidP8BAGcCAAAAAXHqOcTAJnPyXEF1cxFATe4S6yHLGZm+s0aj9mUTtKgVAAAAAACHGwAAAoAyAAAAAAAAIgAgAYLPNnsrzQaSg7aZR0JUgXHtO6bnZRehvxqxyzW5m5ygjAIAAAAAAAAAAAAAAAEBK0ANAwAAAAAAIgAgdS3fC7QX+PKWZBful8J229uixPOW012CYpKMH7rU8T4iAgKkxJmDMXYy1OdMI/x8PV9j3+1kQ0gpzuD+KqSeYfjzTkgwRQIhAMwdbbLXqH49pRfZR6PtSzNg/MB+DuVo1xs7rPTZQ12RAiBDSHEGyQaE1K+wknL2IFnhWXKn+/YSfSMtMg9u4zepNwEiAgO2p8sldVsHhhEimy+ZW0E1L3vX5d9mqQ0d01XVdx3DWUcwRAIgRhhHxuXx5X2eniy4tMP4wP2xoBD+XZlxMQiF9HoXIDYCIEfKdXOOILXSFKeOZ2v6nomllEQOyjuBUk+0LhK7+55mASICAtutlRTEdM0EvJJfteMEFrlq7FN+O5RIfETe8nUld92VSDBFAiEAzSxWF19m2/1Sh92jahJ/A6pMvmCa95USVSXzPEOBn3ACIHzYQdjjDJIhZ5z1xkduaEtjvYtLDIauoMA00xO6fok3AQEDBAEAAAABBaohAtutlRTEdM0EvJJfteMEFrlq7FN+O5RIfETe8nUld92VrFGHZHapFLyK7KRbyUNl1FZeArhRjSAsCSNfiKxrdqkUn6VDRhuPgSKDvf3VMS3GKSA/gMOIrGyTUodnUiECpMSZgzF2MtTnTCP8fD1fY9/tZENIKc7g/iqknmH4804hA7anyyV1WweGESKbL5lbQTUve9fl32apDR3TVdV3HcNZUq8ChxuyaAABASUhAtutlRTEdM0EvJJfteMEFrlq7FN+O5RIfETe8nUld92VrFGHAAA=").unwrap();
        db_update_spend(&db_path, &spend_tx_b).unwrap();

        // There are 2 Unvaults referenced by this Spend
        let db_spend = db_spend_transaction(&db_path, &spend_tx_b.txid())
            .unwrap()
            .unwrap();
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let unvault_psbts = conn
            .prepare(
                "SELECT ptx.psbt FROM presigned_transactions as ptx \
             INNER JOIN spend_inputs as sin ON ptx.id = sin.unvault_id \
             INNER JOIN spend_transactions as stx ON stx.id = sin.spend_id \
             WHERE stx.id = (?1)",
            )
            .unwrap()
            .query_map(rusqlite::params![db_spend.id], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<Vec<u8>>>>()
            .unwrap();
        assert_eq!(unvault_psbts.len(), 2);
        for psbt in unvault_psbts {
            UnvaultTransaction::from_psbt_serialized(&psbt).unwrap();
        }

        // Thus there are 2 vaults too
        let spent_outpoints: Vec<OutPoint> = db_vaults_from_spend(&db_path, &spend_tx_b.txid())
            .unwrap()
            .into_iter()
            .map(|(_, db_vault)| db_vault.deposit_outpoint)
            .collect();
        assert_eq!(spent_outpoints.len(), 2);
        assert!(spent_outpoints.contains(&outpoint));
        assert!(spent_outpoints.contains(&outpoint_b));

        let spend_txid = spend_tx.txid();
        assert!(db_spend_transaction(&db_path, &spend_txid)
            .unwrap()
            .unwrap()
            .broadcasted
            .is_none());
        assert_eq!(
            db_broadcastable_spend_transactions(&db_path).unwrap().len(),
            0
        );
        db_mark_broadcastable_spend(&db_path, &spend_txid).unwrap();
        assert_eq!(
            db_broadcastable_spend_transactions(&db_path).unwrap().len(),
            1
        );
        assert!(!db_spend_transaction(&db_path, &spend_txid)
            .unwrap()
            .unwrap()
            .broadcasted
            .unwrap(),);
        db_mark_broadcasted_spend(&db_path, &spend_txid).unwrap();
        assert_eq!(
            db_broadcastable_spend_transactions(&db_path).unwrap().len(),
            0
        );
        assert!(db_spend_transaction(&db_path, &spend_txid)
            .unwrap()
            .unwrap()
            .broadcasted
            .unwrap());

        // And we can delete the transaction
        db_delete_spend(&db_path, &spend_txid).unwrap();
        assert!(db_spend_transaction(&db_path, &spend_txid)
            .unwrap()
            .is_none());

        // And if we unconfirm the vault, it'll delete the last remaining transaction
        let txid_b = spend_tx_b.txid();
        db_exec(&db_path, |db_tx| {
            db_unconfirm_deposit_dbtx(&db_tx, db_vault.id).unwrap();
            Ok(())
        })
        .unwrap();
        assert!(db_spend_transaction(&db_path, &txid_b).unwrap().is_none());
        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }

    // We disabled #[test] for the above, as they may erase the db concurrently.
    // Instead, run them sequentially.
    #[test]
    fn db_sequential_test_runner() {
        test_db_creation();
        test_db_fetch_deposits();
        test_db_store_presigned_txs();
        test_db_concurrent_write();
        test_db_spend_storage();
    }
}
