use crate::{
    database::{
        bitcointx::{RevaultTx, TransactionType},
        interface::*,
        schema::{DbTransaction, DbVault, SCHEMA},
        DatabaseError, DB_VERSION,
    },
    revaultd::{BlockchainTip, RevaultD, VaultStatus},
};
use revault_tx::{
    bitcoin::{secp256k1, util::bip32::ChildNumber, Amount, OutPoint, Txid},
    miniscript::descriptor::DescriptorTrait,
    transactions::{
        CancelTransaction, EmergencyTransaction, RevaultTransaction, SpendTransaction,
        UnvaultEmergencyTransaction, UnvaultTransaction,
    },
};

use std::{
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
        tx.execute_batch(SCHEMA)
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
        create_db(revaultd)?;
    }

    check_db(revaultd)?;
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
) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        let derivation_index: u32 = derivation_index.into();
        tx.execute(
            "INSERT INTO vaults ( \
                wallet_id, status, blockheight, deposit_txid, deposit_vout, amount, derivation_index, \
                funded_at, secured_at, delegated_at, moved_at, final_txid, emer_shared \
            ) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL, NULL, NULL, NULL, 0)",
            params![
                wallet_id,
                VaultStatus::Unconfirmed as u32,
                0, // FIXME: it should probably be NULL instead, but no big deal
                deposit_outpoint.txid.to_vec(),
                deposit_outpoint.vout,
                amount_to_i64(amount),
                derivation_index,
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
#[allow(clippy::too_many_arguments)]
pub fn db_confirm_deposit(
    db_path: &Path,
    outpoint: &OutPoint,
    blockheight: u32,
    blocktime: u32,
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
                "UPDATE vaults SET status = (?1), blockheight = (?2), funded_at = (?3) WHERE id = (?4)",
                params![VaultStatus::Funded as u32, blockheight, blocktime, vault_id,],
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
        "UPDATE vaults SET status = (?1), blockheight = (?2), \
         funded_at = NULL, secured_at = NULL, delegated_at = NULL \
         WHERE id = (?3)",
        params![VaultStatus::Unconfirmed as u32, 0, vault_id],
    )?;

    Ok(())
}

/// Update the vault status and enforce that moved_at is NULL
fn dbtx_downgrade(
    db_tx: &rusqlite::Transaction,
    vault_id: u32,
    status: VaultStatus,
) -> Result<(), DatabaseError> {
    // Because the status is downgraded, status cannot be one of the statuses
    // of the end of a vault lifecycle.
    assert!(!matches!(
        status,
        VaultStatus::Canceled
            | VaultStatus::Spent
            | VaultStatus::UnvaultEmergencyVaulted
            | VaultStatus::EmergencyVaulted
    ));
    db_tx.execute(
        "UPDATE vaults SET status = (?1), moved_at = NULL WHERE id = (?2)",
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

/// Update vault status from its unvault transaction ID.
fn db_status_from_unvault_txid(
    db_path: &Path,
    unvault_txid: &Txid,
    status: VaultStatus,
) -> Result<(), DatabaseError> {
    // Theses statuses cannot be set without their respective timestamps.
    assert!(!matches!(
        status,
        VaultStatus::Funded
            | VaultStatus::Secured
            | VaultStatus::Active
            | VaultStatus::Spent
            | VaultStatus::Canceled
            | VaultStatus::EmergencyVaulted
            | VaultStatus::UnvaultEmergencyVaulted
    ));
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE vaults SET status = (?1) \
             WHERE vaults.id IN (SELECT vault_id FROM presigned_transactions WHERE txid = (?2))",
            params![status as u32, unvault_txid.to_vec(),],
        )
        .map_err(|e| DatabaseError(format!("Updating vault to '{}': {}", status, e.to_string())))?;

        Ok(())
    })
}

fn db_status_and_final_txid_from_unvault_txid(
    db_path: &Path,
    unvault_txid: &Txid,
    status: VaultStatus,
    final_txid: &Txid,
) -> Result<(), DatabaseError> {
    // Since the final txid is given, status can only be spending/spent or canceling/canceled.
    assert!(matches!(
        status,
        VaultStatus::Canceling | VaultStatus::Canceled | VaultStatus::Spending | VaultStatus::Spent
    ));
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE vaults SET status = (?1), final_txid = (?2) \
             WHERE vaults.id IN (SELECT vault_id FROM presigned_transactions WHERE txid = (?3))",
            params![status as u32, final_txid.to_vec(), unvault_txid.to_vec(),],
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
pub fn db_cancel_unvault(
    db_path: &Path,
    unvault_txid: &Txid,
    cancel_txid: &Txid,
) -> Result<(), DatabaseError> {
    db_status_and_final_txid_from_unvault_txid(
        db_path,
        unvault_txid,
        VaultStatus::Canceling,
        cancel_txid,
    )
}

/// Mark a vault as being in the 'spending' state, out of the Unvault txid
pub fn db_spend_unvault(
    db_path: &Path,
    unvault_txid: &Txid,
    spend_txid: &Txid,
) -> Result<(), DatabaseError> {
    db_status_and_final_txid_from_unvault_txid(
        db_path,
        unvault_txid,
        VaultStatus::Spending,
        spend_txid,
    )
}

/// Mark a vault as being in the 'unvault_emergency_vaulting' state, out of the Unvault txid
pub fn db_emer_unvault(db_path: &Path, unvault_txid: &Txid) -> Result<(), DatabaseError> {
    db_status_from_unvault_txid(db_path, unvault_txid, VaultStatus::UnvaultEmergencyVaulting)
}

/// Update vault status and moved_at timestamp with the given status and blocktime.
fn db_mark_vault_as_moved(
    db_path: &Path,
    vault_id: u32,
    status: VaultStatus,
    blocktime: u32,
) -> Result<(), DatabaseError> {
    // Because vault is moved and last transaction is confirmed, status must match the statuses of
    // the end of the vault lifecycle.
    assert!(matches!(
        status,
        VaultStatus::Canceled
            | VaultStatus::Spent
            | VaultStatus::EmergencyVaulted
            | VaultStatus::UnvaultEmergencyVaulted
    ));
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE vaults SET status = (?1), moved_at = (?2) \
             WHERE vaults.id = (?3)",
            params![status as u32, blocktime, vault_id],
        )?;

        Ok(())
    })
}

/// Update vault status to `spent` and set moved_at with given blocktime.
pub fn db_mark_spent_unvault(
    db_path: &Path,
    vault_id: u32,
    blocktime: u32,
) -> Result<(), DatabaseError> {
    db_mark_vault_as_moved(db_path, vault_id, VaultStatus::Spent, blocktime)
}

/// Update vault status to `canceled` and set moved_at with given blocktime.
pub fn db_mark_canceled_unvault(
    db_path: &Path,
    vault_id: u32,
    blocktime: u32,
) -> Result<(), DatabaseError> {
    db_mark_vault_as_moved(db_path, vault_id, VaultStatus::Canceled, blocktime)
}

/// Update vault status to `emergencied` and set moved_at with given blocktime.
pub fn db_mark_emergencied_unvault(
    db_path: &Path,
    vault_id: u32,
    blocktime: u32,
) -> Result<(), DatabaseError> {
    db_mark_vault_as_moved(
        db_path,
        vault_id,
        VaultStatus::UnvaultEmergencyVaulted,
        blocktime,
    )
}

pub fn db_mark_emergencying_vault(db_path: &Path, vault_id: u32) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE vaults SET status = (?1) \
             WHERE vaults.id = (?2)",
            params![VaultStatus::EmergencyVaulting as u32, vault_id],
        )?;

        Ok(())
    })
}

pub fn db_mark_emergencied_vault(
    db_path: &Path,
    vault_id: u32,
    blocktime: u32,
) -> Result<(), DatabaseError> {
    db_mark_vault_as_moved(db_path, vault_id, VaultStatus::EmergencyVaulted, blocktime)
}

/// Mark that we actually signed this vault's revocation txs, and stored the signatures for it.
pub fn db_mark_securing_vault(db_path: &Path, vault_id: u32) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE vaults SET status = (?1) \
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
            "UPDATE vaults SET status = (?1) \
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

/// Mark a vault as having its Emergency signature already shared with the watchtowers.
pub fn db_mark_emer_shared(db_path: &Path, db_vault: &DbVault) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE vaults SET emer_shared = 1 WHERE vaults.id = (?1)",
            params![db_vault.id],
        )
        .map(|_| ())
        .map_err(DatabaseError::from)
    })
}

// Merge the partial sigs of two transactions of the same type into the first one
//
// Returns true if this made the transaction "valid" (fully signed).
fn revault_txs_merge_sigs<T, S>(tx_a: &mut T, tx_b: &T, secp: &secp256k1::Secp256k1<S>) -> bool
where
    T: RevaultTransaction,
    S: secp256k1::Verification,
{
    for (pubkey, sig) in &tx_b.psbt().inputs[0].partial_sigs {
        let sig = secp256k1::Signature::from_der(&sig[..sig.len() - 1]).expect("From DB");
        tx_a.add_signature(0, pubkey.key, sig, secp)
            .expect("From an in-DB PSBT");
    }

    tx_a.is_finalizable(secp)
}

// Merge the signatures for two transactions into the first one
//
// The two transaction MUST be of the same type.
fn db_txs_merge_sigs(
    tx_a: &mut DbTransaction,
    tx_b: &DbTransaction,
    secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
) -> bool {
    assert_eq!(tx_a.tx_type, tx_b.tx_type);

    match tx_a.psbt {
        RevaultTx::Unvault(ref mut tx_a) => {
            revault_txs_merge_sigs(tx_a, tx_b.psbt.unwrap_unvault(), secp)
        }
        RevaultTx::Cancel(ref mut tx_a) => {
            revault_txs_merge_sigs(tx_a, tx_b.psbt.unwrap_cancel(), secp)
        }
        RevaultTx::Emergency(ref mut tx_a) => {
            revault_txs_merge_sigs(tx_a, tx_b.psbt.unwrap_emer(), secp)
        }
        RevaultTx::UnvaultEmergency(ref mut tx_a) => {
            revault_txs_merge_sigs(tx_a, tx_b.psbt.unwrap_unvault_emer(), secp)
        }
    }
}

/// Update the transactions of a given vault with the signatures of the given transactions.
///
/// The provided transactions MUST be valid, there signatures aren't checked.
pub fn db_update_presigned_txs(
    db_path: &Path,
    db_vault: &DbVault,
    transactions: Vec<DbTransaction>,
    secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
) -> Result<(), DatabaseError> {
    db_exec(db_path, move |db_tx| {
        for mut transaction in transactions {
            // Merge the transaction with the in-db ones, in case another thread modified
            // it under our feet.
            let db_transaction: DbTransaction = db_tx
                .prepare("SELECT * FROM presigned_transactions WHERE id = (?1)")?
                .query(params![transaction.id])?
                .next()?
                // Note this can happen if another thread removed them.
                .ok_or_else(|| {
                    DatabaseError(format!(
                        "Transaction with id '{}' (vault id '{}') not found in db",
                        transaction.id, db_vault.id
                    ))
                })?
                .try_into()?;
            let is_fully_signed = db_txs_merge_sigs(&mut transaction, &db_transaction, secp);
            db_tx.execute(
                "UPDATE presigned_transactions SET psbt = (?1), fullysigned = (?2) WHERE id = (?3)",
                params![transaction.psbt.ser(), is_fully_signed, transaction.id],
            )?;
        }

        Ok(())
    })
}

/// Update vault status to active or secured if the vault presigned_transactions are fully signed
/// and the associated timestamps secured_at and delegated_at in the case they are null.
pub fn db_update_vault_status(db_path: &Path, db_vault: &DbVault) -> Result<(), DatabaseError> {
    assert!(matches!(
        db_vault.status,
        VaultStatus::Unconfirmed
            | VaultStatus::Funded
            | VaultStatus::Securing
            | VaultStatus::Secured
            | VaultStatus::Activating
    ));

    db_exec(db_path, |db_tx| {
        let db_transactions: Vec<DbTransaction> = db_tx
            .prepare("SELECT * FROM presigned_transactions WHERE vault_id = (?1)")?
            .query_map(params![db_vault.id], |row| row.try_into())?
            .collect::<rusqlite::Result<Vec<DbTransaction>>>()?;

        if db_transactions.is_empty() {
            return Ok(());
        }

        let (mut all_signed, mut all_but_unvault_signed) = (true, true);
        for db_tx in db_transactions {
            if !db_tx.is_fully_signed {
                all_signed = false;
                if !matches!(db_tx.tx_type, TransactionType::Unvault) {
                    all_but_unvault_signed = false;
                    break;
                }
            }
        }

        if all_signed {
            db_tx.execute(
                "UPDATE vaults \
                 SET status = (?1), secured_at = ifnull(secured_at, strftime('%s','now')), delegated_at = strftime('%s','now') \
                 WHERE vaults.id = (?2)",
                params![VaultStatus::Active as u32, db_vault.id],
            )?;
        } else if all_but_unvault_signed
            && matches!(
                db_vault.status,
                VaultStatus::Unconfirmed | VaultStatus::Funded | VaultStatus::Securing
            )
        {
            db_tx.execute(
                "UPDATE vaults \
                 SET status = (?1), secured_at = strftime('%s','now') \
                 WHERE vaults.id = (?2)",
                params![VaultStatus::Secured as u32, db_vault.id],
            )?;
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
            "INSERT INTO spend_transactions (psbt, txid, broadcasted, has_priority) VALUES (?1, ?2, NULL, false)",
            params![spend_psbt, spend_txid.to_vec()],
        )?;
        let spend_id = db_tx.last_insert_rowid();

        for unvault_tx in unvault_txs {
            db_tx.execute(
                "INSERT INTO spend_inputs (unvault_id, spend_id) VALUES (?1, ?2)",
                params![unvault_tx.id, spend_id],
            )?;
        }

        Ok(())
    })
}

pub fn db_update_spend(
    db_path: &Path,
    spend_tx: &SpendTransaction,
    has_priority: bool,
) -> Result<(), DatabaseError> {
    let spend_txid = spend_tx.txid();
    let spend_psbt = spend_tx.as_psbt_serialized();

    db_exec(db_path, |db_tx| {
        db_tx.execute(
            "UPDATE spend_transactions SET psbt = (?1), has_priority = (?2) WHERE txid = (?3)",
            params![spend_psbt, has_priority, spend_txid.to_vec()],
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
    use crate::utils::test_utils::{dummy_revaultd, test_datadir, UserRole};
    use revault_tx::{
        bitcoin::{
            Network, OutPoint, PrivateKey as BitcoinPrivKey, PublicKey as BitcoinPubKey,
            SigHashType,
        },
        transactions::{CancelTransaction, EmergencyTransaction, UnvaultEmergencyTransaction},
    };

    use std::{collections, fs, str::FromStr};

    /// Force the status in database for a given vault.
    fn db_mark_vault_as(
        db_path: &Path,
        vault_id: u32,
        status: VaultStatus,
    ) -> Result<(), DatabaseError> {
        db_exec(db_path, |tx| {
            tx.execute(
                "UPDATE vaults SET status = (?1) \
             WHERE vaults.id = (?2)",
                params![status as u32, vault_id,],
            )
            .map_err(|e| {
                DatabaseError(format!("Updating vault to '{}': {}", status, e.to_string()))
            })?;

            Ok(())
        })
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

    fn revault_tx_add_sig(
        tx: &mut impl RevaultTransaction,
        input_index: usize,
        sighash_type: SigHashType,
        secp_ctx: &secp256k1::Secp256k1<secp256k1::All>,
    ) {
        let (privkey, pubkey) = create_keys(secp_ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let signature_hash =
            secp256k1::Message::from_slice(&tx.signature_hash(input_index, sighash_type).unwrap())
                .unwrap();
        let signature = secp_ctx.sign(&signature_hash, &privkey.key);
        tx.add_signature(input_index, pubkey.key, signature, secp_ctx)
            .unwrap();
    }

    fn update_presigned_tx<C>(
        db_path: &std::path::PathBuf,
        db_vault: &DbVault,
        mut db_tx: DbTransaction,
        sigs: &collections::BTreeMap<BitcoinPubKey, Vec<u8>>,
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

    #[test]
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

    #[test]
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
        let derivation_index = ChildNumber::from(3);
        db_insert_new_unconfirmed_vault(
            &db_path,
            wallet_id,
            &first_deposit_outpoint,
            &amount,
            derivation_index,
        )
        .unwrap();

        let wallet_id = 1;
        let second_deposit_outpoint = OutPoint::from_str(
            "e56808d17a866de5a1d0874894c84a759a7cabc8763694966cc6423f4c597a7f:0",
        )
        .unwrap();
        let amount = Amount::from_sat(456789);
        let derivation_index = ChildNumber::from(12);
        db_insert_new_unconfirmed_vault(
            &db_path,
            wallet_id,
            &second_deposit_outpoint,
            &amount,
            derivation_index,
        )
        .unwrap();

        let wallet_id = 1;
        let third_deposit_outpoint = OutPoint::from_str(
            "616efc37747c8cafc2f99692177a5400bad81b671d8d35ffa347d84b246e9a83:0",
        )
        .unwrap();
        let amount = Amount::from_sat(428000);
        let derivation_index = ChildNumber::from(15);
        db_insert_new_unconfirmed_vault(
            &db_path,
            wallet_id,
            &third_deposit_outpoint,
            &amount,
            derivation_index,
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
                "UPDATE vaults SET status = (?1) \
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

    #[test]
    fn test_db_store_presigned_txs() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);
        let db_path = revaultd.db_file();
        let secp_ctx = secp256k1::Secp256k1::new();

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
        let derivation_index = ChildNumber::from(33334);
        db_insert_new_unconfirmed_vault(&db_path, wallet_id, &outpoint, &amount, derivation_index)
            .unwrap();
        let db_vault = db_vault_by_deposit(&db_path, &outpoint).unwrap().unwrap();

        // We can store unsigned transactions
        let fresh_emer_tx = EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAVqQwvZ+XLjEW+P90WnqdbVWkC1riPNhF8j9Ca4dM0RiAAAAAAD9////AfhgAwAAAAAAIgAgB6abzQJ4vo5CO9XW3r3JnNumTwlpQbZm9FVICsLHPYQAAAAAAAEBK4iUAwAAAAAAIgAgB6abzQJ4vo5CO9XW3r3JnNumTwlpQbZm9FVICsLHPYQBAwSBAAAAAQVHUiED35umh5GhiToV6GS7lTokWfq/Rvy+rRI9XMQuf+foOoEhA9GtXpHhUvxcj9DJWbaRvz59CNsMwH2NEvmRa8gc2WRkUq4iBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAAiAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap();
        let fresh_cancel_tx = CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAARoHs0elD2sCfWV4+b7PH3aRA+BkRVNf3m/P+Epjx2fNAAAAAAD9////AdLKAgAAAAAAIgAgB6abzQJ4vo5CO9XW3r3JnNumTwlpQbZm9FVICsLHPYQAAAAAAAEBK0ANAwAAAAAAIgAglEs6phQpv+twnAQSdjDvAEic65OtUIijeePBzAAqr50BAwSBAAAAAQWrIQO4lrAuffeRLuEEuwp2hAMZIPmqaHMTUySM3OwdA2hIW6xRh2R2qRTflccImFIy5NdTqwPuPZFB7g1pvYisa3apFOQxXoLeQv/aDFfav/l6YnYRKt+1iKxsk1KHZ1IhA32Q1DEqQ/kUP2MvQYFW46RCexZ5aYk17Arhp01th+37IQNrXQtfIXQdrv+RyyHLilJsb4ujlUMddG9X2jYkeXiWoFKvA3nxALJoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQFHUiED35umh5GhiToV6GS7lTokWfq/Rvy+rRI9XMQuf+foOoEhA9GtXpHhUvxcj9DJWbaRvz59CNsMwH2NEvmRa8gc2WRkUq4iAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap();
        let fresh_unemer_tx = UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAZHNg0DZSHTBSpVaGwH2apdYBRu88ZeeB/XmrijJpvH5AAAAAAD9////AdLKAgAAAAAAIgAg8Wcu+wsgQXcO9MAiWSMtqsVSQkptpfTXJ51MFSdhJAoAAAAAAAEBK0ANAwAAAAAAIgAgtSqMFDOQ2FkdNrt/yUTzVjikth3tOm+um6yLFzLTilcBAwSBAAAAAQWrIQJF6Amv78N3ctJ3+oSlIasXN3/N8H/bu2si9Vu3QNBRuKxRh2R2qRS77fZRBsFKSf1uP2HBT3uhL1oRloisa3apFIPfFe62NUR/RApmlyj0VsJJdJ4CiKxsk1KHZ1IhA5scAvk3lvCVQmoWDTHhcd8utuA6Swf2PolVbdB7yVwnIQIXS76HRC/hWucQkpC43HriwIukm1se8QRc9nIlODCN81KvA37BALJoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap();
        let fresh_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAcRWqIPG85zGye1nuRlbwWKkko4g91Vd/508Ff6vKklpAAAAAAD9////AkANAwAAAAAAIgAgsT7u0Lo8o2WEfxS1nXWtQzsdJTMJnnOC5fwg0nYPvpowdQAAAAAAACIAIAx0DegrXfBr4D0XdetrGgAT2Q3AZANYm0rJL8L/Epp/AAAAAAABASuIlAMAAAAAACIAIGaHQ5brMNbT+WCtfE/WPW8gkmMir5NXAKRsQZAs9cT2AQMEAQAAAAEFR1IhAwYSJ4FeXdf/XPw6lFHpeMFeGvh88f+rWN2VtnaW75TNIQOn5Sg6nytLwT5FT9z5KmV/LMN1pZRsqbworUMwRdRN0lKuIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQGqIQN0Nj5YtWlqdUtE4VzrCy9fIUbgVSBiSedOJzYY9A0jLqxRh2R2qRQ2UoYTYXFkzWxHTxQLsYl/NGpeVIisa3apFChMb7eFLoSVfMHD7bU9EO0Qn2wqiKxsk1KHZ1IhA2KobMJZNs2+adObuXpg1Ny2DOg/nFo5bqGJdJZWSgKUIQL/DSNFGVoHc5rlzQ4+tEDFvETWR1/NXbg5axpIIYuAhVKvAtY0smgiAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAABASUhA3Q2Pli1aWp1S0ThXOsLL18hRuBVIGJJ504nNhj0DSMurFGHIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap();

        let blockheight = 700000;
        let blocktime = 700000;
        db_confirm_deposit(
            &db_path,
            &outpoint,
            blockheight,
            blocktime,
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
        let stored_cancel_tx = db_cancel_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        assert_eq!(
            stored_cancel_tx.psbt.unwrap_cancel().psbt().inputs[0]
                .partial_sigs
                .len(),
            0
        );
        let mut cancel_tx = fresh_cancel_tx.clone();
        revault_tx_add_sig(
            &mut cancel_tx,
            0,
            SigHashType::AllPlusAnyoneCanPay,
            &secp_ctx,
        );
        update_presigned_tx(
            &db_path,
            &db_vault,
            stored_cancel_tx,
            &cancel_tx.psbt().inputs[0].partial_sigs,
            &revaultd.secp_ctx,
        );
        let stored_cancel_tx = db_cancel_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        assert_eq!(
            stored_cancel_tx.psbt.unwrap_cancel().psbt().inputs[0]
                .partial_sigs
                .len(),
            1
        );

        let stored_emer_tx = db_emer_transaction(&db_path, db_vault.id).unwrap().unwrap();
        assert_eq!(
            stored_emer_tx.psbt.unwrap_emer().psbt().inputs[0]
                .partial_sigs
                .len(),
            0
        );
        let mut emer_tx = fresh_emer_tx.clone();
        revault_tx_add_sig(&mut emer_tx, 0, SigHashType::AllPlusAnyoneCanPay, &secp_ctx);
        update_presigned_tx(
            &db_path,
            &db_vault,
            stored_emer_tx,
            &emer_tx.psbt().inputs[0].partial_sigs,
            &revaultd.secp_ctx,
        );
        let stored_emer_tx = db_emer_transaction(&db_path, db_vault.id).unwrap().unwrap();
        assert_eq!(
            stored_emer_tx.psbt.unwrap_emer().psbt().inputs[0]
                .partial_sigs
                .len(),
            1
        );

        let stored_unemer_tx = db_unvault_emer_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        assert_eq!(
            stored_unemer_tx.psbt.unwrap_unvault_emer().psbt().inputs[0]
                .partial_sigs
                .len(),
            0
        );
        let mut unemer_tx = fresh_unemer_tx.clone();
        revault_tx_add_sig(
            &mut unemer_tx,
            0,
            SigHashType::AllPlusAnyoneCanPay,
            &secp_ctx,
        );
        update_presigned_tx(
            &db_path,
            &db_vault,
            stored_unemer_tx,
            &unemer_tx.psbt().inputs[0].partial_sigs,
            &revaultd.secp_ctx,
        );
        let stored_unemer_tx = db_unvault_emer_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        assert_eq!(
            stored_unemer_tx.psbt.unwrap_unvault_emer().psbt().inputs[0]
                .partial_sigs
                .len(),
            1
        );

        let stored_unvault_tx = db_unvault_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        assert_eq!(
            stored_unvault_tx.psbt.unwrap_unvault().psbt().inputs[0]
                .partial_sigs
                .len(),
            0
        );
        let mut unvault_tx = fresh_unvault_tx.clone();
        revault_tx_add_sig(&mut unvault_tx, 0, SigHashType::All, &secp_ctx);
        update_presigned_tx(
            &db_path,
            &db_vault,
            stored_unvault_tx,
            &unvault_tx.psbt().inputs[0].partial_sigs,
            &revaultd.secp_ctx,
        );
        let stored_unvault_tx = db_unvault_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        assert_eq!(
            stored_unvault_tx.psbt.assert_unvault().psbt().inputs[0]
                .partial_sigs
                .len(),
            1
        );

        // They can also be queried
        assert_eq!(
            emer_tx,
            db_emer_transaction(&db_path, db_vault.id)
                .unwrap()
                .unwrap()
                .psbt
                .assert_emer()
        );
        assert_eq!(
            cancel_tx,
            db_cancel_transaction(&db_path, db_vault.id)
                .unwrap()
                .unwrap()
                .psbt
                .assert_cancel()
        );
        assert_eq!(
            unemer_tx,
            db_unvault_emer_transaction(&db_path, db_vault.id)
                .unwrap()
                .unwrap()
                .psbt
                .assert_unvault_emer()
        );
        assert_eq!(
            unvault_tx,
            db_unvault_transaction(&db_path, db_vault.id)
                .unwrap()
                .unwrap()
                .psbt
                .assert_unvault()
        );
        let sig_mis_map = db_sig_missing(&db_path).unwrap();
        assert_eq!(sig_mis_map.len(), 1);
        assert_eq!(
            sig_mis_map
                .get(sig_mis_map.keys().next().unwrap())
                .unwrap()
                .len(),
            4
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
        assert!(db_unvault_transaction(&db_path, db_vault.id)
            .unwrap()
            .is_none());
        let db_vault = db_vault_by_deposit(&db_path, &db_vault.deposit_outpoint)
            .unwrap()
            .unwrap();
        assert_eq!(db_vault.status, VaultStatus::Unconfirmed);
        assert!(db_vault.delegated_at.is_none());
        assert!(db_vault.secured_at.is_none());
        assert!(db_vault.funded_at.is_none());

        // And re-added of course
        db_confirm_deposit(
            &db_path,
            &outpoint,
            blockheight,
            blocktime,
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
            blocktime,
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
        let sig_mis_map = db_sig_missing(&db_path).unwrap();
        assert_eq!(sig_mis_map.len(), 1);
        assert_eq!(
            sig_mis_map
                .get(sig_mis_map.keys().next().unwrap())
                .unwrap()
                .len(),
            3
        );
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

        // Sanity check we can mark the Emergency as shared with the watchtowers
        assert!(
            !db_vault_by_deposit(&db_path, &db_vault.deposit_outpoint)
                .unwrap()
                .unwrap()
                .emer_shared
        );
        db_mark_emer_shared(&db_path, &db_vault).unwrap();
        assert!(
            db_vault_by_deposit(&db_path, &db_vault.deposit_outpoint)
                .unwrap()
                .unwrap()
                .emer_shared
        );

        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }

    // There we trigger a concurrent write access to the database by inserting a deposit and
    // updating its presigned transaction in two different thread. It should be fine and one of
    // them just lock thanks to the unlock_notify feature of SQLite https://sqlite.org/unlock_notify.html
    #[test]
    fn test_db_concurrent_write() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);
        let db_path = revaultd.db_file();
        let secp_ctx = secp256k1::Secp256k1::new();

        setup_db(&mut revaultd).unwrap();

        // Let's insert a deposit
        let wallet_id = 1;
        let outpoint = OutPoint::from_str(
            "adaa5a4b9fb07c860f8de460727b6bad4b5ab01d2e7f90f6f3f15a0080020168:0",
        )
        .unwrap();
        let amount = Amount::from_sat(123456);
        let derivation_index = ChildNumber::from(33334);
        db_insert_new_unconfirmed_vault(&db_path, wallet_id, &outpoint, &amount, derivation_index)
            .unwrap();
        let db_vault = db_vault_by_deposit(&db_path, &outpoint).unwrap().unwrap();

        let fresh_cancel_tx = CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAARoHs0elD2sCfWV4+b7PH3aRA+BkRVNf3m/P+Epjx2fNAAAAAAD9////AdLKAgAAAAAAIgAgB6abzQJ4vo5CO9XW3r3JnNumTwlpQbZm9FVICsLHPYQAAAAAAAEBK0ANAwAAAAAAIgAglEs6phQpv+twnAQSdjDvAEic65OtUIijeePBzAAqr50BAwSBAAAAAQWrIQO4lrAuffeRLuEEuwp2hAMZIPmqaHMTUySM3OwdA2hIW6xRh2R2qRTflccImFIy5NdTqwPuPZFB7g1pvYisa3apFOQxXoLeQv/aDFfav/l6YnYRKt+1iKxsk1KHZ1IhA32Q1DEqQ/kUP2MvQYFW46RCexZ5aYk17Arhp01th+37IQNrXQtfIXQdrv+RyyHLilJsb4ujlUMddG9X2jYkeXiWoFKvA3nxALJoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQFHUiED35umh5GhiToV6GS7lTokWfq/Rvy+rRI9XMQuf+foOoEhA9GtXpHhUvxcj9DJWbaRvz59CNsMwH2NEvmRa8gc2WRkUq4iAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap();
        let fresh_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAT7KJ+fkvbKBDobFTsm31LqtMUfhTiR5tWA5XJA9oYgOAAAAAAD9////AkANAwAAAAAAIgAgbMJH4U4sOCdd1R9PVUuEbmS4bkbnNNlJaqxZBqXHwCcwdQAAAAAAACIAIM8vNQyMFHWpzTmNSefLOTf0spivub9JuegPqYdx0rLvAAAAAAABASuIlAMAAAAAACIAIONmt9fso2OE03OxwV4EkzSucRgHSh3ylMy/KcBayrRaAQMEAQAAAAEFR1IhAum/3N5NY9BZnqXIJxEBNzNEhHwCOY4WQ5xdZZ9XN4+dIQNwiQrXHbeULZ18BN3FOfnYK48NrsVzMDAXVEiu7HfvylKuIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQGqIQOxOjPIG6CKHguqGMBsMRvG/RIiZzCbu7GDMDGmmvH6FqxRh2R2qRSrdyIjb58/y1mAP+ccckOFvfAe04isa3apFAexihzQF+l8AqKa+Y/5XVddSavViKxsk1KHZ1IhAwOygpbYC9yckzxzYFmjVTs4cZzaRTJ97nCHwbFZ6PCaIQLBejnrZMZEk984LSigxiITRc96BSWvsT2wJVMCkLKSe1KvAlAFsmgiAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAABASUhA7E6M8gboIoeC6oYwGwxG8b9EiJnMJu7sYMwMaaa8foWrFGHIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap();

        let blockheight = 2300000;
        let blocktime = 2300000;
        db_confirm_deposit(
            &db_path,
            &outpoint,
            blockheight,
            blocktime,
            &fresh_unvault_tx,
            &fresh_cancel_tx,
            None,
            None,
        )
        .unwrap();

        let stored_cancel_tx = db_cancel_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        let mut cancel_tx = fresh_cancel_tx.clone();
        revault_tx_add_sig(
            &mut cancel_tx,
            0,
            SigHashType::AllPlusAnyoneCanPay,
            &secp_ctx,
        );
        let handle = std::thread::spawn({
            let db_path = db_path.clone();
            let cancel_tx = cancel_tx.clone();
            let secp = revaultd.secp_ctx.clone();
            let stored_cancel_tx_b = stored_cancel_tx.clone();
            move || {
                for _ in 0..10 {
                    update_presigned_tx(
                        &db_path,
                        &db_vault,
                        stored_cancel_tx_b.clone(),
                        &cancel_tx.psbt().inputs[0].partial_sigs,
                        &secp,
                    );
                }
            }
        });
        for _ in 0..10 {
            update_presigned_tx(
                &db_path,
                &db_vault,
                stored_cancel_tx.clone(),
                &cancel_tx.psbt().inputs[0].partial_sigs,
                &revaultd.secp_ctx,
            );
        }
        handle.join().unwrap();
        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }

    #[test]
    fn test_db_spend_storage() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);
        let db_path = revaultd.db_file();
        let fresh_cancel_tx = CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAARoHs0elD2sCfWV4+b7PH3aRA+BkRVNf3m/P+Epjx2fNAAAAAAD9////AdLKAgAAAAAAIgAgB6abzQJ4vo5CO9XW3r3JnNumTwlpQbZm9FVICsLHPYQAAAAAAAEBK0ANAwAAAAAAIgAglEs6phQpv+twnAQSdjDvAEic65OtUIijeePBzAAqr50BAwSBAAAAAQWrIQO4lrAuffeRLuEEuwp2hAMZIPmqaHMTUySM3OwdA2hIW6xRh2R2qRTflccImFIy5NdTqwPuPZFB7g1pvYisa3apFOQxXoLeQv/aDFfav/l6YnYRKt+1iKxsk1KHZ1IhA32Q1DEqQ/kUP2MvQYFW46RCexZ5aYk17Arhp01th+37IQNrXQtfIXQdrv+RyyHLilJsb4ujlUMddG9X2jYkeXiWoFKvA3nxALJoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQFHUiED35umh5GhiToV6GS7lTokWfq/Rvy+rRI9XMQuf+foOoEhA9GtXpHhUvxcj9DJWbaRvz59CNsMwH2NEvmRa8gc2WRkUq4iAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap();
        let fresh_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAfF2iPeJqz13zFlW6eLAM+uDu5IhUqcQxtMWQx7z5Y8lAAAAAAD9////AkANAwAAAAAAIgAgKb0SdnuqeHAJpRuZTbk3r81qbXpuHrMEmxT9Kph47HQwdQAAAAAAACIAIIMbpoIz4DI+aB1p/EJLyqjyDdDeZ7gG8kPhRIDiWaY8AAAAAAABASuIlAMAAAAAACIAIA9CgZ1cg/hn3iy3buDZvU5zUnQ9NzutToR/r42YZyu3AQMEAQAAAAEFR1IhA9P6hV8yf6HkNofzleom06eqkUxZayWHJnOMNlMtqvD3IQJo5Mj6Wf3ktrwEB3IQXFmgApibojplpNykg0hA8XV6SFKuIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQGqIQMfu47eLiYeHN6Y3C1Vk0ckgmWifMy5IUhaPHbNELV93axRh2R2qRTtiGxBD5KrMQQU6UGx2zsKMMf6nIisa3apFCDKte9IuDeF0D4GA/JRUNX4xgt+iKxsk1KHZ1IhAzTPPnjrvzPFmi+raNR6sY8WTt1KNusVwp82uWebzWDwIQKl21mZX7WAQhRvdhhwqUAuQfIemg9zkTCCyMQ+Q8CVFVKvAqUBsmgiAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAABASUhAx+7jt4uJh4c3pjcLVWTRySCZaJ8zLkhSFo8ds0QtX3drFGHIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap();
        let fullysigned_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAfF2iPeJqz13zFlW6eLAM+uDu5IhUqcQxtMWQx7z5Y8lAAAAAAD9////AkANAwAAAAAAIgAgKb0SdnuqeHAJpRuZTbk3r81qbXpuHrMEmxT9Kph47HQwdQAAAAAAACIAIIMbpoIz4DI+aB1p/EJLyqjyDdDeZ7gG8kPhRIDiWaY8AAAAAAABASuIlAMAAAAAACIAIA9CgZ1cg/hn3iy3buDZvU5zUnQ9NzutToR/r42YZyu3IgICaOTI+ln95La8BAdyEFxZoAKYm6I6ZaTcpINIQPF1ekhHMEQCIGwH+/OfgUAbJwthOxnMAR4zoLf/ispCH50wqin3TERrAiBak0Xw5+dQ3Od68PWZ65UPLQXG070wCX9pfcInGVUiagEiAgPT+oVfMn+h5DaH85XqJtOnqpFMWWslhyZzjDZTLarw90cwRAIgA/69zvbYYHbKpBId51MVBeS0xIMF/DZJJ+9/UytAh/0CIBG6NR6AulGTLlMGP6bYMqMQ9HRKlAVFSvEK8dVQ2FdeAQEDBAEAAAABBUdSIQPT+oVfMn+h5DaH85XqJtOnqpFMWWslhyZzjDZTLarw9yECaOTI+ln95La8BAdyEFxZoAKYm6I6ZaTcpINIQPF1ekhSriIGAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBqiEDH7uO3i4mHhzemNwtVZNHJIJlonzMuSFIWjx2zRC1fd2sUYdkdqkU7YhsQQ+SqzEEFOlBsds7CjDH+pyIrGt2qRQgyrXvSLg3hdA+BgPyUVDV+MYLfoisbJNSh2dSIQM0zz54678zxZovq2jUerGPFk7dSjbrFcKfNrlnm81g8CECpdtZmV+1gEIUb3YYcKlALkHyHpoPc5EwgsjEPkPAlRVSrwKlAbJoIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQElIQMfu47eLiYeHN6Y3C1Vk0ckgmWifMy5IUhaPHbNELV93axRhyICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAA==").unwrap();

        setup_db(&mut revaultd).unwrap();

        // Let's insert a deposit
        let wallet_id = 1;
        let outpoint = OutPoint::from_str(
            "c9cf38058b720050bcba47490ee27f4a29d57a5aa2ee0f3c97731e140dbeced7:1",
        )
        .unwrap();
        let amount = Amount::from_sat(612345);
        let derivation_index = ChildNumber::from(349874);
        db_insert_new_unconfirmed_vault(&db_path, wallet_id, &outpoint, &amount, derivation_index)
            .unwrap();
        let db_vault = db_vault_by_deposit(&db_path, &outpoint).unwrap().unwrap();

        // Have the Unvault tx fully signed
        db_confirm_deposit(
            &db_path,
            &outpoint,
            9,
            9,
            &fresh_unvault_tx,
            &fresh_cancel_tx,
            None,
            None,
        )
        .unwrap();
        let stored_unvault_tx = db_unvault_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        update_presigned_tx(
            &db_path,
            &db_vault,
            stored_unvault_tx,
            &fullysigned_unvault_tx.psbt().inputs[0].partial_sigs,
            &revaultd.secp_ctx,
        );
        db_mark_vault_as(&db_path, db_vault.id, VaultStatus::Active).unwrap();

        // We can store a Spend tx spending a single unvault and query it
        let spend_tx = SpendTransaction::from_psbt_str("cHNidP8BAGcCAAAAAciTbKS43sH49TJWX6xJ+MxqWfNQhRl+vkttRZ9sLUkHAAAAAAClAQAAAoAyAAAAAAAAIgAggxumgjPgMj5oHWn8QkvKqPIN0N5nuAbyQ+FEgOJZpjygjAIAAAAAAAAAAAAAAAEBK0ANAwAAAAAAIgAgKb0SdnuqeHAJpRuZTbk3r81qbXpuHrMEmxT9Kph47HQBAwQBAAAAAQWqIQMfu47eLiYeHN6Y3C1Vk0ckgmWifMy5IUhaPHbNELV93axRh2R2qRTtiGxBD5KrMQQU6UGx2zsKMMf6nIisa3apFCDKte9IuDeF0D4GA/JRUNX4xgt+iKxsk1KHZ1IhAzTPPnjrvzPFmi+raNR6sY8WTt1KNusVwp82uWebzWDwIQKl21mZX7WAQhRvdhhwqUAuQfIemg9zkTCCyMQ+Q8CVFVKvAqUBsmgiBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAABASUhAx+7jt4uJh4c3pjcLVWTRySCZaJ8zLkhSFo8ds0QtX3drFGHIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap();
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
                    broadcasted: None,
                    has_priority: false,
                },
                vec![outpoint]
            ))
        );

        // We can update it, eg with a Spend with more sigs
        let spend_tx = SpendTransaction::from_psbt_str("cHNidP8BAGcCAAAAAciTbKS43sH49TJWX6xJ+MxqWfNQhRl+vkttRZ9sLUkHAAAAAAClAQAAAoAyAAAAAAAAIgAggxumgjPgMj5oHWn8QkvKqPIN0N5nuAbyQ+FEgOJZpjygjAIAAAAAAAAAAAAAAAEBK0ANAwAAAAAAIgAgKb0SdnuqeHAJpRuZTbk3r81qbXpuHrMEmxT9Kph47HQBAwQBAAAAAQWqIQMfu47eLiYeHN6Y3C1Vk0ckgmWifMy5IUhaPHbNELV93axRh2R2qRTtiGxBD5KrMQQU6UGx2zsKMMf6nIisa3apFCDKte9IuDeF0D4GA/JRUNX4xgt+iKxsk1KHZ1IhAzTPPnjrvzPFmi+raNR6sY8WTt1KNusVwp82uWebzWDwIQKl21mZX7WAQhRvdhhwqUAuQfIemg9zkTCCyMQ+Q8CVFVKvAqUBsmgiBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAABASUhAx+7jt4uJh4c3pjcLVWTRySCZaJ8zLkhSFo8ds0QtX3drFGHIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap();
        db_update_spend(&db_path, &spend_tx, true).unwrap();
        let spend_txid = spend_tx.txid();
        assert_eq!(
            db_list_spends(&db_path).unwrap().get(&spend_txid),
            Some(&(
                DbSpendTransaction {
                    id: 1,
                    psbt: spend_tx.clone(),
                    broadcasted: None,
                    has_priority: true,
                },
                vec![outpoint]
            ))
        );
        // Not in the CPFPable as it's not broadcasted
        assert!(!db_cpfpable_spends(&db_path).unwrap().contains(&spend_tx));

        // And delete it
        db_delete_spend(&db_path, &spend_tx.txid()).unwrap();
        assert!(db_list_spends(&db_path).unwrap().get(&spend_txid).is_none());

        // And this works with multiple unvaults too

        // Re-insert the previous one so we have many references to the first Unvault
        db_insert_spend(&db_path, &[db_unvault.clone()], &spend_tx).unwrap();
        db_update_spend(&db_path, &spend_tx, true).unwrap();

        // Same as above with a new vault
        let cancel_tx = CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAAc+BIbsSvYK/BWRNOAjazIlLfjlVzCCtXvoyN5/bydgEAAAAAAD9////AdLKAgAAAAAAIgAgFy2HNuxbT516bQQBY3R04IkEja348wJveLmF73Tj/owAAAAAAAEBK0ANAwAAAAAAIgAgZw+cwq8wJzworIDuy6s8cpOo3uF8fYyL5pECqg0UVagBAwSBAAAAAQWrIQLDtCYN0BlQw/h5zAcF0yXft2G7vAjkRsD9B9uoiyr1x6xRh2R2qRTGFACwvLOTrJHUPKb3ifnio7mt0Yisa3apFOZTIiKdGP+9rilwd09H1kOsfB/PiKxsk1KHZ1IhAtGKwcs21FeGy2qY+fzQ9uvI4X5ThtCqkwHsGtKQx0jYIQP93zm1sGAtxTNxsYQTkoXt26FoyKWNh1sx6hmk1yVzYlKvA8aOALJoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQFHUiEDwco8fBTB0TgIyRuiySVtsjqY8/PNWc6ibssXFBu8J9ghAnfnwLjDsJCtzPdRRymjx6qxGfklMzRjSB7kXPcIClLuUq4iAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap();
        let fresh_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAe7jtZYQ3avFhc+JxU4paq8e26NIkAB1zHLgv6mKWxgBAAAAAAD9////AkANAwAAAAAAIgAgdS3fC7QX+PKWZBful8J229uixPOW012CYpKMH7rU8T4wdQAAAAAAACIAIAGCzzZ7K80GkoO2mUdCVIFx7Tum52UXob8ascs1uZucAAAAAAABASuIlAMAAAAAACIAIFvpTQQruW8AB+k+csGMaThNLBAzppkxo+k4Hb2SZ4hKAQMEAQAAAAEFR1IhAvkWJfB/ssW9YaE7llH/y/1FBJ/LK+ybOJiT8j+O4cnhIQIS4abTQKWATfsTrVsEPfkCUHvxY4M0F+ZDz502NXMy1FKuIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQGqIQLbrZUUxHTNBLySX7XjBBa5auxTfjuUSHxE3vJ1JXfdlaxRh2R2qRS8iuykW8lDZdRWXgK4UY0gLAkjX4isa3apFJ+lQ0Ybj4Eig7391TEtxikgP4DDiKxsk1KHZ1IhAqTEmYMxdjLU50wj/Hw9X2Pf7WRDSCnO4P4qpJ5h+PNOIQO2p8sldVsHhhEimy+ZW0E1L3vX5d9mqQ0d01XVdx3DWVKvAocbsmgiAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAABASUhAtutlRTEdM0EvJJfteMEFrlq7FN+O5RIfETe8nUld92VrFGHIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap();
        let fullysigned_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAe7jtZYQ3avFhc+JxU4paq8e26NIkAB1zHLgv6mKWxgBAAAAAAD9////AkANAwAAAAAAIgAgdS3fC7QX+PKWZBful8J229uixPOW012CYpKMH7rU8T4wdQAAAAAAACIAIAGCzzZ7K80GkoO2mUdCVIFx7Tum52UXob8ascs1uZucAAAAAAABASuIlAMAAAAAACIAIFvpTQQruW8AB+k+csGMaThNLBAzppkxo+k4Hb2SZ4hKIgICEuGm00ClgE37E61bBD35AlB78WODNBfmQ8+dNjVzMtRHMEQCID2my9yVWxgLSDKDBL5PmF9FVZC6b8mLu598Rq8oebjQAiB3FC3br7rS6bkKOKa4h9Ml1nicuPWpXTWjAWrALVTd+gEiAgL5FiXwf7LFvWGhO5ZR/8v9RQSfyyvsmziYk/I/juHJ4UcwRAIgGfJBreyXt5Isv9PjLRJCFy5jVrMGieGsvV01LTPf3/gCICS81/Mvot0WYdlXC+FnAQ4AprXIQH+g1pnDomBGO+UZAQEDBAEAAAABBUdSIQL5FiXwf7LFvWGhO5ZR/8v9RQSfyyvsmziYk/I/juHJ4SECEuGm00ClgE37E61bBD35AlB78WODNBfmQ8+dNjVzMtRSriIGAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBqiEC262VFMR0zQS8kl+14wQWuWrsU347lEh8RN7ydSV33ZWsUYdkdqkUvIrspFvJQ2XUVl4CuFGNICwJI1+IrGt2qRSfpUNGG4+BIoO9/dUxLcYpID+Aw4isbJNSh2dSIQKkxJmDMXYy1OdMI/x8PV9j3+1kQ0gpzuD+KqSeYfjzTiEDtqfLJXVbB4YRIpsvmVtBNS971+XfZqkNHdNV1Xcdw1lSrwKHG7JoIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQElIQLbrZUUxHTNBLySX7XjBBa5auxTfjuUSHxE3vJ1JXfdlaxRhyICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAA==").unwrap();
        let wallet_id = 1;
        let outpoint_b = OutPoint::from_str(
            "2117d7c3461ca013a099d8e60b0bcc6c33aec95db49f636c479ab85117479a91:0",
        )
        .unwrap();
        let amount = Amount::from_sat(112245);
        let derivation_index = ChildNumber::from(643874);
        db_insert_new_unconfirmed_vault(
            &db_path,
            wallet_id,
            &outpoint_b,
            &amount,
            derivation_index,
        )
        .unwrap();
        let db_vault = db_vault_by_deposit(&db_path, &outpoint_b).unwrap().unwrap();
        db_confirm_deposit(
            &db_path,
            &outpoint_b,
            9,
            9,
            &fresh_unvault_tx,
            &cancel_tx,
            None,
            None,
        )
        .unwrap();
        let stored_unvault_tx = db_unvault_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        update_presigned_tx(
            &db_path,
            &db_vault,
            stored_unvault_tx,
            &fullysigned_unvault_tx.psbt().inputs[0].partial_sigs,
            &revaultd.secp_ctx,
        );
        db_mark_vault_as(&db_path, db_vault.id, VaultStatus::Active).unwrap();

        let spend_tx_b = SpendTransaction::from_psbt_str("cHNidP8BAGcCAAAAAXHqOcTAJnPyXEF1cxFATe4S6yHLGZm+s0aj9mUTtKgVAAAAAACHGwAAAoAyAAAAAAAAIgAgAYLPNnsrzQaSg7aZR0JUgXHtO6bnZRehvxqxyzW5m5ygjAIAAAAAAAAAAAAAAAEBK0ANAwAAAAAAIgAgdS3fC7QX+PKWZBful8J229uixPOW012CYpKMH7rU8T4BAwQBAAAAAQWqIQLbrZUUxHTNBLySX7XjBBa5auxTfjuUSHxE3vJ1JXfdlaxRh2R2qRS8iuykW8lDZdRWXgK4UY0gLAkjX4isa3apFJ+lQ0Ybj4Eig7391TEtxikgP4DDiKxsk1KHZ1IhAqTEmYMxdjLU50wj/Hw9X2Pf7WRDSCnO4P4qpJ5h+PNOIQO2p8sldVsHhhEimy+ZW0E1L3vX5d9mqQ0d01XVdx3DWVKvAocbsmgiBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAABASUhAtutlRTEdM0EvJJfteMEFrlq7FN+O5RIfETe8nUld92VrFGHIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap();
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
                    broadcasted: None,
                    has_priority: true,
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
                    broadcasted: None,
                    has_priority: false,
                },
                vec![outpoint, outpoint_b]
            ))
        );

        let spend_tx_b = SpendTransaction::from_psbt_str("cHNidP8BAGcCAAAAAXHqOcTAJnPyXEF1cxFATe4S6yHLGZm+s0aj9mUTtKgVAAAAAACHGwAAAoAyAAAAAAAAIgAgAYLPNnsrzQaSg7aZR0JUgXHtO6bnZRehvxqxyzW5m5ygjAIAAAAAAAAAAAAAAAEBK0ANAwAAAAAAIgAgdS3fC7QX+PKWZBful8J229uixPOW012CYpKMH7rU8T4iAgKkxJmDMXYy1OdMI/x8PV9j3+1kQ0gpzuD+KqSeYfjzTkgwRQIhAMwdbbLXqH49pRfZR6PtSzNg/MB+DuVo1xs7rPTZQ12RAiBDSHEGyQaE1K+wknL2IFnhWXKn+/YSfSMtMg9u4zepNwEiAgLbrZUUxHTNBLySX7XjBBa5auxTfjuUSHxE3vJ1JXfdlUgwRQIhAM0sVhdfZtv9Uofdo2oSfwOqTL5gmveVElUl8zxDgZ9wAiB82EHY4wySIWec9cZHbmhLY72LSwyGrqDANNMTun6JNwEiAgO2p8sldVsHhhEimy+ZW0E1L3vX5d9mqQ0d01XVdx3DWUcwRAIgRhhHxuXx5X2eniy4tMP4wP2xoBD+XZlxMQiF9HoXIDYCIEfKdXOOILXSFKeOZ2v6nomllEQOyjuBUk+0LhK7+55mAQEDBAEAAAABBaohAtutlRTEdM0EvJJfteMEFrlq7FN+O5RIfETe8nUld92VrFGHZHapFLyK7KRbyUNl1FZeArhRjSAsCSNfiKxrdqkUn6VDRhuPgSKDvf3VMS3GKSA/gMOIrGyTUodnUiECpMSZgzF2MtTnTCP8fD1fY9/tZENIKc7g/iqknmH4804hA7anyyV1WweGESKbL5lbQTUve9fl32apDR3TVdV3HcNZUq8ChxuyaCIGAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBJSEC262VFMR0zQS8kl+14wQWuWrsU347lEh8RN7ydSV33ZWsUYciAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAAiAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap();
        db_update_spend(&db_path, &spend_tx_b, false).unwrap();

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
        // Since the spend is broadcastable, its unvaults are cpfpable
        assert_eq!(db_cpfpable_spends(&db_path).unwrap().len(), 0);
        assert_eq!(db_cpfpable_unvaults(&db_path).unwrap().len(), 1);
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
        // Now the spend is cpfpable as it's broadcasted
        assert_eq!(db_cpfpable_spends(&db_path).unwrap().len(), 1);
        assert_eq!(db_cpfpable_unvaults(&db_path).unwrap().len(), 0);

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

    #[test]
    fn test_db_update_vault_status() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);
        let db_path = revaultd.db_file();

        setup_db(&mut revaultd).unwrap();

        let fresh_cancel_tx = CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAAfihVFC0qjTyRXe/NFNqD5H41QqyRbKs6hABmmmmPYFcAAAAAAD9////ARQJVQEAAAAAIgAgkElks+0BcARwPPXA93nn7gE03Jm7+3obqqKLM5wa7OsAAAAAAAEBK7hEVQEAAAAAIgAgbsu/Z4HxJp0NLrRFQTCKGQckU0lArG3qqpSIVinrf8UBAwSBAAAAAQVhIQPAKvZof/JMq6C/mAv3iRqN76eVO6RzNYLzz9XqXigOjqxRh2R2qRTSH6G2Ru92gsQ8Zo4dNgTsvMy2L4isa3apFLP0U8urvhbV0H973pOSBuRg+k7xiKxsk1KHZ1iyaCIGA7gRH0o4M9yQoqitp18e5GAOLRMFjGIarmzri8HelKrGCNZ9f+kBAAAAIgYDvlsnkvqDNc+mSaKuVISQGu8YaPxvbflKJN3ee4NJh2AIcqlfIgEAAAAiBgPAKvZof/JMq6C/mAv3iRqN76eVO6RzNYLzz9XqXigOjgglHWAJAQAAAAAiAgO4ER9KODPckKKoradfHuRgDi0TBYxiGq5s64vB3pSqxgjWfX/pAQAAACICA75bJ5L6gzXPpkmirlSEkBrvGGj8b235SiTd3nuDSYdgCHKpXyIBAAAAAA==").unwrap();
        let fresh_emergency_tx = EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAXsLEnDEk/kajuPbB1tQ4i6kfExo7HA6I3xHgmJWRSLaAAAAAAD9////ATgcVQEAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBKwDMVQEAAAAAIgAgkElks+0BcARwPPXA93nn7gE03Jm7+3obqqKLM5wa7OsBAwSBAAAAAQVHUiEDuBEfSjgz3JCiqK2nXx7kYA4tEwWMYhqubOuLwd6UqsYhA75bJ5L6gzXPpkmirlSEkBrvGGj8b235SiTd3nuDSYdgUq4iBgO4ER9KODPckKKoradfHuRgDi0TBYxiGq5s64vB3pSqxgjWfX/pAQAAACIGA75bJ5L6gzXPpkmirlSEkBrvGGj8b235SiTd3nuDSYdgCHKpXyIBAAAAAAA=").unwrap();
        let fresh_unvaultemergency_tx = UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAfihVFC0qjTyRXe/NFNqD5H41QqyRbKs6hABmmmmPYFcAAAAAAD9////AWZ5VAEAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK7hEVQEAAAAAIgAgbsu/Z4HxJp0NLrRFQTCKGQckU0lArG3qqpSIVinrf8UBAwSBAAAAAQVhIQPAKvZof/JMq6C/mAv3iRqN76eVO6RzNYLzz9XqXigOjqxRh2R2qRTSH6G2Ru92gsQ8Zo4dNgTsvMy2L4isa3apFLP0U8urvhbV0H973pOSBuRg+k7xiKxsk1KHZ1iyaCIGA7gRH0o4M9yQoqitp18e5GAOLRMFjGIarmzri8HelKrGCNZ9f+kBAAAAIgYDvlsnkvqDNc+mSaKuVISQGu8YaPxvbflKJN3ee4NJh2AIcqlfIgEAAAAiBgPAKvZof/JMq6C/mAv3iRqN76eVO6RzNYLzz9XqXigOjgglHWAJAQAAAAAA").unwrap();
        let fresh_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAXsLEnDEk/kajuPbB1tQ4i6kfExo7HA6I3xHgmJWRSLaAAAAAAD9////ArhEVQEAAAAAIgAgbsu/Z4HxJp0NLrRFQTCKGQckU0lArG3qqpSIVinrf8UwdQAAAAAAACIAILzK9vum6/lhgKe5jxw305+0hoD0nTIyaO2YhNSGPZYbAAAAAAABASsAzFUBAAAAACIAIJBJZLPtAXAEcDz1wPd55+4BNNyZu/t6G6qiizOcGuzrAQMEAQAAAAEFR1IhA7gRH0o4M9yQoqitp18e5GAOLRMFjGIarmzri8HelKrGIQO+WyeS+oM1z6ZJoq5UhJAa7xho/G9t+Uok3d57g0mHYFKuIgYDuBEfSjgz3JCiqK2nXx7kYA4tEwWMYhqubOuLwd6UqsYI1n1/6QEAAAAiBgO+WyeS+oM1z6ZJoq5UhJAa7xho/G9t+Uok3d57g0mHYAhyqV8iAQAAAAAiAgO4ER9KODPckKKoradfHuRgDi0TBYxiGq5s64vB3pSqxgjWfX/pAQAAACICA75bJ5L6gzXPpkmirlSEkBrvGGj8b235SiTd3nuDSYdgCHKpXyIBAAAAIgIDwCr2aH/yTKugv5gL94kaje+nlTukczWC88/V6l4oDo4IJR1gCQEAAAAAIgICpNYvWPZyxsUYf7xyXokNYDytbr1bx10GK6jRxJ19+r4I+93szQEAAAAA").unwrap();

        let fullysigned_cancel_tx = CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAAfihVFC0qjTyRXe/NFNqD5H41QqyRbKs6hABmmmmPYFcAAAAAAD9////ARQJVQEAAAAAIgAgkElks+0BcARwPPXA93nn7gE03Jm7+3obqqKLM5wa7OsAAAAAAAEBK7hEVQEAAAAAIgAgbsu/Z4HxJp0NLrRFQTCKGQckU0lArG3qqpSIVinrf8UiAgO4ER9KODPckKKoradfHuRgDi0TBYxiGq5s64vB3pSqxkcwRAIgB/3p+T4lseNEnwmN7iohmyMUiIUsDDnGU58iftbc6lcCIDTeEOYzwqyCkU65rRqQ45q6DHsL/M8SxvTS87vaaMQhgSICA75bJ5L6gzXPpkmirlSEkBrvGGj8b235SiTd3nuDSYdgSDBFAiEA039gXXzN9fjgENN6EOP8LE9HwDxHcJSVRpCCw5DJUKoCIDdwWFSHtJR/3gnubCtUNPF2dJzinCsVFjW2MfQfjYDGgQEDBIEAAAABBWEhA8Aq9mh/8kyroL+YC/eJGo3vp5U7pHM1gvPP1epeKA6OrFGHZHapFNIfobZG73aCxDxmjh02BOy8zLYviKxrdqkUs/RTy6u+FtXQf3vek5IG5GD6TvGIrGyTUodnWLJoIgYDuBEfSjgz3JCiqK2nXx7kYA4tEwWMYhqubOuLwd6UqsYI1n1/6QEAAAAiBgO+WyeS+oM1z6ZJoq5UhJAa7xho/G9t+Uok3d57g0mHYAhyqV8iAQAAACIGA8Aq9mh/8kyroL+YC/eJGo3vp5U7pHM1gvPP1epeKA6OCCUdYAkBAAAAACICA7gRH0o4M9yQoqitp18e5GAOLRMFjGIarmzri8HelKrGCNZ9f+kBAAAAIgIDvlsnkvqDNc+mSaKuVISQGu8YaPxvbflKJN3ee4NJh2AIcqlfIgEAAAAA").unwrap();
        let fullysigned_emergency_tx = EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAXsLEnDEk/kajuPbB1tQ4i6kfExo7HA6I3xHgmJWRSLaAAAAAAD9////ATgcVQEAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBKwDMVQEAAAAAIgAgkElks+0BcARwPPXA93nn7gE03Jm7+3obqqKLM5wa7OsiAgO4ER9KODPckKKoradfHuRgDi0TBYxiGq5s64vB3pSqxkcwRAIgKDAJyH5ixlG6HgsUtvWgYbpRv6vuthbwjaIc6nxa220CIDfUJJe5RgnmPgWXnQdjiMp/nLNETh1fbi2KV3u6YxRbgSICA75bJ5L6gzXPpkmirlSEkBrvGGj8b235SiTd3nuDSYdgSDBFAiEAyFE0qIblxbDV3ocAUcbrLEvIMXi/c5H2Z+PbkGA43xUCIDagAFsbwHijNkp7QFMkr2M7YVhXODcJ0JO6mzznRcWegQEDBIEAAAABBUdSIQO4ER9KODPckKKoradfHuRgDi0TBYxiGq5s64vB3pSqxiEDvlsnkvqDNc+mSaKuVISQGu8YaPxvbflKJN3ee4NJh2BSriIGA7gRH0o4M9yQoqitp18e5GAOLRMFjGIarmzri8HelKrGCNZ9f+kBAAAAIgYDvlsnkvqDNc+mSaKuVISQGu8YaPxvbflKJN3ee4NJh2AIcqlfIgEAAAAAAA==").unwrap();
        let fullysigned_unvaultemergency_tx = UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAfihVFC0qjTyRXe/NFNqD5H41QqyRbKs6hABmmmmPYFcAAAAAAD9////AWZ5VAEAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK7hEVQEAAAAAIgAgbsu/Z4HxJp0NLrRFQTCKGQckU0lArG3qqpSIVinrf8UiAgO4ER9KODPckKKoradfHuRgDi0TBYxiGq5s64vB3pSqxkgwRQIhAKpNCciNFBhFAnGRgOwnSQWmXXd+MGECPxqPyDU795EzAiBkLV2iCdA5S0ggYIYiANaXsRrZCxHRiRdBGQaDgWyviYEiAgO+WyeS+oM1z6ZJoq5UhJAa7xho/G9t+Uok3d57g0mHYEcwRAIgYvx1ukm7/2LGEgUb2JrZouzbNi9Otlqdf9FhKbDaZiICIDtx72rpajYo/xtLQGXUrFmoogOOasxEZztmNZ0x0Gk3gQEDBIEAAAABBWEhA8Aq9mh/8kyroL+YC/eJGo3vp5U7pHM1gvPP1epeKA6OrFGHZHapFNIfobZG73aCxDxmjh02BOy8zLYviKxrdqkUs/RTy6u+FtXQf3vek5IG5GD6TvGIrGyTUodnWLJoIgYDuBEfSjgz3JCiqK2nXx7kYA4tEwWMYhqubOuLwd6UqsYI1n1/6QEAAAAiBgO+WyeS+oM1z6ZJoq5UhJAa7xho/G9t+Uok3d57g0mHYAhyqV8iAQAAACIGA8Aq9mh/8kyroL+YC/eJGo3vp5U7pHM1gvPP1epeKA6OCCUdYAkBAAAAAAA=").unwrap();
        let fullysigned_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAXsLEnDEk/kajuPbB1tQ4i6kfExo7HA6I3xHgmJWRSLaAAAAAAD9////ArhEVQEAAAAAIgAgbsu/Z4HxJp0NLrRFQTCKGQckU0lArG3qqpSIVinrf8UwdQAAAAAAACIAILzK9vum6/lhgKe5jxw305+0hoD0nTIyaO2YhNSGPZYbAAAAAAABASsAzFUBAAAAACIAIJBJZLPtAXAEcDz1wPd55+4BNNyZu/t6G6qiizOcGuzrIgIDuBEfSjgz3JCiqK2nXx7kYA4tEwWMYhqubOuLwd6UqsZHMEQCICc3av7U4xVy0x35E2BdzIDjR1+F/0NVdCwnkcmNGgNCAiB5pHElbUup/2JRAopn/gQuLGt+uCHhFQy01IOrsje3ZwEiAgO+WyeS+oM1z6ZJoq5UhJAa7xho/G9t+Uok3d57g0mHYEcwRAIgBj4yp1mne9ibY3k6pdpIrdbdAG+MZuOuBdV9Nanzl7cCIFtfEBSqRcruzwGPK0KniC7buW4ow9o6+ELAeH83ZuQDAQEDBAEAAAABBUdSIQO4ER9KODPckKKoradfHuRgDi0TBYxiGq5s64vB3pSqxiEDvlsnkvqDNc+mSaKuVISQGu8YaPxvbflKJN3ee4NJh2BSriIGA7gRH0o4M9yQoqitp18e5GAOLRMFjGIarmzri8HelKrGCNZ9f+kBAAAAIgYDvlsnkvqDNc+mSaKuVISQGu8YaPxvbflKJN3ee4NJh2AIcqlfIgEAAAAAIgIDuBEfSjgz3JCiqK2nXx7kYA4tEwWMYhqubOuLwd6UqsYI1n1/6QEAAAAiAgO+WyeS+oM1z6ZJoq5UhJAa7xho/G9t+Uok3d57g0mHYAhyqV8iAQAAACICA8Aq9mh/8kyroL+YC/eJGo3vp5U7pHM1gvPP1epeKA6OCCUdYAkBAAAAACICAqTWL1j2csbFGH+8cl6JDWA8rW69W8ddBiuo0cSdffq+CPvd7M0BAAAAAA==").unwrap();

        let wallet_id = 1;
        let outpoint_b = OutPoint::from_str(
            "da2245566282477c233a70ec684c7ca42ee2505b07dbe38e1af993c470120b7b:0",
        )
        .unwrap();
        let amount = Amount::from_sat(22400000);
        let derivation_index = ChildNumber::from(1);
        db_insert_new_unconfirmed_vault(
            &db_path,
            wallet_id,
            &outpoint_b,
            &amount,
            derivation_index,
        )
        .unwrap();
        let db_vault = db_vault_by_deposit(&db_path, &outpoint_b).unwrap().unwrap();
        db_confirm_deposit(
            &db_path,
            &outpoint_b,
            9,
            9,
            &fresh_unvault_tx,
            &fresh_cancel_tx,
            Some(&fresh_emergency_tx),
            Some(&fresh_unvaultemergency_tx),
        )
        .unwrap();

        let stored_cancel_tx = db_cancel_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        update_presigned_tx(
            &db_path,
            &db_vault,
            stored_cancel_tx,
            &fullysigned_cancel_tx.psbt().inputs[0].partial_sigs,
            &revaultd.secp_ctx,
        );

        let stored_emergency_tx = db_emer_transaction(&db_path, db_vault.id).unwrap().unwrap();
        update_presigned_tx(
            &db_path,
            &db_vault,
            stored_emergency_tx,
            &fullysigned_emergency_tx.psbt().inputs[0].partial_sigs,
            &revaultd.secp_ctx,
        );

        let stored_unvaultemergency_tx = db_unvault_emer_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        update_presigned_tx(
            &db_path,
            &db_vault,
            stored_unvaultemergency_tx,
            &fullysigned_unvaultemergency_tx.psbt().inputs[0].partial_sigs,
            &revaultd.secp_ctx,
        );

        db_update_vault_status(&db_path, &db_vault).unwrap();
        let db_vault = db_vault_by_deposit(&db_path, &db_vault.deposit_outpoint)
            .unwrap()
            .unwrap();
        assert_eq!(db_vault.status, VaultStatus::Secured);
        assert!(db_vault.funded_at.is_some());
        assert!(db_vault.secured_at.is_some());
        assert!(db_vault.delegated_at.is_none());

        let stored_unvault_tx = db_unvault_transaction(&db_path, db_vault.id)
            .unwrap()
            .unwrap();
        update_presigned_tx(
            &db_path,
            &db_vault,
            stored_unvault_tx,
            &fullysigned_unvault_tx.psbt().inputs[0].partial_sigs,
            &revaultd.secp_ctx,
        );
        db_update_vault_status(&db_path, &db_vault).unwrap();
        let db_vault = db_vault_by_deposit(&db_path, &db_vault.deposit_outpoint)
            .unwrap()
            .unwrap();
        assert_eq!(db_vault.status, VaultStatus::Active);
        assert!(db_vault.funded_at.is_some());
        assert!(db_vault.secured_at.is_some());
        assert!(db_vault.delegated_at.is_some());

        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }
}
