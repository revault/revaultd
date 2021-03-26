use crate::{
    assert_tx_type,
    database::{
        schema::{DbTransaction, DbVault, DbWallet, RevaultTx, TransactionType},
        DatabaseError,
    },
    revaultd::{BlockchainTip, VaultStatus},
};
use revault_tx::{
    bitcoin::{
        consensus::encode,
        util::bip32::{ChildNumber, ExtendedPubKey},
        Amount, BlockHash, Network, OutPoint, Txid,
    },
    transactions::{
        CancelTransaction, EmergencyTransaction, RevaultTransaction, UnvaultEmergencyTransaction,
        UnvaultTransaction,
    },
};

use std::{
    boxed::Box,
    convert::{TryFrom, TryInto},
    path::PathBuf,
    str::FromStr,
};

use rusqlite::{
    params, types::FromSqlError, Connection, Row, ToSql, Transaction, TransactionBehavior,
    NO_PARAMS,
};

// As the bundled sqlite is compiled with SQLITE_THREADSAFE, quoting sqlite.org:
// > Multi-thread. In this mode, SQLite can be safely used by multiple threads provided that
// > no single database connection is used simultaneously in two or more threads.
// Therefore the below routines for now create a new connection and can be used from any thread.
// For concurrent write accesses, we rely on the 'unlock_notify' feature of SQLite: https://sqlite.org/unlock_notify.html

/// Perform a set of modifications to the database inside a single transaction
pub fn db_exec<F>(path: &PathBuf, modifications: F) -> Result<(), DatabaseError>
where
    F: FnOnce(&Transaction) -> Result<(), DatabaseError>,
{
    let mut conn = Connection::open(path)
        .map_err(|e| DatabaseError(format!("Opening database: {}", e.to_string())))?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| DatabaseError(format!("Creating transaction: {}", e.to_string())))?;

    modifications(&tx)?;
    tx.commit()
        .map_err(|e| DatabaseError(format!("Comitting transaction: {}", e.to_string())))?;

    Ok(())
}

// Internal helper for queries boilerplate
fn db_query<'a, P, F, T>(
    path: &PathBuf,
    stmt_str: &'a str,
    params: P,
    f: F,
) -> Result<Vec<T>, DatabaseError>
where
    P: IntoIterator,
    P::Item: ToSql,
    F: FnMut(&Row<'_>) -> rusqlite::Result<T>,
{
    let conn = Connection::open(path)
        .map_err(|e| DatabaseError(format!("Opening database for query: {}", e.to_string())))?;

    // rustc says 'borrowed value does not live long enough'
    let x = conn
        .prepare(stmt_str)
        .map_err(|e| DatabaseError(format!("Preparing query: '{}'", e.to_string())))?
        .query_map(params, f)
        .map_err(|e| DatabaseError(format!("Mapping query: '{}'", e.to_string())))?
        .collect::<rusqlite::Result<Vec<T>>>()
        .map_err(|e| DatabaseError(format!("Executing query: '{}'", e.to_string())));

    x
}

/// Get the database version
pub fn db_version(db_path: &PathBuf) -> Result<u32, DatabaseError> {
    let mut rows = db_query(db_path, "SELECT version FROM version", NO_PARAMS, |row| {
        row.get::<_, u32>(0)
    })?;

    rows.pop()
        .ok_or_else(|| DatabaseError("No row in version table?".to_string()))
}

/// Get our tip from the database
pub fn db_tip(db_path: &PathBuf) -> Result<BlockchainTip, DatabaseError> {
    let mut rows = db_query(
        db_path,
        "SELECT blockheight, blockhash FROM tip",
        NO_PARAMS,
        |row| {
            let height = row.get::<_, u32>(0)?;
            let hash: BlockHash = encode::deserialize(&row.get::<_, Vec<u8>>(1)?)
                .map_err(|e| FromSqlError::Other(Box::new(e)))?;

            Ok(BlockchainTip { height, hash })
        },
    )?;

    rows.pop()
        .ok_or_else(|| DatabaseError("No row in tip table?".to_string()))
}

/// Get the network this DB was created on
pub fn db_network(db_path: &PathBuf) -> Result<Network, DatabaseError> {
    let mut rows = db_query(db_path, "SELECT network FROM tip", NO_PARAMS, |row| {
        Ok(Network::from_str(&row.get::<_, String>(0)?)
            .expect("We only evert insert from to_string"))
    })?;

    rows.pop()
        .ok_or_else(|| DatabaseError("No row in tip table?".to_string()))
}

/// Get the database wallet. We only support single wallet, so this always return the first row.
pub fn db_wallet(db_path: &PathBuf) -> Result<DbWallet, DatabaseError> {
    let mut rows = db_query(db_path, "SELECT * FROM wallets", NO_PARAMS, |row| {
        let our_man_xpub_str = row.get::<_, Option<String>>(4)?;
        let our_man_xpub = if let Some(ref xpub_str) = our_man_xpub_str {
            Some(
                ExtendedPubKey::from_str(&xpub_str)
                    .map_err(|e| FromSqlError::Other(Box::new(e)))?,
            )
        } else {
            None
        };

        let our_stk_xpub_str = row.get::<_, Option<String>>(5)?;
        let our_stk_xpub = if let Some(ref xpub_str) = our_stk_xpub_str {
            Some(
                ExtendedPubKey::from_str(&xpub_str)
                    .map_err(|e| FromSqlError::Other(Box::new(e)))?,
            )
        } else {
            None
        };

        assert!(
            our_man_xpub.is_some() || our_stk_xpub.is_some(),
            "The database is messed up, and we could not catch the error."
        );

        Ok(DbWallet {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            deposit_descriptor: row.get(2)?,
            unvault_descriptor: row.get(3)?,
            our_man_xpub,
            our_stk_xpub,
            deposit_derivation_index: ChildNumber::from(row.get::<_, u32>(6)?),
        })
    })?;

    rows.pop()
        .ok_or_else(|| DatabaseError("No row in wallet table?".to_string()))
}

impl TryFrom<&Row<'_>> for DbVault {
    type Error = rusqlite::Error;

    fn try_from(row: &Row) -> Result<Self, Self::Error> {
        let (id, wallet_id) = (row.get(0)?, row.get(1)?);
        let status: VaultStatus = row.get::<_, u32>(2)?.try_into().map_err(|_| {
            FromSqlError::Other(Box::new(DatabaseError(format!(
                "Unknown status for vault id '{}'",
                id
            ))))
        })?;
        let blockheight = row.get(3)?;
        let txid: Txid = encode::deserialize(&row.get::<_, Vec<u8>>(4)?)
            .map_err(|e| FromSqlError::Other(Box::new(e)))?;
        let deposit_outpoint = OutPoint {
            txid,
            vout: row.get(5)?,
        };
        let amount = Amount::from_sat(row.get::<_, i64>(6)? as u64);
        let derivation_index = ChildNumber::from(row.get::<_, u32>(7)?);
        let received_at = row.get(8)?;
        let updated_at = row.get(9)?;

        Ok(DbVault {
            id,
            wallet_id,
            status,
            blockheight,
            deposit_outpoint,
            amount,
            derivation_index,
            received_at,
            updated_at,
        })
    }
}

/// Get all the vaults we know about from the db, sorted by last update
pub fn db_vaults(db_path: &PathBuf) -> Result<Vec<DbVault>, DatabaseError> {
    db_query::<_, _, DbVault>(
        db_path,
        "SELECT * FROM vaults ORDER BY updated_at DESC",
        NO_PARAMS,
        |row| row.try_into(),
    )
}

/// Get all the vaults we know about from an already-created transaction
pub fn db_vaults_dbtx(db_tx: &Transaction) -> Result<Vec<DbVault>, DatabaseError> {
    db_tx
        .prepare("SELECT * FROM vaults")?
        .query_map(params![], |row| row.try_into())?
        .collect::<rusqlite::Result<Vec<DbVault>>>()
        .map_err(|e| e.into())
}

/// Get the vaults that didn't move onchain yet from the DB.
pub fn db_deposits(db_path: &PathBuf) -> Result<Vec<DbVault>, DatabaseError> {
    db_query(
        db_path,
        "SELECT * FROM vaults WHERE status <= (?1) ORDER BY updated_at DESC",
        &[VaultStatus::Active as u32],
        |row| row.try_into(),
    )
}

/// Get a vault from a deposit outpoint. Returns None if we never heard of such a vault.
pub fn db_vault_by_deposit(
    db_path: &PathBuf,
    deposit: &OutPoint,
) -> Result<Option<DbVault>, DatabaseError> {
    db_query(
        db_path,
        "SELECT * FROM vaults WHERE deposit_txid = (?1) AND deposit_vout = (?2)",
        params![deposit.txid.to_vec(), deposit.vout],
        |row| row.try_into(),
    )
    .map(|mut vault_list| vault_list.pop())
}

impl TryFrom<&Row<'_>> for DbTransaction {
    type Error = rusqlite::Error;

    fn try_from(row: &Row) -> Result<Self, Self::Error> {
        let id: u32 = row.get(0)?;
        let vault_id: u32 = row.get(1)?;

        let db_tx_type: u32 = row.get(2)?;
        let tx_type: TransactionType = db_tx_type.try_into().map_err(|_| {
            FromSqlError::Other(Box::new(DatabaseError(format!(
                "Unsane db: got an invalid tx type: '{}'",
                db_tx_type
            ))))
        })?;

        let db_psbt: Vec<u8> = row.get(3)?;
        let psbt = match tx_type {
            // For the remaining transactions (which we do create), we store a PSBT.
            TransactionType::Unvault => RevaultTx::Unvault(
                UnvaultTransaction::from_psbt_serialized(&db_psbt)
                    .map_err(|e| FromSqlError::Other(Box::new(e)))?,
            ),
            TransactionType::Cancel => RevaultTx::Cancel(
                CancelTransaction::from_psbt_serialized(&db_psbt)
                    .map_err(|e| FromSqlError::Other(Box::new(e)))?,
            ),
            TransactionType::Emergency => RevaultTx::Emergency(
                EmergencyTransaction::from_psbt_serialized(&db_psbt)
                    .map_err(|e| FromSqlError::Other(Box::new(e)))?,
            ),
            TransactionType::UnvaultEmergency => RevaultTx::UnvaultEmergency(
                UnvaultEmergencyTransaction::from_psbt_serialized(&db_psbt)
                    .map_err(|e| FromSqlError::Other(Box::new(e)))?,
            ),
        };

        let is_fully_signed: bool = row.get(4)?;

        Ok(DbTransaction {
            id,
            vault_id,
            tx_type,
            psbt,
            is_fully_signed,
        })
    }
}

/// Get the Unvault transaction for this vault
pub fn db_unvault_transaction(
    db_path: &PathBuf,
    vault_id: u32,
) -> Result<(u32, UnvaultTransaction), DatabaseError> {
    let mut rows: Vec<DbTransaction> = db_query(
        db_path,
        "SELECT * FROM presigned_transactions WHERE vault_id = (?1) AND type = (?2)",
        params![vault_id, TransactionType::Unvault as u32],
        |row| row.try_into(),
    )?;
    let db_tx = rows
        .pop()
        .ok_or_else(|| DatabaseError(format!("No unvault tx in db for vault id '{}'", vault_id)))?;

    Ok((
        db_tx.id,
        assert_tx_type!(db_tx.psbt, Unvault, "We just queryed it"),
    ))
}

/// Get the Cancel transaction corresponding to this vault
pub fn db_cancel_transaction(
    db_path: &PathBuf,
    vault_id: u32,
) -> Result<(u32, CancelTransaction), DatabaseError> {
    let mut rows: Vec<DbTransaction> = db_query(
        db_path,
        "SELECT * FROM presigned_transactions WHERE vault_id = (?1) AND type = (?2)",
        params![vault_id, TransactionType::Cancel as u32],
        |row| row.try_into(),
    )?;
    let db_tx = rows
        .pop()
        .ok_or_else(|| DatabaseError(format!("No cancel tx in db for vault id '{}'", vault_id)))?;

    Ok((
        db_tx.id,
        assert_tx_type!(db_tx.psbt, Cancel, "We just queryed it"),
    ))
}

/// Get the Emergency transaction corresponding to this vault.
/// Will error if there are none, ie if called by a non-stakeholder!
pub fn db_emer_transaction(
    db_path: &PathBuf,
    vault_id: u32,
) -> Result<(u32, EmergencyTransaction), DatabaseError> {
    let mut rows: Vec<DbTransaction> = db_query(
        db_path,
        "SELECT * FROM presigned_transactions WHERE vault_id = (?1) AND type = (?2)",
        params![vault_id, TransactionType::Emergency as u32],
        |row| row.try_into(),
    )?;
    let db_tx = rows.pop().ok_or_else(|| {
        DatabaseError(format!("No emergency tx in db for vault id '{}'", vault_id))
    })?;

    Ok((
        db_tx.id,
        assert_tx_type!(db_tx.psbt, Emergency, "We just queryed it"),
    ))
}

/// Get the Unvault Emergency transaction corresponding to this vault
/// Will error if there are none, ie if called by a non-stakeholder!
pub fn db_unvault_emer_transaction(
    db_path: &PathBuf,
    vault_id: u32,
) -> Result<(u32, UnvaultEmergencyTransaction), DatabaseError> {
    let mut rows: Vec<DbTransaction> = db_query(
        db_path,
        "SELECT * FROM presigned_transactions WHERE vault_id = (?1) AND type = (?2)",
        params![vault_id, TransactionType::UnvaultEmergency as u32],
        |row| row.try_into(),
    )?;
    let db_tx = rows.pop().ok_or_else(|| {
        DatabaseError(format!(
            "No unvault emergency tx in db for vault id '{}'",
            vault_id
        ))
    })?;

    Ok((
        db_tx.id,
        assert_tx_type!(db_tx.psbt, UnvaultEmergency, "We just queryed it"),
    ))
}

/// Get all the presigned transactions for which we don't have all the sigs yet.
/// Note that it will return the emergency transactions (if unsigned) only if we
/// are a stakeholder.
pub fn db_transactions_sig_missing(db_path: &PathBuf) -> Result<Vec<DbTransaction>, DatabaseError> {
    db_query(
        db_path,
        "SELECT * FROM presigned_transactions WHERE fullysigned = 0",
        params![],
        |row| row.try_into(),
    )
}
