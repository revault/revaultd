use crate::daemon::{
    database::{
        bitcointx::{RevaultTx, TransactionType},
        schema::{DbSpendTransaction, DbTransaction, DbVault, DbWallet},
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
    scripts::{CpfpDescriptor, DepositDescriptor, UnvaultDescriptor},
    transactions::{
        CancelTransaction, EmergencyTransaction, RevaultTransaction, SpendTransaction,
        UnvaultEmergencyTransaction, UnvaultTransaction,
    },
};

use std::{
    boxed::Box,
    collections::HashMap,
    convert::{TryFrom, TryInto},
    path::Path,
    str::FromStr,
};

use rusqlite::{
    params, types::FromSqlError, Connection, Row, ToSql, Transaction, TransactionBehavior,
};

// As the bundled sqlite is compiled with SQLITE_THREADSAFE, quoting sqlite.org:
// > Multi-thread. In this mode, SQLite can be safely used by multiple threads provided that
// > no single database connection is used simultaneously in two or more threads.
// Therefore the below routines for now create a new connection and can be used from any thread.
// For concurrent write accesses, we rely on the 'unlock_notify' feature of SQLite: https://sqlite.org/unlock_notify.html

/// Perform a set of modifications to the database inside a single transaction
pub fn db_exec<F>(path: &Path, modifications: F) -> Result<(), DatabaseError>
where
    F: FnOnce(&Transaction) -> Result<(), DatabaseError>,
{
    let mut conn = Connection::open(path)
        .map_err(|e| DatabaseError(format!("Opening database: {}", e.to_string())))?;
    conn.busy_timeout(std::time::Duration::from_secs(60))?;
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
    path: &Path,
    stmt_str: &'a str,
    params: P,
    f: F,
) -> Result<Vec<T>, DatabaseError>
where
    P: IntoIterator + rusqlite::Params,
    P::Item: ToSql,
    F: FnMut(&Row<'_>) -> rusqlite::Result<T>,
{
    let conn = Connection::open(path)
        .map_err(|e| DatabaseError(format!("Opening database for query: {}", e.to_string())))?;

    conn.busy_timeout(std::time::Duration::from_secs(60))?;

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

fn db_query_tx<'a, P, F, T>(
    db_tx: &Transaction,
    stmt_str: &'a str,
    params: P,
    f: F,
) -> Result<Vec<T>, DatabaseError>
where
    P: IntoIterator + rusqlite::Params,
    P::Item: ToSql,
    F: FnMut(&Row<'_>) -> rusqlite::Result<T>,
{
    // rustc says 'borrowed value does not live long enough'
    db_tx
        .prepare(stmt_str)
        .map_err(|e| DatabaseError(format!("Preparing query: '{}'", e.to_string())))?
        .query_map(params, f)
        .map_err(|e| DatabaseError(format!("Mapping query: '{}'", e.to_string())))?
        .collect::<rusqlite::Result<Vec<T>>>()
        .map_err(|e| DatabaseError(format!("Executing query: '{}'", e.to_string())))
}

/// Get the database version
pub fn db_version(db_path: &Path) -> Result<u32, DatabaseError> {
    let mut rows = db_query(db_path, "SELECT version FROM version", params![], |row| {
        row.get::<_, u32>(0)
    })?;

    rows.pop()
        .ok_or_else(|| DatabaseError("No row in version table?".to_string()))
}

/// Get our tip from the database
pub fn db_tip(db_path: &Path) -> Result<BlockchainTip, DatabaseError> {
    let mut rows = db_query(
        db_path,
        "SELECT blockheight, blockhash FROM tip",
        params![],
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
pub fn db_network(db_path: &Path) -> Result<Network, DatabaseError> {
    let mut rows = db_query(db_path, "SELECT network FROM tip", params![], |row| {
        Ok(Network::from_str(&row.get::<_, String>(0)?)
            .expect("We only evert insert from to_string"))
    })?;

    rows.pop()
        .ok_or_else(|| DatabaseError("No row in tip table?".to_string()))
}

/// Get the database wallet. We only support single wallet, so this always return the first row.
pub fn db_wallet(db_path: &Path) -> Result<DbWallet, DatabaseError> {
    let mut rows = db_query(db_path, "SELECT * FROM wallets", params![], |row| {
        let id = row.get(0)?;
        let timestamp = row.get(1)?;

        let deposit_desc_str: String = row.get(2)?;
        let deposit_descriptor = DepositDescriptor::from_str(&deposit_desc_str).map_err(|e| {
            FromSqlError::Other(Box::new(DatabaseError(format!(
                "Parsing database Deposit descriptor '{}': {}",
                deposit_desc_str, e
            ))))
        })?;
        let unvault_desc_str: String = row.get(3)?;
        let unvault_descriptor = UnvaultDescriptor::from_str(&unvault_desc_str).map_err(|e| {
            FromSqlError::Other(Box::new(DatabaseError(format!(
                "Parsing database Unvault descriptor '{}': {}",
                unvault_desc_str, e
            ))))
        })?;
        let cpfp_desc_str: String = row.get(4)?;
        let cpfp_descriptor = CpfpDescriptor::from_str(&cpfp_desc_str).map_err(|e| {
            FromSqlError::Other(Box::new(DatabaseError(format!(
                "Parsing database Cpfp descriptor '{}': {}",
                cpfp_desc_str, e
            ))))
        })?;

        let our_man_xpub_str = row.get::<_, Option<String>>(5)?;
        let our_man_xpub = if let Some(ref xpub_str) = our_man_xpub_str {
            Some(
                ExtendedPubKey::from_str(&xpub_str)
                    .map_err(|e| FromSqlError::Other(Box::new(e)))?,
            )
        } else {
            None
        };

        let our_stk_xpub_str = row.get::<_, Option<String>>(6)?;
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

        let deposit_derivation_index: u32 = row.get(7)?;
        let deposit_derivation_index: ChildNumber = deposit_derivation_index.into();

        Ok(DbWallet {
            id,
            timestamp,
            deposit_descriptor,
            unvault_descriptor,
            cpfp_descriptor,
            our_man_xpub,
            our_stk_xpub,
            deposit_derivation_index,
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
        let funded_at = row.get(8)?;
        let secured_at = row.get(9)?;
        let delegated_at = row.get(10)?;
        let moved_at = row.get(11)?;
        let final_txid = row
            .get::<_, Option<Vec<u8>>>(12)?
            .map(|raw_txid| encode::deserialize(&raw_txid).expect("We only store valid txids"));
        let emer_shared: bool = row.get(13)?;

        Ok(DbVault {
            id,
            wallet_id,
            status,
            blockheight,
            deposit_outpoint,
            amount,
            derivation_index,
            funded_at,
            secured_at,
            delegated_at,
            moved_at,
            final_txid,
            emer_shared,
        })
    }
}

/// Get all the vaults we know about from the db
pub fn db_vaults(db_path: &Path) -> Result<Vec<DbVault>, DatabaseError> {
    db_query::<_, _, DbVault>(db_path, "SELECT * FROM vaults", params![], |row| {
        row.try_into()
    })
}

/// Get all the vaults where status is *at least* `status`
pub fn db_vaults_min_status(
    db_path: &Path,
    status: VaultStatus,
) -> Result<Vec<DbVault>, DatabaseError> {
    db_query::<_, _, DbVault>(
        db_path,
        "SELECT * FROM vaults WHERE status >= (?1) ORDER BY moved_at, delegated_at, secured_at, funded_at DESC",
        params![status as u32],
        |row| row.try_into(),
    )
}

/// Get all the vaults we know about from an already-created transaction
pub fn db_vaults_dbtx(db_tx: &Transaction) -> Result<Vec<DbVault>, DatabaseError> {
    db_query_tx(db_tx, "SELECT * FROM vaults", params![], |row| {
        row.try_into()
    })
}

/// Get the vaults that didn't move onchain yet from the DB.
pub fn db_deposits(db_path: &Path) -> Result<Vec<DbVault>, DatabaseError> {
    db_query(
        db_path,
        "SELECT * FROM vaults WHERE status <= (?1)",
        params![VaultStatus::Active as u32],
        |row| row.try_into(),
    )
}

/// Get a vault from a deposit outpoint. Returns None if we never heard of such a vault.
pub fn db_vault_by_deposit(
    db_path: &Path,
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

/// Get the vaults that were unvaulted but for which the Unvault was not spent yet from the DB.
pub fn db_unvaulted_vaults(
    db_path: &Path,
) -> Result<Vec<(DbVault, UnvaultTransaction)>, DatabaseError> {
    db_query(
        db_path,
        "SELECT vaults.*, ptx.psbt FROM vaults INNER JOIN presigned_transactions as ptx \
         ON ptx.vault_id = vaults.id \
         WHERE ptx.type = (?1) AND vaults.status IN ((?2), (?3))",
        params![
            TransactionType::Unvault as u32,
            VaultStatus::Unvaulted as u32,
            VaultStatus::Unvaulting as u32,
        ],
        |row| {
            let db_vault: DbVault = row.try_into()?;
            let unvault_tx: Vec<u8> = row.get(14)?;
            let unvault_tx = UnvaultTransaction::from_psbt_serialized(&unvault_tx)
                .expect("We store it with as_psbt_serialized");

            Ok((db_vault, unvault_tx))
        },
    )
}
/// Get the vaults that are in the process of being spent, along with the respective Unvault
/// transaction.
pub fn db_spending_vaults(
    db_path: &Path,
) -> Result<Vec<(DbVault, UnvaultTransaction)>, DatabaseError> {
    db_query(
        db_path,
        "SELECT vaults.*, ptx.psbt FROM vaults \
         INNER JOIN presigned_transactions as ptx ON ptx.vault_id = vaults.id \
         WHERE vaults.status = (?1) AND ptx.type = (?2)",
        params![
            VaultStatus::Spending as u32,
            TransactionType::Unvault as u32,
        ],
        |row| {
            let db_vault: DbVault = row.try_into()?;
            let unvault_tx: Vec<u8> = row.get(14)?;
            let unvault_tx = UnvaultTransaction::from_psbt_serialized(&unvault_tx)
                .expect("We store it with as_psbt_serialized");

            Ok((db_vault, unvault_tx))
        },
    )
}

/// Get the vaults that are in the process of being canceled, along with the respective Cancel
/// transaction.
pub fn db_canceling_vaults(
    db_path: &Path,
) -> Result<Vec<(DbVault, CancelTransaction)>, DatabaseError> {
    db_query(
        db_path,
        "SELECT vaults.*, ptx.psbt FROM vaults \
         INNER JOIN presigned_transactions as ptx ON ptx.vault_id = vaults.id \
         WHERE vaults.status = (?1) AND ptx.type = (?2)",
        params![
            VaultStatus::Canceling as u32,
            TransactionType::Cancel as u32,
        ],
        |row| {
            let db_vault: DbVault = row.try_into()?;
            let cancel_tx: Vec<u8> = row.get(14)?;
            let cancel_tx = CancelTransaction::from_psbt_serialized(&cancel_tx)
                .expect("We store it with as_psbt_serialized");

            Ok((db_vault, cancel_tx))
        },
    )
}

/// Get the vaults that are in the process of being Emergency Vaulted, along with the respective
/// Emergency transaction.
pub fn db_emering_vaults(
    db_path: &Path,
) -> Result<Vec<(DbVault, EmergencyTransaction)>, DatabaseError> {
    db_query(
        db_path,
        "SELECT vaults.*, ptx.psbt FROM vaults \
         INNER JOIN presigned_transactions as ptx ON ptx.vault_id = vaults.id \
         WHERE vaults.status = (?1) AND ptx.type = (?2)",
        params![
            VaultStatus::EmergencyVaulting as u32,
            TransactionType::Emergency as u32,
        ],
        |row| {
            let db_vault: DbVault = row.try_into()?;
            let emer_tx: Vec<u8> = row.get(14)?;
            let emer_tx = EmergencyTransaction::from_psbt_serialized(&emer_tx)
                .expect("We store it with to_psbt_serialized");

            Ok((db_vault, emer_tx))
        },
    )
}

/// Get the Unvaulted vaults that are in the process of being Emergency Vaulted, along with the
/// respective UnvaultEmergency transaction.
pub fn db_unemering_vaults(
    db_path: &Path,
) -> Result<Vec<(DbVault, UnvaultEmergencyTransaction)>, DatabaseError> {
    db_query(
        db_path,
        "SELECT vaults.*, ptx.psbt FROM vaults \
         INNER JOIN presigned_transactions as ptx ON ptx.vault_id = vaults.id \
         WHERE vaults.status = (?1) AND ptx.type = (?2)",
        params![
            VaultStatus::UnvaultEmergencyVaulting as u32,
            TransactionType::UnvaultEmergency as u32,
        ],
        |row| {
            let db_vault: DbVault = row.try_into()?;
            let unemer_tx: Vec<u8> = row.get(14)?;
            let unemer_tx = UnvaultEmergencyTransaction::from_psbt_serialized(&unemer_tx)
                .expect("We store it with to_psbt_serialized");

            Ok((db_vault, unemer_tx))
        },
    )
}

fn db_tx_from_row(row: &Row, index_offset: usize) -> Result<DbTransaction, rusqlite::Error> {
    let id: u32 = row.get(index_offset)?;
    let vault_id: u32 = row.get(index_offset + 1)?;

    let db_tx_type: u32 = row.get(index_offset + 2)?;
    let tx_type: TransactionType = db_tx_type.try_into().map_err(|_| {
        FromSqlError::Other(Box::new(DatabaseError(format!(
            "Unsane db: got an invalid tx type: '{}'",
            db_tx_type
        ))))
    })?;

    let db_psbt: Vec<u8> = row.get(index_offset + 3)?;
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

    debug_assert_eq!(
        encode::deserialize::<revault_tx::bitcoin::util::psbt::PartiallySignedTransaction>(
            &db_psbt
        )
        .unwrap()
        .global
        .unsigned_tx
        .txid()
        .to_vec(),
        row.get::<_, Vec<u8>>(index_offset + 4)?,
        "Column txid and Psbt txid mismatch"
    );

    let is_fully_signed: bool = row.get(index_offset + 5)?;

    Ok(DbTransaction {
        id,
        vault_id,
        tx_type,
        psbt,
        is_fully_signed,
    })
}

impl TryFrom<&Row<'_>> for DbTransaction {
    type Error = rusqlite::Error;

    fn try_from(row: &Row) -> Result<Self, Self::Error> {
        db_tx_from_row(row, 0)
    }
}

/// Get the Unvault transaction for this vault
///
/// NOTE: the transaction *might* not be here even if you polled the vault status
/// beforehand, because it is a new database transaction.
pub fn db_unvault_transaction(
    db_path: &Path,
    vault_id: u32,
) -> Result<Option<DbTransaction>, DatabaseError> {
    db_query(
        db_path,
        "SELECT * FROM presigned_transactions WHERE vault_id = (?1) AND type = (?2)",
        params![vault_id, TransactionType::Unvault as u32],
        |row| row.try_into(),
    )
    .map(|mut rows| rows.pop())
}

/// Get the Unvault transaction for this vault from an existing database transaction
pub fn db_unvault_dbtx(
    db_tx: &Transaction,
    vault_id: u32,
) -> Result<Option<UnvaultTransaction>, DatabaseError> {
    db_query_tx(
        db_tx,
        "SELECT * FROM presigned_transactions WHERE vault_id = (?1) AND type = (?2)",
        params![vault_id, TransactionType::Unvault as u32],
        |row| row.try_into(),
    )
    .map(|mut rows| {
        rows.pop()
            .map(|db_tx: DbTransaction| db_tx.psbt.assert_unvault())
    })
}

/// Get the Unvault transaction corresponding to this vault from the database.
/// Note that unconfirmed vaults don't have the Unvault transaction stored in database.
pub fn db_unvault_from_deposit(
    db_path: &Path,
    deposit: &OutPoint,
) -> Result<Option<UnvaultTransaction>, DatabaseError> {
    let db_unvault: Option<DbTransaction> = db_query(
        db_path,
        "SELECT * FROM presigned_transactions as ptx INNER JOIN vaults ON ptx.vault_id = vaults.id \
         WHERE vaults.deposit_txid = (?1) AND vaults.deposit_vout = (?2) AND ptx.type = (?3)",
        params![deposit.txid.to_vec(), deposit.vout, TransactionType::Unvault as u32],
        |row| row.try_into()
    ).map(|mut rows| rows.pop())?;

    Ok(db_unvault.map(|db_tx| db_tx.psbt.assert_unvault()))
}

/// Get the Cancel transaction corresponding to this vault
///
/// NOTE: the transaction *might* not be here even if you polled the vault status
/// beforehand, because it is a new database transaction.
pub fn db_cancel_transaction(
    db_path: &Path,
    vault_id: u32,
) -> Result<Option<DbTransaction>, DatabaseError> {
    db_query(
        db_path,
        "SELECT * FROM presigned_transactions WHERE vault_id = (?1) AND type = (?2)",
        params![vault_id, TransactionType::Cancel as u32],
        |row| row.try_into(),
    )
    .map(|mut rows| rows.pop())
}

/// Get the Cancel transaction corresponding to this vault
pub fn db_cancel_dbtx(
    db_tx: &Transaction,
    vault_id: u32,
) -> Result<Option<CancelTransaction>, DatabaseError> {
    db_query_tx(
        db_tx,
        "SELECT * FROM presigned_transactions WHERE vault_id = (?1) AND type = (?2)",
        params![vault_id, TransactionType::Cancel as u32],
        |row| row.try_into(),
    )
    .map(|mut rows| {
        rows.pop()
            .map(|db_tx: DbTransaction| db_tx.psbt.assert_cancel())
    })
}

/// Get the Emergency transaction corresponding to this vault.
///
/// NOTE: the transaction *might* not be here even if you polled the vault status
/// beforehand, because it is a new database transaction.
pub fn db_emer_transaction(
    db_path: &Path,
    vault_id: u32,
) -> Result<Option<DbTransaction>, DatabaseError> {
    db_query(
        db_path,
        "SELECT * FROM presigned_transactions WHERE vault_id = (?1) AND type = (?2)",
        params![vault_id, TransactionType::Emergency as u32],
        |row| row.try_into(),
    )
    .map(|mut rows| rows.pop())
}

/// Get the Unvault Emergency transaction corresponding to this vault
///
/// NOTE: the transaction *might* not be here even if you polled the vault status
/// beforehand, because it is a new database transaction.
pub fn db_unvault_emer_transaction(
    db_path: &Path,
    vault_id: u32,
) -> Result<Option<DbTransaction>, DatabaseError> {
    db_query(
        db_path,
        "SELECT * FROM presigned_transactions WHERE vault_id = (?1) AND type = (?2)",
        params![vault_id, TransactionType::UnvaultEmergency as u32],
        |row| row.try_into(),
    )
    .map(|mut rows| rows.pop())
}

/// Get a vault and its Unvault transaction out of an Unvault txid
pub fn db_vault_by_unvault_txid(
    db_path: &Path,
    txid: &Txid,
) -> Result<Option<(DbVault, DbTransaction)>, DatabaseError> {
    Ok(db_query(
        db_path,
        "SELECT vaults.*, ptx.id, ptx.psbt, ptx.fullysigned FROM presigned_transactions as ptx \
         INNER JOIN vaults ON vaults.id = ptx.vault_id \
         WHERE ptx.txid = (?1) and type = (?2)",
        params![txid.to_vec(), TransactionType::Unvault as u32],
        |row| {
            let db_vault: DbVault = row.try_into()?;
            let offset = 14;

            // FIXME: there is probably a more extensible way to implement the from()s so we don't
            // have to change all those when adding a column
            let id: u32 = row.get(offset)?;
            let psbt: Vec<u8> = row.get(offset + 1)?;
            let psbt = UnvaultTransaction::from_psbt_serialized(&psbt).expect("We store it");
            let is_fully_signed = row.get(offset + 2)?;
            let db_tx = DbTransaction {
                id,
                vault_id: db_vault.id,
                tx_type: TransactionType::Unvault,
                psbt: RevaultTx::Unvault(psbt),
                is_fully_signed,
            };

            Ok((db_vault, db_tx))
        },
    )?
    .pop())
}

/// Get all the vaults whose presigned txs are missing signature, along with those txs.
/// Note that it will return the emergency transactions (if unsigned) only if we
/// are a stakeholder.
pub fn db_sig_missing(
    db_path: &Path,
) -> Result<HashMap<DbVault, Vec<DbTransaction>>, DatabaseError> {
    let mut vault_map: HashMap<DbVault, Vec<DbTransaction>> = HashMap::new();

    db_query(
        db_path,
        "SELECT v.*, ptx.* \
         FROM presigned_transactions as ptx INNER JOIN vaults as v ON ptx.vault_id = v.id \
         WHERE ptx.fullysigned = 0 AND v.status IN (?1, ?2, ?3, ?4)",
        params![
            VaultStatus::Funded as u32,
            VaultStatus::Securing as u32,
            VaultStatus::Secured as u32,
            VaultStatus::Activating as u32
        ],
        |row| {
            let db_vault: DbVault = row.try_into()?;
            let db_tx: DbTransaction = db_tx_from_row(row, 14)?;

            if let Some(db_txs) = vault_map.get_mut(&db_vault) {
                db_txs.push(db_tx);
            } else {
                vault_map.insert(db_vault, vec![db_tx]);
            }

            Ok(())
        },
    )?;

    Ok(vault_map)
}

/// Get all the Emergency transactions of the "secured" (Emergency signed) vaults that were not yet
/// Unvaulted.
pub fn db_signed_emer_txs(db_path: &Path) -> Result<Vec<EmergencyTransaction>, DatabaseError> {
    // FIXME: Get rid of this footguny v.status < (?2)
    db_query(
        db_path,
        "SELECT ptx.* FROM presigned_transactions as ptx INNER JOIN vaults as v ON ptx.vault_id = v.id \
         WHERE ptx.fullysigned = 1 AND ptx.type = (?1) AND v.status < (?2)",
        params![
            TransactionType::Emergency as u32,
            VaultStatus::Unvaulting as u32,
        ],
        |row| {
            let db_tx: DbTransaction = row.try_into()?;
            Ok(match db_tx.psbt {
                RevaultTx::Emergency(tx) => tx,
                _ => unreachable!("Inconsistency between TransactionType and RevaultTx variant?"),
            })
        },
    )
}

/// Get all the UnvaultEmergency transactions of the Unvaulted vaults that were not yet Spent
pub fn db_signed_unemer_txs(
    db_path: &Path,
) -> Result<Vec<UnvaultEmergencyTransaction>, DatabaseError> {
    db_query(
        db_path,
        "SELECT ptx.* FROM presigned_transactions as ptx INNER JOIN vaults as v on ptx.vault_id = v.id \
         WHERE ptx.fullysigned = 1 AND ptx.type = (?1) AND v.status IN ((?2), (?3), (?4), (?5))",
        params![
            TransactionType::UnvaultEmergency as u32,
            VaultStatus::Unvaulting as u32,
            VaultStatus::Unvaulted as u32,
            VaultStatus::Spending as u32,
            VaultStatus::Canceling as u32,
        ],
        |row| {
            let db_tx: DbTransaction = row.try_into()?;
            Ok(match db_tx.psbt {
                RevaultTx::UnvaultEmergency(tx) => tx,
                _ => unreachable!("Inconsistency between TransactionType and RevaultTx variant?"),
            })
        },
    )
}

impl TryFrom<&Row<'_>> for DbSpendTransaction {
    type Error = rusqlite::Error;

    fn try_from(row: &Row) -> Result<Self, Self::Error> {
        let id: i64 = row.get(0)?;
        let psbt: Vec<u8> = row.get(1)?;
        let broadcasted: Option<bool> = row.get(3)?; // 2 is 'txid'
        let has_priority: bool = row.get(4)?;

        let psbt = SpendTransaction::from_psbt_serialized(&psbt)
            .expect("We store it with as_psbt_serialized");

        debug_assert_eq!(
            psbt.tx().txid().to_vec(),
            row.get::<_, Vec<u8>>(2)?,
            "Insane db, txid in column is not the same as psbt's one",
        );

        Ok(DbSpendTransaction {
            id,
            psbt,
            broadcasted,
            has_priority,
        })
    }
}

/// List all Spend transactions in DB along with the vault they are spending
pub fn db_list_spends(
    db_path: &Path,
) -> Result<HashMap<Txid, (DbSpendTransaction, Vec<OutPoint>)>, DatabaseError> {
    // SpendTransaction can't be Hash for the moment
    let mut res: HashMap<Txid, (DbSpendTransaction, Vec<OutPoint>)> = HashMap::with_capacity(128);

    db_query(
        db_path,
        "SELECT stx.id, stx.psbt, stx.txid, stx.broadcasted, stx.has_priority, vaults.deposit_txid, vaults.deposit_vout \
         FROM spend_transactions as stx \
         INNER JOIN spend_inputs as sin ON stx.id = sin.spend_id \
         INNER JOIN presigned_transactions as ptx ON ptx.id = sin.unvault_id \
         INNER JOIN vaults ON vaults.id = ptx.vault_id",
        params![],
        |row| {
            let db_spend: DbSpendTransaction = row.try_into()?;

            let txid: Txid = encode::deserialize(&row.get::<_, Vec<u8>>(5)?).expect("We store it");
            let vout: u32 = row.get(6)?;
            let deposit_outpoint = OutPoint { txid, vout };

            let spend_txid = db_spend.psbt.tx().txid();

            if res.contains_key(&spend_txid) {
                let (_, outpoints) = res.get_mut(&spend_txid).unwrap();
                outpoints.push(deposit_outpoint);
            } else {
                res.insert(spend_txid, (db_spend, vec![deposit_outpoint]));
            }

            Ok(())
        },
    )?;

    Ok(res)
}

pub fn db_broadcastable_spend_transactions(
    db_path: &Path,
) -> Result<Vec<DbSpendTransaction>, DatabaseError> {
    db_query(
        db_path,
        "SELECT * FROM spend_transactions WHERE broadcasted = 0",
        params![],
        |row| row.try_into(),
    )
}

/// Get a single Spend transaction from DB by its txid
pub fn db_spend_transaction(
    db_path: &Path,
    spend_txid: &Txid,
) -> Result<Option<DbSpendTransaction>, DatabaseError> {
    Ok(db_query(
        db_path,
        "SELECT * FROM spend_transactions WHERE txid = (?1)",
        params![spend_txid.to_vec()],
        |row| row.try_into(),
    )?
    .pop())
}

/// Get a mapping of Spend transaction inputs to the vault they ultimately spend. Note that we
/// can't have two Unvault outputs in a single Unvault transaction therefore it's fine to use the
/// txid for identifying the Unvault output.
pub fn db_vaults_from_spend(
    db_path: &Path,
    spend_txid: &Txid,
) -> Result<HashMap<Txid, DbVault>, DatabaseError> {
    let mut db_vaults = HashMap::with_capacity(128);

    db_query(
        db_path,
        "SELECT vaults.*, ptx.txid \
         FROM spend_transactions as stx \
         INNER JOIN spend_inputs as sin ON stx.id = sin.spend_id \
         INNER JOIN presigned_transactions as ptx ON ptx.id = sin.unvault_id \
         INNER JOIN vaults ON vaults.id = ptx.vault_id \
         WHERE stx.txid = (?1)",
        params![spend_txid.to_vec()],
        |row| {
            let db_vault: DbVault = row.try_into()?;
            let txid: Txid = encode::deserialize(&row.get::<_, Vec<u8>>(14)?).expect("We store it");
            db_vaults.insert(txid, db_vault);
            Ok(())
        },
    )?;

    Ok(db_vaults)
}

/// Returns all the spends that have priority and have been broadcasted, which are
/// eligible for CPFP
pub fn db_cpfpable_spends(db_path: &Path) -> Result<Vec<SpendTransaction>, DatabaseError> {
    db_query(
        db_path,
        "SELECT * FROM spend_transactions
         WHERE has_priority = 1 AND broadcasted = 1",
        params![],
        |row| {
            let db_spend: DbSpendTransaction = row.try_into()?;
            Ok(db_spend.psbt)
        },
    )
}

/// Returns all the unvaults that have priority and for which their spend has not
/// been broadcasted, which are eligible for CPFP if still unconfirmed
pub fn db_cpfpable_unvaults(db_path: &Path) -> Result<Vec<UnvaultTransaction>, DatabaseError> {
    db_query(
        db_path,
        "SELECT ptx.*, stx.id FROM spend_transactions stx \
         INNER JOIN spend_inputs as sin ON stx.id = sin.spend_id \
         INNER JOIN presigned_transactions as ptx ON ptx.id = sin.unvault_id \
         WHERE has_priority = true AND broadcasted = false AND ptx.type = (?1)
        ",
        params![TransactionType::Unvault as u32,],
        |row| {
            let tx: DbTransaction = row.try_into()?;
            match tx.psbt {
                RevaultTx::Unvault(tx) => Ok(tx),
                _ => unreachable!(),
            }
        },
    )
}

/// This function returns the vaults that are deposit, change deposit or spend output of
/// a limited number of tx which occured between two dates.
pub fn db_vaults_with_txids_in_period(
    db_path: &Path,
    start: u32,
    end: u32,
    limit: u64,
) -> Result<Vec<DbVault>, DatabaseError> {
    db_query(
        db_path,
        "WITH txids AS ( \
            SELECT DISTINCT(txid) FROM ( \
                SELECT * from ( \
                    SELECT deposit_txid AS txid, funded_at AS date FROM vaults \
                    WHERE funded_at >= (?1) \
                    AND funded_at <= (?2) \
                    AND status != (?4) \
                    ORDER BY funded_at DESC LIMIT (?3) \
                ) \
                UNION \
                SELECT * FROM (
                    SELECT final_txid AS txid, moved_at AS date FROM vaults \
                    WHERE moved_at >= (?1) \
                    AND moved_at <= (?2) \
                    AND status IN ((?5), (?6)) \
                    ORDER BY moved_at DESC LIMIT (?3) \
                ) \
                ORDER BY date DESC LIMIT (?3)
            ) \
        ) \
        SELECT * FROM vaults \
        WHERE deposit_txid IN txids \
        OR final_txid IN txids",
        params![
            start,
            end,
            limit,
            VaultStatus::Unconfirmed as u32,
            VaultStatus::Canceled as u32,
            VaultStatus::Spent as u32,
        ],
        |row| row.try_into(),
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::daemon::database::actions::{
        db_confirm_deposit, db_insert_new_unconfirmed_vault, setup_db,
    };
    use crate::daemon::jsonrpc::UserRole;
    use crate::daemon::utils::test_utils::{dummy_revaultd, test_datadir};
    use revault_tx::{bitcoin::OutPoint, transactions::transaction_chain};

    use std::{fs, str::FromStr};

    fn db_vault_set_final_txid(
        db_path: &Path,
        db_vault: &DbVault,
        final_txid: &Txid,
        moved_at: u32,
    ) {
        db_exec(db_path, |tx| {
            tx.execute(
                "UPDATE vaults SET final_txid = (?1), moved_at = (?2), status = (?3) WHERE id = (?4)",
                params![final_txid.to_vec(), moved_at, VaultStatus::Spent as u32, db_vault.id,],
            )?;
            Ok(())
        })
        .unwrap()
    }

    #[test]
    fn test_db_vaults_with_txids_in_period() {
        let datadir = test_datadir();
        let mut revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);
        let db_path = revaultd.db_file();
        setup_db(&mut revaultd).unwrap();
        let genesis_timestamp: u32 = 1231006505;

        // Fill in some vaults funded at different dates
        let wallet_id = 1;
        for i in 1..=10 {
            let outpoint = OutPoint {
                // NOTE: we make the txid vary because the SQL request assumes (rightfully) that
                // vaults with the same txid will never have different `funded_at` values.
                txid: Txid::from_str(&format!(
                    "da2245566282477c233a70ec684c7ca42ee2505b07dbe38e1af993c470120b7{:x}",
                    i
                ))
                .unwrap(),
                vout: i,
            };
            let amount = Amount::from_sat(3456798 * i as u64);
            let derivation_index = ChildNumber::from(i * 10);
            db_insert_new_unconfirmed_vault(
                &db_path,
                wallet_id,
                &outpoint,
                &amount,
                derivation_index,
            )
            .unwrap();
            let (unvault_tx, cancel_tx, emer_tx, unemer_tx) = transaction_chain(
                outpoint,
                amount,
                &revaultd.deposit_descriptor,
                &revaultd.unvault_descriptor,
                &revaultd.cpfp_descriptor,
                derivation_index,
                revaultd.emergency_address.clone().unwrap(),
                revaultd.lock_time,
                &revaultd.secp_ctx,
            )
            .unwrap();
            db_confirm_deposit(
                &db_path,
                &outpoint,
                i,
                genesis_timestamp as u32 + i * 600,
                &unvault_tx,
                &cancel_tx,
                Some(&emer_tx),
                Some(&unemer_tx),
            )
            .unwrap();
        }

        // Nothing at timestamp 0
        assert_eq!(
            db_vaults_with_txids_in_period(&db_path, 0, 0, 10)
                .unwrap()
                .len(),
            0
        );
        // Range is inclusive
        assert_eq!(
            db_vaults_with_txids_in_period(
                &db_path,
                genesis_timestamp,
                genesis_timestamp + 10 * 600,
                10
            )
            .unwrap()
            .len(),
            10
        );
        assert_eq!(
            db_vaults_with_txids_in_period(
                &db_path,
                genesis_timestamp,
                genesis_timestamp + 10 * 600 - 1,
                10
            )
            .unwrap()
            .len(),
            9
        );
        assert_eq!(
            db_vaults_with_txids_in_period(
                &db_path,
                genesis_timestamp + 1 * 600 + 1,
                genesis_timestamp + 10 * 600,
                10
            )
            .unwrap()
            .len(),
            9
        );
        // We can limit the number of results
        assert_eq!(
            db_vaults_with_txids_in_period(
                &db_path,
                genesis_timestamp,
                genesis_timestamp + 10 * 600,
                5
            )
            .unwrap()
            .len(),
            5
        );

        // This also works with the final txid
        let vaults = db_vaults(&db_path).unwrap();
        for i in 0..5 {
            // NOTE: we make the txid vary because the SQL request assumes (rightfully) that
            // vaults with the same txid will never have different `moved_at` values.
            let txid = Txid::from_str(&format!(
                "af2cac1e0e33d896d9d0751d66fcb2fa54b737c7a13199281fb57e4f497bb65{}",
                i
            ))
            .unwrap();
            db_vault_set_final_txid(
                &db_path,
                &vaults[i],
                &txid,
                genesis_timestamp as u32 + 10 * 600 + (i as u32 + 1) * 600,
            );

            assert_eq!(
                db_vaults_with_txids_in_period(
                    &db_path,
                    genesis_timestamp + 10 * 600 + 1,
                    genesis_timestamp + 10 * 600 + 5 * 600,
                    10
                )
                .unwrap()
                .len(),
                i + 1
            );
        }

        // We only have 10 vaults in total, even if half of them have 2 txids in this period.
        assert_eq!(
            db_vaults_with_txids_in_period(&db_path, 0, genesis_timestamp + 100 * 600, 50)
                .unwrap()
                .len(),
            10
        );

        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }
}
