use crate::{
    assert_tx_type,
    database::{
        schema::{
            DbSpendTransaction, DbTransaction, DbVault, DbWallet, RevaultTx, TransactionType,
        },
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
        CancelTransaction, EmergencyTransaction, RevaultTransaction, SpendTransaction,
        UnvaultEmergencyTransaction, UnvaultTransaction,
    },
};

use std::{
    boxed::Box,
    collections::HashMap,
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

fn db_query_tx<'a, P, F, T>(
    db_tx: &Transaction,
    stmt_str: &'a str,
    params: P,
    f: F,
) -> Result<Vec<T>, DatabaseError>
where
    P: IntoIterator,
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
        let spend_txid = row
            .get::<_, Option<Vec<u8>>>(10)?
            .map(|raw_txid| encode::deserialize(&raw_txid).expect("We only store valid txids"));

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
            spend_txid,
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
    db_query_tx(db_tx, "SELECT * FROM vaults", params![], |row| {
        row.try_into()
    })
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

/// Get the vaults that were unvaulted but for which the Unvault was not spent yet from the DB.
pub fn db_unvaulted_vaults(
    db_path: &PathBuf,
) -> Result<Vec<(DbVault, UnvaultTransaction)>, DatabaseError> {
    db_query(
        db_path,
        "SELECT vaults.*, ptx.psbt FROM vaults INNER JOIN presigned_transactions as ptx \
         ON ptx.vault_id = vaults.id \
         WHERE vaults.status = (?1) OR vaults.status = (?2) AND ptx.type = (?3)",
        &[
            VaultStatus::Unvaulting as u32,
            VaultStatus::Unvaulted as u32,
            TransactionType::Unvault as u32,
        ],
        |row| {
            let db_vault: DbVault = row.try_into()?;
            let unvault_tx: Vec<u8> = row.get(11)?;
            let unvault_tx = UnvaultTransaction::from_psbt_serialized(&unvault_tx)
                .expect("We store it with to_psbt_serialized");

            Ok((db_vault, unvault_tx))
        },
    )
}
/// Get the vaults that are in the process of being spent, along with the respective Unvault
/// transaction.
pub fn db_spending_vaults(
    db_path: &PathBuf,
) -> Result<Vec<(DbVault, UnvaultTransaction)>, DatabaseError> {
    db_query(
        db_path,
        "SELECT vaults.*, ptx.psbt FROM vaults \
         INNER JOIN presigned_transactions as ptx ON ptx.vault_id = vaults.id \
         WHERE vaults.status = (?1) AND ptx.type = (?2)",
        &[
            VaultStatus::Spending as u32,
            TransactionType::Unvault as u32,
        ],
        |row| {
            let db_vault: DbVault = row.try_into()?;
            let unvault_tx: Vec<u8> = row.get(11)?;
            let unvault_tx = UnvaultTransaction::from_psbt_serialized(&unvault_tx)
                .expect("We store it with to_psbt_serialized");

            Ok((db_vault, unvault_tx))
        },
    )
}

/// Get the vaults that are in the process of being canceled, along with the respective Cancel
/// transaction.
pub fn db_canceling_vaults(
    db_path: &PathBuf,
) -> Result<Vec<(DbVault, CancelTransaction)>, DatabaseError> {
    db_query(
        db_path,
        "SELECT vaults.*, ptx.psbt FROM vaults \
         INNER JOIN presigned_transactions as ptx ON ptx.vault_id = vaults.id \
         WHERE vaults.status = (?1) AND ptx.type = (?2)",
        &[
            VaultStatus::Canceling as u32,
            TransactionType::Cancel as u32,
        ],
        |row| {
            let db_vault: DbVault = row.try_into()?;
            let cancel_tx: Vec<u8> = row.get(11)?;
            let cancel_tx = CancelTransaction::from_psbt_serialized(&cancel_tx)
                .expect("We store it with to_psbt_serialized");

            Ok((db_vault, cancel_tx))
        },
    )
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

        debug_assert_eq!(
            encode::deserialize::<revault_tx::bitcoin::util::psbt::PartiallySignedTransaction>(
                &db_psbt
            )
            .unwrap()
            .global
            .unsigned_tx
            .txid()
            .to_vec(),
            row.get::<_, Vec<u8>>(4)?,
            "Column txid and Psbt txid mismatch"
        );

        let is_fully_signed: bool = row.get(5)?;

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
            .map(|db_tx: DbTransaction| assert_tx_type!(db_tx.psbt, Unvault, "We just queryed it"))
    })
}

/// Get the Unvault transaction corresponding to this vault from the database.
/// Note that unconfirmed vaults don't have the Unvault transaction stored in database.
pub fn db_unvault_from_deposit(
    db_path: &PathBuf,
    deposit: &OutPoint,
) -> Result<Option<UnvaultTransaction>, DatabaseError> {
    let db_unvault: Option<DbTransaction> = db_query(
        db_path,
        "SELECT * FROM presigned_transactions as ptx INNER JOIN vaults ON ptx.vault_id = vaults.id \
         WHERE vaults.deposit_txid = (?1) AND vaults.deposit_vout = (?2) AND ptx.type = (?3)",
        params![deposit.txid.to_vec(), deposit.vout, TransactionType::Unvault as u32],
        |row| row.try_into()
    ).map(|mut rows| rows.pop())?;

    Ok(db_unvault.map(|db_tx| assert_tx_type!(db_tx.psbt, Unvault, "We just queried it")))
}

/// Get the Cancel transaction corresponding to this vault
pub fn db_cancel_transaction(
    db_path: &PathBuf,
    vault_id: u32,
) -> Result<Option<(u32, CancelTransaction)>, DatabaseError> {
    let mut rows: Vec<DbTransaction> = db_query(
        db_path,
        "SELECT * FROM presigned_transactions WHERE vault_id = (?1) AND type = (?2)",
        params![vault_id, TransactionType::Cancel as u32],
        |row| row.try_into(),
    )?;
    Ok(rows.pop().map(|db_tx| {
        (
            db_tx.id,
            assert_tx_type!(db_tx.psbt, Cancel, "We just queryed it"),
        )
    }))
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

/// Get a vault and its Unvault transaction out of an Unvault txid
pub fn db_vault_by_unvault_txid(
    db_path: &PathBuf,
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

            // FIXME: there is probably a more extensible way to implement the from()s so we don't
            // have to change all those when adding a column
            let id: u32 = row.get(11)?;
            let psbt: Vec<u8> = row.get(12)?;
            let psbt = UnvaultTransaction::from_psbt_serialized(&psbt).expect("We store it");
            let is_fully_signed = row.get(13)?;
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

impl TryFrom<&Row<'_>> for DbSpendTransaction {
    type Error = rusqlite::Error;

    fn try_from(row: &Row) -> Result<Self, Self::Error> {
        let id: i64 = row.get(0)?;
        let psbt: Vec<u8> = row.get(1)?;
        let broadcasted: Option<bool> = row.get(3)?; // 2 is 'txid'

        let psbt = SpendTransaction::from_psbt_serialized(&psbt)
            .expect("We set it using as_psbt_serialized()");

        debug_assert_eq!(
            psbt.inner_tx().global.unsigned_tx.txid().to_vec(),
            row.get::<_, Vec<u8>>(2)?,
            "Insane db, txid in column is not the same as psbt's one",
        );

        Ok(DbSpendTransaction {
            id,
            psbt,
            broadcasted,
        })
    }
}

/// List all Spend transactions in DB along with the vault they are spending
pub fn db_list_spends(
    db_path: &PathBuf,
) -> Result<HashMap<Txid, (SpendTransaction, Vec<OutPoint>)>, DatabaseError> {
    // SpendTransaction can't be Hash for the moment
    let mut res: HashMap<Txid, (SpendTransaction, Vec<OutPoint>)> = HashMap::with_capacity(128);

    db_query(
        db_path,
        "SELECT stx.id, stx.psbt, stx.txid, stx.broadcasted, vaults.deposit_txid, vaults.deposit_vout \
         FROM spend_transactions as stx \
         INNER JOIN spend_inputs as sin ON stx.id = sin.spend_id \
         INNER JOIN presigned_transactions as ptx ON ptx.id = sin.unvault_id \
         INNER JOIN vaults ON vaults.id = ptx.vault_id",
        params![],
        |row| {
            let db_spend: DbSpendTransaction = row.try_into()?;

            let txid: Txid = encode::deserialize(&row.get::<_, Vec<u8>>(4)?).expect("We store it");
            let vout: u32 = row.get(5)?;
            let deposit_outpoint = OutPoint { txid, vout };

            let spend_tx = db_spend.psbt;
            let spend_txid = spend_tx.inner_tx().global.unsigned_tx.txid();

            if res.contains_key(&spend_txid) {
                let (_, outpoints) = res.get_mut(&spend_txid).unwrap();
                outpoints.push(deposit_outpoint);
            } else {
                res.insert(spend_txid, (spend_tx, vec![deposit_outpoint]));
            }

            Ok(())
        },
    )?;

    Ok(res)
}

pub fn db_broadcastable_spend_transactions(
    db_path: &PathBuf,
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
    db_path: &PathBuf,
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
    db_path: &PathBuf,
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
            let txid: Txid = encode::deserialize(&row.get::<_, Vec<u8>>(11)?).expect("We store it");
            db_vaults.insert(txid, db_vault);
            Ok(())
        },
    )?;

    Ok(db_vaults)
}
