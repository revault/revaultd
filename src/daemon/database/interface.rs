use crate::{database::DatabaseError, revaultd::VaultStatus};
use common::config;
use revault_tx::{
    bitcoin::{
        consensus::encode,
        util::{bip32::ChildNumber, psbt::PartiallySignedTransaction as Psbt},
        Amount, BlockHash, Network, OutPoint, Transaction as BitcoinTransaction, Txid,
    },
    miniscript::descriptor::DescriptorPublicKey,
};

use std::{boxed::Box, convert::TryInto, path::PathBuf, str::FromStr};

use rusqlite::{types::FromSqlError, Connection, Row, ToSql, Transaction, NO_PARAMS};

// Note that we don't share a global struct that would contain the connection here.
// As the bundled sqlite is compiled with SQLITE_THREADSAFE, quoting sqlite.org:
// > Multi-thread. In this mode, SQLite can be safely used by multiple threads provided that
// > no single database connection is used simultaneously in two or more threads.
// Therefore the below routines create a new connection and can be used from any thread.

/// Perform a set of modifications to the database inside a single transaction
pub fn db_exec<F>(path: &PathBuf, modifications: F) -> Result<(), DatabaseError>
where
    F: Fn(&Transaction) -> Result<(), DatabaseError>,
{
    let mut conn = Connection::open(path)
        .map_err(|e| DatabaseError(format!("Opening database: {}", e.to_string())))?;
    let tx = conn
        .transaction()
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
) -> Result<Vec<rusqlite::Result<T>>, DatabaseError>
where
    P: IntoIterator,
    P::Item: ToSql,
    F: FnMut(&Row<'_>) -> rusqlite::Result<T>,
{
    let conn = Connection::open(path)
        .map_err(|e| DatabaseError(format!("Opening database for query: {}", e.to_string())))?;

    let x = Ok(conn
        .prepare(stmt_str)
        .map_err(|e| DatabaseError(format!("Preparing query: '{}'", e.to_string())))?
        .query_map(params, f)
        .map_err(|e| DatabaseError(format!("Executing query: '{}'", e.to_string())))?
        .collect::<Vec<rusqlite::Result<T>>>());
    x
}

/// Get the database version
pub fn db_version(db_path: &PathBuf) -> Result<u32, DatabaseError> {
    let rows = db_query(db_path, "SELECT version FROM version", NO_PARAMS, |row| {
        row.get::<_, u32>(0)
    })?;

    Ok(*rows
        .get(0)
        .ok_or_else(|| DatabaseError("No row in version table?".to_string()))?
        .as_ref()
        .map_err(|e| DatabaseError(format!("Getting version: '{}'", e.to_string())))?)
}

/// Get our tip from the database
pub fn db_tip(db_path: &PathBuf) -> Result<(u32, BlockHash), DatabaseError> {
    let rows = db_query(
        db_path,
        "SELECT blockheight, blockhash FROM tip",
        NO_PARAMS,
        |row| {
            let blockheight = row.get::<_, u32>(0)?;
            let blockhash: BlockHash = encode::deserialize(&row.get::<_, Vec<u8>>(1)?)
                .map_err(|e| FromSqlError::Other(Box::new(e)))?;

            Ok((blockheight, blockhash))
        },
    )?;

    Ok(*rows
        .get(0)
        .ok_or_else(|| DatabaseError("No row in tip table?".to_string()))?
        .as_ref()
        .map_err(|e| DatabaseError(format!("Getting tip: '{}'", e.to_string())))?)
}

/// Get the network this DB was created on
pub fn db_network(db_path: &PathBuf) -> Result<Network, DatabaseError> {
    let rows = db_query(db_path, "SELECT network FROM tip", NO_PARAMS, |row| {
        Ok(Network::from_str(&row.get::<_, String>(0)?)
            .expect("We only evert insert from to_string"))
    })?;

    Ok(*rows
        .get(0)
        .ok_or_else(|| DatabaseError("No row in tip table?".to_string()))?
        .as_ref()
        .map_err(|e| DatabaseError(format!("Getting tip: '{}'", e.to_string())))?)
}

/// A "wallet" as stored in the database
#[derive(Clone)]
pub struct DbWallet {
    pub id: u32,
    pub timestamp: u32,
    pub vault_descriptor: String,
    pub unvault_descriptor: String,
    pub ourselves: config::OurSelves,
    pub deposit_derivation_index: u32,
}

/// Get the database wallet. We only support single wallet, so this always return the first row.
pub fn db_wallet(db_path: &PathBuf) -> Result<DbWallet, DatabaseError> {
    let rows = db_query(db_path, "SELECT * FROM wallets", NO_PARAMS, |row| {
        let our_man_xpub_str = row.get::<_, Option<String>>(4)?;
        let our_man_xpub = if let Some(ref xpub_str) = our_man_xpub_str {
            Some(
                DescriptorPublicKey::from_str(&xpub_str)
                    .map_err(|e| FromSqlError::Other(Box::new(e)))?,
            )
        } else {
            None
        };

        let our_stk_xpub_str = row.get::<_, Option<String>>(5)?;
        let our_stk_xpub = if let Some(ref xpub_str) = our_stk_xpub_str {
            Some(
                DescriptorPublicKey::from_str(&xpub_str)
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
            vault_descriptor: row.get(2)?,
            unvault_descriptor: row.get(3)?,
            ourselves: config::OurSelves {
                manager_xpub: our_man_xpub,
                stakeholder_xpub: our_stk_xpub,
            },
            deposit_derivation_index: row.get(6)?,
        })
    })?;

    Ok(rows
        .get(0)
        .ok_or_else(|| DatabaseError("No row in wallet table?".to_string()))?
        .as_ref()
        .map_err(|e| DatabaseError(format!("Getting wallet: '{}'", e.to_string())))?
        .clone())
}

/// An entry of the "vaults" table
pub struct DbVault {
    pub id: u32,
    pub wallet_id: u32,
    pub status: VaultStatus,
    pub blockheight: u32,
    pub deposit_outpoint: OutPoint,
    pub amount: Amount,
    pub derivation_index: ChildNumber,
}

/// Get the vaults that didn't move onchain yet from the DB.
pub fn db_deposits(db_path: &PathBuf) -> Result<Vec<DbVault>, DatabaseError> {
    db_query(
        db_path,
        "SELECT * FROM vaults WHERE status <= (?1)",
        &[VaultStatus::Active as u32],
        |row| {
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
            let amount = Amount::from_sat(row.get::<_, u32>(6)?.into());
            let derivation_index = ChildNumber::from(row.get::<_, u32>(7)?);

            Ok(DbVault {
                id,
                wallet_id,
                status,
                blockheight,
                deposit_outpoint,
                amount,
                derivation_index,
            })
        },
    )?
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| DatabaseError(format!("Querying vaults from db: '{}'", e.to_string())))
}

/// The type of the transaction, as stored in the "transactions" table
pub enum TransactionType {
    Deposit,
    Unvault,
    Spend,
    Cancel,
    Emergency,
    UnvaultEmergency,
}

/// A row in the "transactions" table
pub struct DbTransaction {
    pub id: u32,
    pub vault_id: u32,
    pub tx_type: TransactionType,
    /// Must not be NULL for RevaultTransactions, must be NULL for external ones
    pub psbt: Option<Psbt>,
    /// Must not be NULL for external transactions, must be NULL for RevaultTransactions
    pub tx: Option<BitcoinTransaction>,
}

// Add more db_* method here!
