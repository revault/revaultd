use crate::{
    database::{interface::*, schema::SCHEMA, DatabaseError, VERSION},
    revaultd::{RevaultD, VaultStatus},
};
use revault_tx::{
    bitcoin::consensus::encode,
    miniscript::Descriptor,
    scripts::{UnvaultDescriptor, VaultDescriptor},
    transactions::VaultTransaction,
};

use std::{
    convert::TryInto,
    path::PathBuf,
    str::FromStr,
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

// No database yet ? In a single tx, create a new one from the schema and populate with current
// information
fn create_db(revaultd: &RevaultD) -> Result<(), DatabaseError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| timestamp_to_u32(dur.as_secs()))
        .map_err(|e| DatabaseError(format!("Computing time since epoch: {}", e.to_string())))?;
    let vault_descriptor = revaultd.vault_descriptor.0.to_string();
    let unvault_descriptor = revaultd.unvault_descriptor.0.to_string();
    let our_man_xpub_str = revaultd
        .ourselves
        .manager_xpub
        .as_ref()
        .map(|xpub| xpub.to_string());
    let our_stk_xpub_str = revaultd
        .ourselves
        .stakeholder_xpub
        .as_ref()
        .map(|xpub| xpub.to_string());

    db_exec(&revaultd.db_file(), |tx| {
        tx.execute_batch(&SCHEMA)
            .map_err(|e| DatabaseError(format!("Creating database: {}", e.to_string())))?;
        tx.execute(
            "INSERT INTO version (version) VALUES (?1)",
            params![VERSION],
        )
        .map_err(|e| DatabaseError(format!("Inserting version: {}", e.to_string())))?;
        tx.execute(
            "INSERT INTO wallets (timestamp, vault_descriptor, unvault_descriptor,\
            our_manager_xpub, our_stakeholder_xpub, deposit_derivation_index) \
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                timestamp,
                vault_descriptor,
                unvault_descriptor,
                our_man_xpub_str,
                our_stk_xpub_str,
                revaultd.current_unused_index,
            ],
        )
        .map_err(|e| DatabaseError(format!("Inserting wallet: {}", e.to_string())))?;

        Ok(())
    })
}

// Called on startup to check database integrity
fn check_db(revaultd: &RevaultD) -> Result<(), DatabaseError> {
    // Check if their database is not from the future.
    // We'll eventually do migration here if version < VERSION, but be strict until then.
    let version = db_version(&revaultd.db_file())?;
    if version != VERSION {
        return Err(DatabaseError(format!(
            "Unexpected database version: got '{}', expected '{}'",
            version, VERSION
        )));
    }

    Ok(())
}

// Called on startup to populate our cache from the database
fn state_from_db(revaultd: &mut RevaultD) -> Result<(), DatabaseError> {
    let wallet = db_wallet(&revaultd.db_file())?;

    //FIXME: Find a way to check if the policies described in the config files are equivalent
    // to the miniscript in the db.
    revaultd.vault_descriptor =
        VaultDescriptor(Descriptor::from_str(&wallet.vault_descriptor).map_err(|e| {
            DatabaseError(format!(
                "Interpreting database vault descriptor '{}': {}",
                wallet.vault_descriptor,
                e.to_string()
            ))
        })?);
    revaultd.unvault_descriptor = UnvaultDescriptor(
        Descriptor::from_str(&wallet.unvault_descriptor).map_err(|e| {
            DatabaseError(format!(
                "Interpreting database unvault descriptor '{}': {}",
                wallet.unvault_descriptor,
                e.to_string()
            ))
        })?,
    );

    revaultd.current_unused_index = wallet.deposit_derivation_index;
    revaultd.wallet_id = wallet.id;

    // TODO: update the vaults cache from the database

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

/// Insert a new deposit in the database (atomically record both the vault and the deposit
/// transaction).
pub fn db_insert_new_vault(
    db_path: &PathBuf,
    wallet_id: u32,
    status: VaultStatus,
    blockheight: u32,
    deposit_txid: Vec<u8>,
    deposit_vout: u32,
    amount: u32,
    derivation_index: u32,
    vault_tx: VaultTransaction,
) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "INSERT INTO vaults (wallet_id, status, blockheight, deposit_txid, \
             deposit_vout, amount, derivation_index) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                wallet_id,
                status as u32,
                blockheight,
                deposit_txid,
                deposit_vout,
                amount,
                derivation_index,
            ],
        )
        .map_err(|e| DatabaseError(format!("Inserting vault: {}", e.to_string())))?;

        let vault_id = tx.last_insert_rowid();

        tx.execute(
            "INSERT INTO transactions (vault_id, type, tx) VALUES (?1, ?2, ?3)",
            params![
                vault_id,
                TransactionType::Deposit as u32,
                encode::serialize(&vault_tx.0)
            ],
        )
        .map_err(|e| DatabaseError(format!("Inserting vault transaction: {}", e.to_string())))?;

        Ok(())
    })
}

/// Mark an active vault as being in 'unvaulting' state
pub fn db_unvault_deposit(
    db_path: &PathBuf,
    txid: Vec<u8>,
    vout: u32,
) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE vaults SET status = (?1) WHERE deposit_txid = (?2) AND deposit_vout = (?3) ",
            params![VaultStatus::Unvaulting as u32, txid, vout],
        )
        .map_err(|e| {
            DatabaseError(format!(
                "Updating vault transaction to 'unvaulting': {}",
                e.to_string()
            ))
        })?;

        Ok(())
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        config::{parse_config, Config},
        revaultd::RevaultD,
    };
    use std::{fs, path::PathBuf};

    fn dummy_datadir_path() -> PathBuf {
        let mut datadir_path = PathBuf::from(file!()).parent().unwrap().to_path_buf();
        datadir_path.push("../../test_data/datadir");
        datadir_path
    }

    // Delete everything but the config (just our main db for now)
    fn clear_datadir(datadir_path: &PathBuf) {
        let mut db_path = datadir_path.clone();
        db_path.push("revaultd.sqlite3");
        fs::remove_file(db_path).expect("Removing db path");
    }

    #[test]
    fn test_db_creation() {
        let datadir_path = dummy_datadir_path();
        let mut config_path = datadir_path.clone();
        config_path.push("config.toml");

        let config: Config = parse_config(Some(config_path)).expect("Parsing valid config file");
        let mut revaultd = RevaultD::from_config(config).expect("Creating state from config");
        // Tweak the datadir, or it'll create it at ~/.revault/
        revaultd.data_dir = datadir_path.clone();

        create_db(&mut revaultd).unwrap();
        // We can't create it twice
        create_db(&mut revaultd).unwrap_err();
        // The version is right
        check_db(&mut revaultd).unwrap();
        // But it would not open a database from the future!
        db_exec(&revaultd.db_file(), |tx| {
            tx.execute("UPDATE version SET version = (?1)", params![VERSION + 1])
                .unwrap();
            Ok(())
        })
        .unwrap();
        check_db(&mut revaultd).unwrap_err();

        clear_datadir(&datadir_path);
    }
}
