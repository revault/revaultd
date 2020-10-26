use crate::{
    database::{interface::*, schema::SCHEMA, DatabaseError, VERSION},
    revaultd::RevaultD,
};
use revault_tx::{miniscript::Descriptor, scripts::UnvaultDescriptor, scripts::VaultDescriptor};

use std::{
    convert::TryInto,
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

    db_exec(&revaultd.db_file(), |tx| {
        tx.execute_batch(&SCHEMA)
            .map_err(|e| DatabaseError(format!("Creating database: {}", e.to_string())))?;
        tx.execute(
            "INSERT INTO version (version) VALUES (?1)",
            params![VERSION],
        )
        .map_err(|e| DatabaseError(format!("Inserting version: {}", e.to_string())))?;
        tx.execute(
        "INSERT INTO wallets (timestamp, vault_descriptor, unvault_descriptor) VALUES (?1, ?2, ?3)",
        params![timestamp, vault_descriptor, unvault_descriptor],
        )
        .map_err(|e| DatabaseError(format!("Inserting wallet: {}", e.to_string())))?;

        Ok(())
    })
}

// Called on startup to check database integrity and populate Miniscript descriptors
fn check_db(revaultd: &mut RevaultD) -> Result<(), DatabaseError> {
    let db_path = revaultd.db_file();
    // Check if their database is not from the future.
    // We'll eventually do migration here if version < VERSION, but be strict until then.
    let version = db_version(&db_path)?;
    if version != VERSION {
        return Err(DatabaseError(format!(
            "Unexpected database version: got '{}', expected '{}'",
            version, VERSION
        )));
    }

    let wallet = db_wallet(&db_path)?;
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

    check_db(revaultd)?;

    Ok(())
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
