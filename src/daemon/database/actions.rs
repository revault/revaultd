use crate::{
    database::{
        interface::*,
        schema::{TransactionType, SCHEMA},
        DatabaseError, DB_VERSION,
    },
    revaultd::{BlockchainTip, RevaultD, VaultStatus},
};
use revault_tx::{
    bitcoin::{util::bip32::ChildNumber, Amount, OutPoint},
    miniscript::Descriptor,
    scripts::{UnvaultDescriptor, VaultDescriptor},
    transactions::{
        CancelTransaction, EmergencyTransaction, RevaultTransaction, UnvaultEmergencyTransaction,
    },
};

use std::{
    convert::TryInto,
    fs,
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

// Create the db file with RW permissions only for the user
fn create_db_file(db_path: &PathBuf) -> Result<(), std::io::Error> {
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
    // FIXME: migrate to next rusqlite for u64!! https://github.com/rusqlite/rusqlite/pull/826

    let db_path = revaultd.db_file();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| timestamp_to_u32(dur.as_secs()))
        .map_err(|e| DatabaseError(format!("Computing time since epoch: {}", e.to_string())))?;
    let vault_descriptor = revaultd.vault_descriptor.0.to_string();
    let unvault_descriptor = revaultd.unvault_descriptor.0.to_string();
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
            "INSERT INTO wallets (timestamp, vault_descriptor, unvault_descriptor,\
            our_manager_xpub, our_stakeholder_xpub, deposit_derivation_index) \
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                timestamp,
                vault_descriptor,
                unvault_descriptor,
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

    // Check if their database is not from the future.
    // We'll eventually do migration here if version < VERSION, but be strict until then.
    let version = db_version(&db_path)?;
    if version != DB_VERSION {
        return Err(DatabaseError(format!(
            "Unexpected database version: got '{}', expected '{}'",
            version, DB_VERSION
        )));
    }

    let db_net = db_network(&db_path)?;
    if db_net != revaultd.bitcoind_config.network {
        return Err(DatabaseError(format!(
            "Invalid network. Database is on '{}' but config says '{}'.",
            db_net, revaultd.bitcoind_config.network
        )));
    }

    Ok(())
}

// Called on startup to populate our cache from the database
fn state_from_db(revaultd: &mut RevaultD) -> Result<(), DatabaseError> {
    let db_path = revaultd.db_file();
    let wallet = db_wallet(&db_path)?;

    revaultd.tip = Some(db_tip(&db_path)?);

    //FIXME: Use the Abstract Miniscript policy to check the policies described in the
    // config files are equivalent to the miniscript in the db.
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
    // Of course, it's no good... Miniscript on bitcoind soon :tm:
    // FIXME: in the meantime, reversed gap limit?
    let raw_index: u32 = revaultd.current_unused_index.into();
    (0..raw_index + revaultd.gap_limit()).for_each(|i| {
        // FIXME: this should fail instead of creating a hardened index
        let index = ChildNumber::from(i);
        revaultd.derivation_index_map.insert(
            revaultd
                .vault_descriptor
                .derive(index)
                .0
                .address(revaultd.bitcoind_config.network, revaultd.xpub_ctx())
                .expect("vault_descriptor is a wsh")
                .script_pubkey(),
            index,
        );
    });
    revaultd.wallet_id = Some(wallet.id);

    // TODO: update vaults-that-are-not-in-deposit-state cache from the database

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

/// Called by the bitcoind thread as we poll `getblockcount`
pub fn db_update_tip(db_path: &PathBuf, tip: BlockchainTip) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE tip SET blockheight = (?1), blockhash = (?2)",
            params![tip.height, tip.hash.to_vec()],
        )
        .map_err(|e| DatabaseError(format!("Inserting new tip: {}", e.to_string())))?;

        Ok(())
    })
}

pub fn db_update_deposit_index(
    db_path: &PathBuf,
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
pub fn db_insert_new_vault(
    db_path: &PathBuf,
    wallet_id: u32,
    status: &VaultStatus,
    blockheight: u32,
    deposit_outpoint: &OutPoint,
    amount: &Amount,
    derivation_index: ChildNumber,
) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        let derivation_index: u32 = derivation_index.into();
        tx.execute(
            "INSERT INTO vaults (wallet_id, status, blockheight, deposit_txid, \
             deposit_vout, amount, derivation_index) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                wallet_id,
                *status as u32,
                blockheight,
                deposit_outpoint.txid.to_vec(),
                deposit_outpoint.vout,
                amount.as_sat() as u32, // FIXME: update to next rusqlite!!
                derivation_index,
            ],
        )
        .map_err(|e| DatabaseError(format!("Inserting vault: {}", e.to_string())))?;

        Ok(())
    })
}

/// Mark an unconfirmed deposit as being in 'Funded' state (confirmed)
pub fn db_confirm_deposit(
    db_path: &PathBuf,
    outpoint: &OutPoint,
    blockheight: u32,
) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE vaults SET status = (?1), blockheight = (?2) WHERE deposit_txid = (?3) \
             AND deposit_vout = (?4) ",
            params![
                VaultStatus::Funded as u32,
                blockheight,
                outpoint.txid.to_vec(),
                outpoint.vout
            ],
        )
        .map_err(|e| DatabaseError(format!("Updating vault to 'funded': {}", e.to_string())))?;

        Ok(())
    })
}

/// Mark an active vault as being in 'unvaulting' state
pub fn db_unvault_deposit(db_path: &PathBuf, outpoint: &OutPoint) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE vaults SET status = (?1) WHERE deposit_txid = (?2) AND deposit_vout = (?3) ",
            params![
                VaultStatus::Unvaulting as u32,
                outpoint.txid.to_vec(),
                outpoint.vout
            ],
        )
        .map_err(|e| DatabaseError(format!("Updating vault to 'unvaulting': {}", e.to_string())))?;

        Ok(())
    })
}

// Store a set of pre-signed transactions in the `transactions` table for the given vault_id.
// The transactions MUST ALL be finalized before being passed.
// Bitcoin transactions are inserted in a single database transaction (atomically).
macro_rules! db_store_transactions {
    ($db_path:ident, $vault_id:ident, [$( $tx:ident ),*]) => {
        db_exec($db_path, |db_tx| {
            $(
                // We already do these check in revault_tx's finalize, so only double check on Debug
                #[cfg(debug_assertions)]
                {
                    for i in 0..$tx.inner_tx().inputs.len() {
                        $tx.verify_input(i)?;
                    }
                }
                let tx_type = TransactionType::from(&$tx);
                db_tx
                    .execute(
                        "INSERT INTO transactions (vault_id, type, psbt) VALUES (?1, ?2, ?3)",
                        params![$vault_id, tx_type as u32, $tx.as_psbt_serialized()?],
                    )
                    .map_err(|e| {
                        DatabaseError(format!("Inserting psbt in vault '{}': {}", $vault_id, e))
                    })?;
            )*

            Ok(())
        })
    };
}

/// Store the *fully-signed* revocation transactions for this vault in db.
pub fn db_store_revocation_txs(
    db_path: &PathBuf,
    vault_id: u32,
    cancel: CancelTransaction,
    emer: EmergencyTransaction,
    unvault_emer: UnvaultEmergencyTransaction,
) -> Result<(), DatabaseError> {
    db_store_transactions!(db_path, vault_id, [cancel, emer, unvault_emer])
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{database::schema::RevaultTx, revaultd::RevaultD};
    use common::config::Config;
    use revault_tx::{
        bitcoin::{Network, OutPoint},
        transactions::{CancelTransaction, EmergencyTransaction, UnvaultEmergencyTransaction},
    };

    use std::{fs, path::PathBuf};

    fn dummy_revaultd() -> RevaultD {
        let mut datadir_path = PathBuf::from(file!()).parent().unwrap().to_path_buf();
        datadir_path.push("../../../test_data/datadir");
        let mut config_path = datadir_path.clone();
        config_path.push("config.toml");

        let config = Config::from_file(Some(config_path)).expect("Parsing valid config file");
        let mut revaultd = RevaultD::from_config(config).expect("Creating state from config");
        // Tweak the datadir, or it'll create it at ~/.revault/
        revaultd.data_dir = datadir_path.clone();

        revaultd
    }

    // Delete everything but the config (just our main db for now)
    fn clear_datadir(datadir_path: &PathBuf) {
        let mut db_path = datadir_path.clone();
        db_path.push("revaultd.sqlite3");
        fs::remove_file(db_path).expect("Removing db path");
    }

    fn test_db_creation() {
        let mut revaultd = dummy_revaultd();

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

        clear_datadir(&revaultd.data_dir);
    }

    fn test_db_fetch_deposits() {
        let mut revaultd = dummy_revaultd();
        let db_path = revaultd.db_file();

        setup_db(&mut revaultd).unwrap();

        // Let's insert two new deposits and an unvault

        let wallet_id = 1;
        let status = VaultStatus::Funded;
        let blockheight = 100;
        let first_deposit_outpoint = OutPoint::from_str(
            "4d799e993665149109682555ba482b386aea03c5dbd62c059b48eb8f40f2f040:0",
        )
        .unwrap();
        let amount = Amount::from_sat(123456);
        let derivation_index = ChildNumber::from(3);
        db_insert_new_vault(
            &db_path,
            wallet_id,
            &status,
            blockheight,
            &first_deposit_outpoint,
            &amount,
            derivation_index,
        )
        .unwrap();

        let wallet_id = 1;
        let status = VaultStatus::Funded;
        let blockheight = 150;
        let second_deposit_outpoint = OutPoint::from_str(
            "e56808d17a866de5a1d0874894c84a759a7cabc8763694966cc6423f4c597a7f:0",
        )
        .unwrap();
        let amount = Amount::from_sat(456789);
        let derivation_index = ChildNumber::from(12);
        db_insert_new_vault(
            &db_path,
            wallet_id,
            &status,
            blockheight,
            &second_deposit_outpoint,
            &amount,
            derivation_index,
        )
        .unwrap();

        let wallet_id = 1;
        let status = VaultStatus::Unvaulting;
        let blockheight = 122;
        let third_deposit_outpoint = OutPoint::from_str(
            "616efc37747c8cafc2f99692177a5400bad81b671d8d35ffa347d84b246e9a83:0",
        )
        .unwrap();
        let amount = Amount::from_sat(428000);
        let derivation_index = ChildNumber::from(15);
        db_insert_new_vault(
            &db_path,
            wallet_id,
            &status,
            blockheight,
            &third_deposit_outpoint,
            &amount,
            derivation_index,
        )
        .unwrap();

        // By the way, trying to insert for an inexistant wallet will fail the
        // db constraint
        db_insert_new_vault(
            &db_path,
            wallet_id + 1,
            &status,
            blockheight,
            &third_deposit_outpoint,
            &amount,
            derivation_index,
        )
        .unwrap_err();

        // Now retrieve the deposits; there must be the first ones but not the
        // unvaulting one.
        let deposit_outpoints: Vec<OutPoint> = db_deposits(&db_path)
            .unwrap()
            .into_iter()
            .map(|db_vault| db_vault.deposit_outpoint)
            .collect();
        assert_eq!(deposit_outpoints.len(), 2);
        assert!(deposit_outpoints.contains(&first_deposit_outpoint));
        assert!(deposit_outpoints.contains(&second_deposit_outpoint));
        assert!(!deposit_outpoints.contains(&third_deposit_outpoint));

        // Now if we mark the first as being unvaulted we'll onlu fetch one
        db_unvault_deposit(&db_path, &first_deposit_outpoint).unwrap();
        let deposit_outpoints: Vec<OutPoint> = db_deposits(&db_path)
            .unwrap()
            .into_iter()
            .map(|db_vault| db_vault.deposit_outpoint)
            .collect();
        assert_eq!(deposit_outpoints.len(), 1);
        assert!(!deposit_outpoints.contains(&first_deposit_outpoint));
        assert!(deposit_outpoints.contains(&second_deposit_outpoint));
        assert!(!deposit_outpoints.contains(&third_deposit_outpoint));

        clear_datadir(&revaultd.data_dir);
    }

    fn test_db_store_revocation_txs() {
        let mut revaultd = dummy_revaultd();
        let db_path = revaultd.db_file();

        setup_db(&mut revaultd).unwrap();

        // Let's insert a deposit
        let wallet_id = 1;
        let status = VaultStatus::Funded;
        let blockheight = 700000;
        let outpoint = OutPoint::from_str(
            "4d799e993665149109682555ba482b386aea03c5dbd62c059b48eb8f40f2f040:0",
        )
        .unwrap();
        let amount = Amount::from_sat(123456);
        let derivation_index = ChildNumber::from(33334);
        db_insert_new_vault(
            &db_path,
            wallet_id,
            &status,
            blockheight,
            &outpoint,
            &amount,
            derivation_index,
        )
        .unwrap();
        let db_vault = db_vault_by_deposit(&db_path, &outpoint).unwrap().unwrap();

        // We can store fully-signed revocation transactions
        let emer_tx = EmergencyTransaction::from_psbt_str("cHNidP8BAIcCAAAAArFynMjrSjRoYgTnYmTh/eya2EpPbOkYdSBK+YSepb5xAAAAAAD9////wwc1PjONWaQ6k8Ff89IO4tjDCOOdeuKikZ5sNkgcBEYAAAAAAP3///8B+GADAAAAAAAiACAc4QQhSEvVjup9r++li+ikFVLc95mFU+iGeCAU7wz5FQAAAAAAAQEriJQDAAAAAAAiACAc4QQhSEvVjup9r++li+ikFVLc95mFU+iGeCAU7wz5FQEI2gQARzBEAiBFBSzPW8a+GyGXrBOGyXX8kNRlI5AKoo6c96mQCnXR9gIgUqpeBYqszcnrS3/TQvGfgYRelf78CzSxlt/Jr5lLSNuBRzBEAiAFDfzvHQQtLTu3LDom1Uo4nt6I7xNr4qgIxLT1a459fAIgfpilxRE82/M2lSvo0EoNmoPt6FKrToAB7T3yITPSETyBR1IhAhwDjK9CjcFGN5YjIRrPavF2FnMnrTsMogehacoHKS0aIQP7X94RPdx3P6Qy0sJa7U6RmkPXIqGiDKtWciD/Ce7D4VKuAAEBH5rdAAAAAAAAFgAUaW37E5hUMCLu61U7VnB//VwedisBCGwCSDBFAiEAppnl4d5gkO3sKSCiJZyXm1n3V5Udr24cCj52BqwXpk8CIG0OaqU5d9oB3Ul7SLKBBpyGv0OuHIwhwieBXAOzZfzYASECqGQbqKq3ulO3U7oBBis9NheNk0Zhq3kGL4J5JA3lvu0AAA==").unwrap();
        let cancel_tx = CancelTransaction::from_psbt_str("cHNidP8BAIcCAAAAAuyFhupGoLqUKY8M4QpTeVaoxLw96bl+2UZqnjwjUkuPAAAAAAD9////wwc1PjONWaQ6k8Ff89IO4tjDCOOdeuKikZ5sNkgcBEYAAAAAAP3///8B0soCAAAAAAAiACAc4QQhSEvVjup9r++li+ikFVLc95mFU+iGeCAU7wz5FQAAAAAAAQErQA0DAAAAAAAiACAWHb8jPz1qlOOjBiB74iByuZvixegBDoMqf8KQ3yUBlwEI/YIBBkcwRAIgB00daH7aJ2LFYfQeuHwvj2m/kSzLTwi3DLc3QscJPU8CIB4f4V6EZ49ajsEMZy++NCMi8yOWUpBsyqtlgA7xVVkUgSED+1/eET3cdz+kMtLCWu1OkZpD1yKhogyrVnIg/wnuw+FHMEQCIFUSHXB+t/eHmIlQePYjdbGMRP+zMbg+mU6a4ygrWkfKAiBfnvJ/V4/GS9M7hywxtVg5gvSClNQmICsNau1TgSiy34EhAhwDjK9CjcFGN5YjIRrPavF2FnMnrTsMogehacoHKS0aAKshAwnCKhSjqfl9G5NEQhvawpcj9v8qBdFLFhW4zSJmXUyXrFGHZHapFMvTdVfBbYudE6mAVG9ipw3MjljBiKxrdqkUdWsiYLDcCQCwNrAIO/hjbwoUnYaIrGyTUodnUiEDa8fElGskCZLM6ODgIPKIOnXC54mzyTjJZqNomUnFxt8hAxLdF6uofuC5OH7yFErtmJOoryiWTe52F8UJsHp7hmJUUq8DwvwAsmgAAQEfmt0AAAAAAAAWABRpbfsTmFQwIu7rVTtWcH/9XB52KwEIbAJIMEUCIQC83pn82XF0nh/Wm+2nZvK7oWWfVUdP/5DOChi/3mdcvAIgEXGgP7TZSGUM7IB4J3HENmAuAqINtmaP2LDELvo9aQIBIQKoZBuoqre6U7dTugEGKz02F42TRmGreQYvgnkkDeW+7QABAUdSIQIcA4yvQo3BRjeWIyEaz2rxdhZzJ607DKIHoWnKByktGiED+1/eET3cdz+kMtLCWu1OkZpD1yKhogyrVnIg/wnuw+FSrgA=").unwrap();
        let unemer_tx = UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAeyFhupGoLqUKY8M4QpTeVaoxLw96bl+2UZqnjwjUkuPAAAAAAD9////AdLKAgAAAAAAIgAgHOEEIUhL1Y7qfa/vpYvopBVS3PeZhVPohnggFO8M+RUAAAAAAAEBK0ANAwAAAAAAIgAgFh2/Iz89apTjowYge+Igcrmb4sXoAQ6DKn/CkN8lAZcBCP2CAQZHMEQCIAdNHWh+2idixWH0Hrh8L49pv5Esy08Itwy3N0LHCT1PAiAeH+FehGePWo7BDGcvvjQjIvMjllKQbMqrZYAO8VVZFIEhA/tf3hE93Hc/pDLSwlrtTpGaQ9cioaIMq1ZyIP8J7sPhRzBEAiBVEh1wfrf3h5iJUHj2I3WxjET/szG4PplOmuMoK1pHygIgX57yf1ePxkvTO4csMbVYOYL0gpTUJiArDWrtU4Eost+BIQIcA4yvQo3BRjeWIyEaz2rxdhZzJ607DKIHoWnKByktGgCrIQMJwioUo6n5fRuTREIb2sKXI/b/KgXRSxYVuM0iZl1Ml6xRh2R2qRTL03VXwW2LnROpgFRvYqcNzI5YwYisa3apFHVrImCw3AkAsDawCDv4Y28KFJ2GiKxsk1KHZ1IhA2vHxJRrJAmSzOjg4CDyiDp1wueJs8k4yWajaJlJxcbfIQMS3RerqH7guTh+8hRK7ZiTqK8olk3udhfFCbB6e4ZiVFKvA8L8ALJoAAA=").unwrap();
        db_store_revocation_txs(
            &db_path,
            db_vault.id,
            cancel_tx.clone(),
            emer_tx.clone(),
            unemer_tx.clone(),
        )
        .unwrap();

        // Sanity check we can query them now
        let db_txs: Vec<RevaultTx> = db_transactions(&db_path, db_vault.id, &[])
            .unwrap()
            .into_iter()
            .map(|x| x.psbt)
            .collect();
        assert!(db_txs.contains(&RevaultTx::Emergency(emer_tx.clone())));
        assert!(db_txs.contains(&RevaultTx::Cancel(cancel_tx.clone())));
        assert!(db_txs.contains(&RevaultTx::UnvaultEmergency(unemer_tx.clone())));

        let db_txs: Vec<RevaultTx> =
            db_transactions(&db_path, db_vault.id, &[TransactionType::Emergency])
                .unwrap()
                .into_iter()
                .map(|x| x.psbt)
                .collect();
        assert!(db_txs.contains(&RevaultTx::Emergency(emer_tx.clone())));
        assert!(!db_txs.contains(&RevaultTx::Cancel(cancel_tx.clone())));
        assert!(!db_txs.contains(&RevaultTx::UnvaultEmergency(unemer_tx.clone())));

        let db_txs: Vec<RevaultTx> = db_transactions(
            &db_path,
            db_vault.id,
            &[TransactionType::UnvaultEmergency, TransactionType::Cancel],
        )
        .unwrap()
        .into_iter()
        .map(|x| x.psbt)
        .collect();
        assert!(!db_txs.contains(&RevaultTx::Emergency(emer_tx.clone())));
        assert!(db_txs.contains(&RevaultTx::Cancel(cancel_tx.clone())));
        assert!(db_txs.contains(&RevaultTx::UnvaultEmergency(unemer_tx.clone())));

        clear_datadir(&revaultd.data_dir);
    }

    // We disabled #[test] for the above, as they may erase the db concurrently.
    // Instead, run them sequentially.
    #[test]
    fn db_sequential_test_runner() {
        test_db_creation();
        test_db_fetch_deposits();
        test_db_store_revocation_txs();
    }
}
