use crate::{
    database::{interface::*, schema::SCHEMA, DatabaseError, DB_VERSION},
    revaultd::{CachedVault, RevaultD, VaultStatus},
};
use revault_tx::{
    bitcoin::{consensus::encode, util::bip32::ChildNumber, BlockHash, TxOut},
    miniscript::Descriptor,
    scripts::{UnvaultDescriptor, VaultDescriptor},
    transactions::VaultTransaction,
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
    let db_path = revaultd.db_file();
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
                revaultd.current_unused_index,
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
    // Of course, it's no good... Miniscript on bitcoind soon :tm:
    // FIXME: in the meantime, reversed gap limit?
    (0..revaultd.current_unused_index + revaultd.gap_limit()).for_each(|i| {
        revaultd.derivation_index_map.insert(
            revaultd
                .vault_descriptor
                .derive(ChildNumber::from(i))
                .0
                .address(revaultd.bitcoind_config.network)
                .expect("vault_descriptor is a wsh")
                .script_pubkey(),
            i,
        );
    });
    revaultd.wallet_id = Some(wallet.id);

    for vault in db_deposits(&db_path)?.into_iter() {
        let deposit_script_pubkey = revaultd
            .vault_address(vault.derivation_index.into())
            .script_pubkey();
        revaultd.vaults.insert(
            vault.deposit_outpoint,
            CachedVault {
                txo: TxOut {
                    value: vault.amount.as_sat(),
                    script_pubkey: deposit_script_pubkey,
                },
                status: vault.status,
            },
        );
        log::trace!("Loaded deposit '{}' from db", vault.deposit_outpoint);
    }

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
pub fn db_update_tip(db_path: &PathBuf, tip: (u32, BlockHash)) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE tip SET blockheight = (?1), blockhash = (?2)",
            params![tip.0, tip.1.to_vec()],
        )
        .map_err(|e| DatabaseError(format!("Inserting new tip: {}", e.to_string())))?;

        Ok(())
    })
}

pub fn db_increase_deposit_index(
    db_path: &PathBuf,
    current_index: u32,
) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE wallets SET deposit_derivation_index = (?1)",
            params![current_index + 1],
        )
        .map_err(|e| DatabaseError(format!("Inserting new tip: {}", e.to_string())))?;

        Ok(())
    })
}

/// Insert a new deposit in the database (atomically record both the vault and the deposit
/// transaction).
pub fn db_insert_new_vault(
    db_path: &PathBuf,
    wallet_id: u32,
    status: VaultStatus,
    blockheight: u32,
    // FIXME: TYYYYYYPES
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
    use crate::revaultd::RevaultD;
    use common::config::Config;
    use revault_tx::bitcoin::{hashes::hex::FromHex, Network, OutPoint};

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
        let amount = 123456;
        let derivation_index = 3;
        let vault_tx = VaultTransaction(encode::deserialize(&Vec::from_hex("01000000018d02f09e91dee22f854c1f4d5da6c63b424ae61c403a9ca649bc7232b6f52e780a0000006a47304402206badd975c2d9fc3873ef0bf7eded79fd8b2fb04d94eb403fb00fd2da4ce6f10a02202d508ffca05ec2da4bd7aca34f9319905f62b349fb46b7791dc3458125baeaab012102c8431929d7493a7feb0e397c88a6a1651f1709cb2b420b55e7d732ebc31041e9ffffffff0b1027000000000000232102c8431929d7493a7feb0e397c88a6a1651f1709cb2b420b55e7d732ebc31041e9ac1027000000000000232102c8431929d7493a7feb0e397c88a6a1651f1709cb2b420b55e7d732ebc31041e9ac1027000000000000232102c8431929d7493a7feb0e397c88a6a1651f1709cb2b420b55e7d732ebc31041e9ac1027000000000000232102c8431929d7493a7feb0e397c88a6a1651f1709cb2b420b55e7d732ebc31041e9ac1027000000000000232102c8431929d7493a7feb0e397c88a6a1651f1709cb2b420b55e7d732ebc31041e9ac1027000000000000232102c8431929d7493a7feb0e397c88a6a1651f1709cb2b420b55e7d732ebc31041e9ac1027000000000000232102c8431929d7493a7feb0e397c88a6a1651f1709cb2b420b55e7d732ebc31041e9ac1027000000000000232102c8431929d7493a7feb0e397c88a6a1651f1709cb2b420b55e7d732ebc31041e9ac1027000000000000232102c8431929d7493a7feb0e397c88a6a1651f1709cb2b420b55e7d732ebc31041e9ac1027000000000000232102c8431929d7493a7feb0e397c88a6a1651f1709cb2b420b55e7d732ebc31041e9acc0106902000000001976a9143e3387cc0f659ac5d9e137a5641d73606a0172ee88ac00000000").unwrap()).unwrap());
        db_insert_new_vault(
            &db_path,
            wallet_id,
            status,
            blockheight,
            first_deposit_outpoint.txid.to_vec(),
            first_deposit_outpoint.vout,
            amount,
            derivation_index,
            vault_tx,
        )
        .unwrap();

        let wallet_id = 1;
        let status = VaultStatus::Funded;
        let blockheight = 150;
        let second_deposit_outpoint = OutPoint::from_str(
            "e56808d17a866de5a1d0874894c84a759a7cabc8763694966cc6423f4c597a7f:0",
        )
        .unwrap();
        let amount = 6398;
        let derivation_index = 12;
        let vault_tx = VaultTransaction(encode::deserialize(&Vec::from_hex("020000000001013337e39b850fadd0264673e9d70ecae8a2dfa6f373571de0fafce4dbae020bf901000000171600141aa8b21429f9d1fabb880ab0c3ff5c4004d3a4a0feffffff027d1080600500000017a914b7d46105439a4cb89740eecb2cd8071b86097a0087eed013000000000017a914f54db0418a675090f70b5ab57b1fa7de4d1f3b7c87024730440220228f1de3c2e036bd255b2471003a9eedc1f53ce0c1b2b18b83cdc15c1dda231c022036287b99b302e77c394b1cf5862e00b834c538413da7ef1f7971aba3d8908b7e01210258ac070e3a2653dbb908d703223d09f6d06ef7145775dd9a8028fd708f7b600a4bcd1c00").unwrap()).unwrap());
        db_insert_new_vault(
            &db_path,
            wallet_id,
            status,
            blockheight,
            second_deposit_outpoint.txid.to_vec(),
            second_deposit_outpoint.vout,
            amount,
            derivation_index,
            vault_tx,
        )
        .unwrap();

        let wallet_id = 1;
        let status = VaultStatus::Unvaulting;
        let blockheight = 122;
        let third_deposit_outpoint = OutPoint::from_str(
            "616efc37747c8cafc2f99692177a5400bad81b671d8d35ffa347d84b246e9a83:0",
        )
        .unwrap();
        let amount = 428000;
        let derivation_index = 15;
        let vault_tx = VaultTransaction(encode::deserialize(&Vec::from_hex("01000000000105af45796fb9a23d6f8da5a07c454ab7f7389d44fc3ee9d8ae9206c37857859a410500000000ffffffff09654613689cfd335e27586ad6d63f9f656b66e1c97437d6d7881421484a75540200000000ffffffff50cb13707cc02bbf6c748cc7e52ee4f67fd3849074cf38c0ce29cde3922fe1660400000000ffffffff6058513de33d705fa853f02fbaa90c773fe3d770738fb42c12cd0d5aa7c820ad0400000000ffffffffa83604a33de69e02dd93144f340c00553946f4758889dccf49231b6122c36ace0200000000ffffffff0540420f0000000000160014338c75df6ab88f0017c97eae7f37b067b39ddddc40420f000000000016001448052f93aa57c3ba797a250acc27cd207d18346d40420f000000000016001454a5b3e09aa2e783bca90a9522c02189ef002da340420f00000000001600149657de4bd76ee8ef5c5cf855e1298fa4104d9e9940420f0000000000160014c86321f7131e03400c7a4f9c82f33994bd072ab402473044022077a35282dfce498cadd378dadd77fb1aa734d6ed5df9f6d60b28ce1a6a9f5bc4022031f69ba6e35f182600e2dbf2494fe9da3f34c784700836c4012c10a207e4c6f30121032ae7ed94fc714d9e883c36dfa1804b9cb4d64f64540e670e4c55c2a29049ee4f02483045022100b7fadf8bfc0b50b07f54f876445bdc7fab830f9696a372d04c6b5f045021fac90220059bade2d8cddd77eb81f653e123e5db72df41da2e9e85cb81b2f5a5bc2c2aab012102c254b246037d7b979072eee4b1d1536aadb8a64cd00eb12246ad8bff590cdc3f02473044022072105afbc95b3e37d0b779aaae9b6b77c2ef18b6711297f76fc3b67e2c3025f402204c73be24853a7114a37a388d79c269b151f0cf67f4acaec5581612786618511101210387b70c65d4f5068589952985e6d8c43c005127801a713931564cf1702a21cdb90247304402206d765fb6f07a9becb8a43cf64d81eef995a5d66d2cb222264f07c80b54aef4a002206b644922dc37189c867cc0c9e6cdf2fd266511b0038a1c0ed82a0f07c2178d860121033f38c01b0ed6c04d2c7e9636ededd92de79624f31a7b29c8d857620ddf2f0765024730440220381d3fe5a83da00a173fe6f137f015345798cd820590180136ba173ae65fabef02203c54de5d5ffebaa0a04e88152bdded6cd5319f05024c3dc860898568810ca54b01210294652741695124b2bafc07da3fe6f16b8175e8ba6e48299a2360af0650d3bc5100000000").unwrap()).unwrap());
        db_insert_new_vault(
            &db_path,
            wallet_id,
            status,
            blockheight,
            third_deposit_outpoint.txid.to_vec(),
            third_deposit_outpoint.vout,
            amount,
            derivation_index,
            vault_tx.clone(),
        )
        .unwrap();

        // By the way, trying to insert for an inexistant wallet will fail the
        // db constraint
        db_insert_new_vault(
            &db_path,
            wallet_id + 1,
            status,
            blockheight,
            third_deposit_outpoint.txid.to_vec(),
            third_deposit_outpoint.vout,
            amount,
            derivation_index,
            vault_tx,
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
        db_unvault_deposit(
            &db_path,
            first_deposit_outpoint.txid.to_vec(),
            first_deposit_outpoint.vout,
        )
        .unwrap();
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

    // We disabled #[test] for the above, as they may erase the db concurrently.
    // Instead, run them sequentially.
    #[test]
    fn db_sequential_test_runner() {
        test_db_creation();
        test_db_fetch_deposits();
    }
}
