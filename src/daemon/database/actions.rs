use crate::{
    database::{
        interface::*,
        schema::{DbTransaction, RevaultTx, TransactionType, SCHEMA},
        DatabaseError, DB_VERSION,
    },
    revaultd::{BlockchainTip, RevaultD, VaultStatus},
};
use revault_tx::{
    bitcoin::{secp256k1, util::bip32::ChildNumber, Amount, OutPoint, PublicKey as BitcoinPubKey},
    miniscript::Descriptor,
    scripts::{DepositDescriptor, UnvaultDescriptor},
    transactions::{
        CancelTransaction, EmergencyTransaction, RevaultTransaction, UnvaultEmergencyTransaction,
        UnvaultTransaction,
    },
};

use std::{
    collections::BTreeMap,
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
    let deposit_descriptor = revaultd.deposit_descriptor.0.to_string();
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
            "INSERT INTO wallets (timestamp, deposit_descriptor, unvault_descriptor,\
            our_manager_xpub, our_stakeholder_xpub, deposit_derivation_index) \
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                timestamp,
                deposit_descriptor,
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
    revaultd.deposit_descriptor = DepositDescriptor(
        Descriptor::from_str(&wallet.deposit_descriptor).map_err(|e| {
            DatabaseError(format!(
                "Interpreting database vault descriptor '{}': {}",
                wallet.deposit_descriptor,
                e.to_string()
            ))
        })?,
    );
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
                .deposit_descriptor
                .derive(index)
                .0
                .address(revaultd.bitcoind_config.network, revaultd.xpub_ctx())
                .expect("deposit_descriptor is a wsh")
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
pub fn db_update_tip(db_path: &PathBuf, tip: &BlockchainTip) -> Result<(), DatabaseError> {
    db_exec(db_path, |db_tx| db_update_tip_dbtx(db_tx, tip))
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
pub fn db_insert_new_unconfirmed_vault(
    db_path: &PathBuf,
    wallet_id: u32,
    status: &VaultStatus,
    deposit_outpoint: &OutPoint,
    amount: &Amount,
    derivation_index: ChildNumber,
    received_at: u32,
) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        let derivation_index: u32 = derivation_index.into();
        tx.execute(
            "INSERT INTO vaults (wallet_id, status, blockheight, deposit_txid, \
             deposit_vout, amount, derivation_index, received_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                wallet_id,
                *status as u32,
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
                assert_eq!($tx.inner_tx().inputs.len(), 1);
                // They must be freshly generated..
                assert!($tx.inner_tx().inputs[0].partial_sigs.is_empty());

                let tx_type = TransactionType::from($tx);
                $db_tx
                    .execute(
                        "INSERT INTO presigned_transactions (vault_id, type, psbt, fullysigned) VALUES (?1, ?2, ?3 , ?4)",
                        params![$vault_id, tx_type as u32, $tx.as_psbt_serialized(), false as u32],
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
    db_path: &PathBuf,
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

/// Drop all presigned transactions for a vault, and mark it as unconfirmed. The opposite of
/// [db_confirm_deposit].
pub fn db_unconfirm_deposit_dbtx(
    db_tx: &rusqlite::Transaction,
    vault_id: u32,
) -> Result<(), DatabaseError> {
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

/// Mark an active vault as being in 'unvaulting' state
pub fn db_unvault_deposit(db_path: &PathBuf, outpoint: &OutPoint) -> Result<(), DatabaseError> {
    db_exec(db_path, |tx| {
        tx.execute(
            "UPDATE vaults SET status = (?1), updated_at = strftime('%s','now') WHERE deposit_txid = (?2) AND deposit_vout = (?3) ",
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

fn revault_tx_merge_sigs(
    tx: &mut impl RevaultTransaction,
    sigs: BTreeMap<BitcoinPubKey, Vec<u8>>,
    secp_ctx: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
) -> Result<(bool, Vec<u8>), DatabaseError> {
    tx.inner_tx_mut().inputs[0].partial_sigs.extend(sigs);
    let fully_signed = tx.finalize(secp_ctx).is_ok();
    let raw_psbt = tx.as_psbt_serialized();
    Ok((fully_signed, raw_psbt))
}

/// Update the presigned transaction in-db. If the transaction is valid and no more revocation
/// transactions are remaining unsigned for this vault, it will update the vault status as well in
/// the same database transaction.
pub fn db_update_presigned_tx(
    db_path: &PathBuf,
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
                    "SELECT * FROM presigned_transactions WHERE fullysigned = 0 AND type != (?1)",
                )?
                // All presigned transactions but the Unvault are revocation txs
                .query(params![TransactionType::Unvault as u32])?
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::revaultd::RevaultD;
    use common::config::Config;
    use revault_tx::{
        bitcoin::{Network, OutPoint, PublicKey},
        transactions::{CancelTransaction, EmergencyTransaction, UnvaultEmergencyTransaction},
    };

    use std::{fs, path::PathBuf, str::FromStr};

    fn dummy_revaultd() -> RevaultD {
        let mut datadir_path = PathBuf::from(file!()).parent().unwrap().to_path_buf();
        datadir_path.push("../../../test_data/datadir");
        let mut config_path = datadir_path.clone();
        config_path.push("config.toml");
        let mut db_path = datadir_path.clone();
        db_path.push("revaultd.sqlite3");

        let config = Config::from_file(Some(config_path)).expect("Parsing valid config file");
        let mut revaultd = RevaultD::from_config(config).expect("Creating state from config");
        // Tweak the datadir, or it'll create it at ~/.revault/
        revaultd.data_dir = datadir_path.clone();

        // Just in case there is a leftover from a previous run
        fs::remove_file(db_path).unwrap_or_else(|_| {
            eprintln!("No leftover");
        });

        revaultd
    }

    // Delete everything but the config (just our main db for now)
    fn clear_datadir(datadir_path: &PathBuf) {
        let mut db_path = datadir_path.clone();
        db_path.push("revaultd.sqlite3");
        fs::remove_file(db_path).expect("Removing db path");
    }

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
        tx.inner_tx_mut().inputs[input_index]
            .partial_sigs
            .insert(pubkey, sig);
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
            &status,
            &first_deposit_outpoint,
            &amount,
            derivation_index,
            received_at,
        )
        .unwrap();

        let wallet_id = 1;
        let status = VaultStatus::Funded;
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
            &status,
            &second_deposit_outpoint,
            &amount,
            derivation_index,
            received_at,
        )
        .unwrap();

        let wallet_id = 1;
        let status = VaultStatus::Unvaulting;
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
            &status,
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
            &status,
            &third_deposit_outpoint,
            &amount,
            derivation_index,
            received_at,
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

    fn test_db_store_presigned_txs() {
        let mut revaultd = dummy_revaultd();
        let db_path = revaultd.db_file();

        setup_db(&mut revaultd).unwrap();

        // Let's insert a deposit
        let wallet_id = 1;
        let status = VaultStatus::Funded;
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
            &status,
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
        let fresh_unemer_tx = UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAARoHs0elD2sCfWV4+b7PH3aRA+BkRVNf3m/P+Epjx2fNAAAAAAD9////AdLKAgAAAAAAIgAgB6abzQJ4vo5CO9XW3r3JnNumTwlpQbZm9FVICsLHPYQAAAAAAAEBK0ANAwAAAAAAIgAglEs6phQpv+twnAQSdjDvAEic65OtUIijeePBzAAqr50BAwSBAAAAAQWrIQO4lrAuffeRLuEEuwp2hAMZIPmqaHMTUySM3OwdA2hIW6xRh2R2qRTflccImFIy5NdTqwPuPZFB7g1pvYisa3apFOQxXoLeQv/aDFfav/l6YnYRKt+1iKxsk1KHZ1IhA32Q1DEqQ/kUP2MvQYFW46RCexZ5aYk17Arhp01th+37IQNrXQtfIXQdrv+RyyHLilJsb4ujlUMddG9X2jYkeXiWoFKvA3nxALJoAAA=").unwrap();
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

        // Sanity check we can add sigs to them now
        let (tx_db_id, stored_cancel_tx) = db_cancel_transaction(&db_path, db_vault.id).unwrap();
        assert_eq!(stored_cancel_tx.inner_tx().inputs[0].partial_sigs.len(), 0);
        let mut cancel_tx = fresh_cancel_tx.clone();
        revault_tx_add_dummy_sig(&mut cancel_tx, 0);
        db_update_presigned_tx(
            &db_path,
            db_vault.id,
            tx_db_id,
            cancel_tx.inner_tx().inputs[0].partial_sigs.clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();
        let (_, stored_cancel_tx) = db_cancel_transaction(&db_path, db_vault.id).unwrap();
        assert_eq!(stored_cancel_tx.inner_tx().inputs[0].partial_sigs.len(), 1);

        let (tx_db_id, stored_emer_tx) = db_emer_transaction(&db_path, db_vault.id).unwrap();
        assert_eq!(stored_emer_tx.inner_tx().inputs[0].partial_sigs.len(), 0);
        let mut emer_tx = fresh_emer_tx.clone();
        revault_tx_add_dummy_sig(&mut emer_tx, 0);
        db_update_presigned_tx(
            &db_path,
            db_vault.id,
            tx_db_id,
            emer_tx.inner_tx().inputs[0].partial_sigs.clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();
        let (_, stored_emer_tx) = db_emer_transaction(&db_path, db_vault.id).unwrap();
        assert_eq!(stored_emer_tx.inner_tx().inputs[0].partial_sigs.len(), 1);

        let (tx_db_id, stored_unemer_tx) =
            db_unvault_emer_transaction(&db_path, db_vault.id).unwrap();
        assert_eq!(stored_unemer_tx.inner_tx().inputs[0].partial_sigs.len(), 0);
        let mut unemer_tx = fresh_unemer_tx.clone();
        revault_tx_add_dummy_sig(&mut unemer_tx, 0);
        db_update_presigned_tx(
            &db_path,
            db_vault.id,
            tx_db_id,
            unemer_tx.inner_tx().inputs[0].partial_sigs.clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();
        let (_, stored_unemer_tx) = db_unvault_emer_transaction(&db_path, db_vault.id).unwrap();
        assert_eq!(stored_unemer_tx.inner_tx().inputs[0].partial_sigs.len(), 1);

        let (tx_db_id, stored_unvault_tx) = db_unvault_transaction(&db_path, db_vault.id).unwrap();
        assert_eq!(stored_unvault_tx.inner_tx().inputs[0].partial_sigs.len(), 0);
        let mut unvault_tx = fresh_unvault_tx.clone();
        revault_tx_add_dummy_sig(&mut unvault_tx, 0);
        db_update_presigned_tx(
            &db_path,
            db_vault.id,
            tx_db_id,
            unvault_tx.inner_tx().inputs[0].partial_sigs.clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();
        let (_, stored_unvault_tx) = db_unvault_transaction(&db_path, db_vault.id).unwrap();
        assert_eq!(stored_unvault_tx.inner_tx().inputs[0].partial_sigs.len(), 1);

        // They can also be queried
        assert_eq!(
            emer_tx,
            db_emer_transaction(&db_path, db_vault.id).unwrap().1
        );
        assert_eq!(
            cancel_tx,
            db_cancel_transaction(&db_path, db_vault.id).unwrap().1
        );
        assert_eq!(
            unemer_tx,
            db_unvault_emer_transaction(&db_path, db_vault.id)
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
        db_emer_transaction(&db_path, db_vault.id).unwrap_err();
        db_cancel_transaction(&db_path, db_vault.id).unwrap_err();
        db_unvault_emer_transaction(&db_path, db_vault.id).unwrap_err();
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

        clear_datadir(&revaultd.data_dir);
    }

    // We disabled #[test] for the above, as they may erase the db concurrently.
    // Instead, run them sequentially.
    #[test]
    fn db_sequential_test_runner() {
        test_db_creation();
        test_db_fetch_deposits();
        test_db_store_presigned_txs();
    }
}
