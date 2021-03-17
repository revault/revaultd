use crate::{
    database::{
        interface::*,
        schema::{DbTransaction, RevaultTx, TransactionType, SCHEMA},
        DatabaseError, DB_VERSION,
    },
    revaultd::{BlockchainTip, RevaultD, VaultStatus},
};
use revault_tx::{
    bitcoin::{
        secp256k1, util::bip32::ChildNumber, Amount, OutPoint, PublicKey as BitcoinPubKey, Txid,
    },
    miniscript::Descriptor,
    scripts::{DepositDescriptor, UnvaultDescriptor},
    transactions::{
        CancelTransaction, EmergencyTransaction, RevaultTransaction, SpendTransaction,
        UnvaultEmergencyTransaction, UnvaultTransaction,
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
    let fully_signed = tx.is_finalizable(secp_ctx);
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

/// Insert a new Spend transaction in the database
pub fn db_insert_spend(
    db_path: &PathBuf,
    unvault_txs: &[&DbTransaction],
    spend_tx: &SpendTransaction,
) -> Result<(), DatabaseError> {
    let spend_txid = spend_tx.inner_tx().global.unsigned_tx.txid();
    let spend_psbt = spend_tx.as_psbt_serialized();

    db_exec(db_path, |db_tx| {
        db_tx.execute(
            "INSERT INTO spend_transactions (psbt, txid) VALUES (?1, ?2)",
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
    db_path: &PathBuf,
    spend_tx: &SpendTransaction,
) -> Result<(), DatabaseError> {
    let spend_txid = spend_tx.inner_tx().global.unsigned_tx.txid();
    let spend_psbt = spend_tx.as_psbt_serialized();

    db_exec(db_path, |db_tx| {
        db_tx.execute(
            "UPDATE spend_transactions SET psbt = (?1) WHERE txid = (?2)",
            params![spend_psbt, spend_txid.to_vec()],
        )?;
        Ok(())
    })
}

pub fn db_delete_spend(db_path: &PathBuf, spend_txid: &Txid) -> Result<(), DatabaseError> {
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

    // There we trigger a concurrent write access to the database by inserting a deposit and
    // updating its presigned transaction in two different thread. It should be fine and one of
    // them just lock thanks to the unlock_notify feature of SQLite https://sqlite.org/unlock_notify.html
    fn test_db_concurrent_write() {
        let mut revaultd = dummy_revaultd();
        let db_path = revaultd.db_file();

        setup_db(&mut revaultd).unwrap();

        // Let's insert a deposit
        let wallet_id = 1;
        let status = VaultStatus::Funded;
        let outpoint = OutPoint::from_str(
            "adaa5a4b9fb07c860f8de460727b6bad4b5ab01d2e7f90f6f3f15a0080020168:0",
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

        let fresh_cancel_tx = CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAARoHs0elD2sCfWV4+b7PH3aRA+BkRVNf3m/P+Epjx2fNAAAAAAD9////AdLKAgAAAAAAIgAgB6abzQJ4vo5CO9XW3r3JnNumTwlpQbZm9FVICsLHPYQAAAAAAAEBK0ANAwAAAAAAIgAglEs6phQpv+twnAQSdjDvAEic65OtUIijeePBzAAqr50BAwSBAAAAAQWrIQO4lrAuffeRLuEEuwp2hAMZIPmqaHMTUySM3OwdA2hIW6xRh2R2qRTflccImFIy5NdTqwPuPZFB7g1pvYisa3apFOQxXoLeQv/aDFfav/l6YnYRKt+1iKxsk1KHZ1IhA32Q1DEqQ/kUP2MvQYFW46RCexZ5aYk17Arhp01th+37IQNrXQtfIXQdrv+RyyHLilJsb4ujlUMddG9X2jYkeXiWoFKvA3nxALJoAAEBR1IhA9+bpoeRoYk6Fehku5U6JFn6v0b8vq0SPVzELn/n6DqBIQPRrV6R4VL8XI/QyVm2kb8+fQjbDMB9jRL5kWvIHNlkZFKuAA==").unwrap();
        let fresh_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAT7KJ+fkvbKBDobFTsm31LqtMUfhTiR5tWA5XJA9oYgOAAAAAAD9////AkANAwAAAAAAIgAgbMJH4U4sOCdd1R9PVUuEbmS4bkbnNNlJaqxZBqXHwCcwdQAAAAAAACIAIM8vNQyMFHWpzTmNSefLOTf0spivub9JuegPqYdx0rLvAAAAAAABASuIlAMAAAAAACIAIONmt9fso2OE03OxwV4EkzSucRgHSh3ylMy/KcBayrRaAQMEAQAAAAEFR1IhAum/3N5NY9BZnqXIJxEBNzNEhHwCOY4WQ5xdZZ9XN4+dIQNwiQrXHbeULZ18BN3FOfnYK48NrsVzMDAXVEiu7HfvylKuAAEBqiEDsTozyBugih4LqhjAbDEbxv0SImcwm7uxgzAxpprx+hasUYdkdqkUq3ciI2+fP8tZgD/nHHJDhb3wHtOIrGt2qRQHsYoc0BfpfAKimvmP+V1XXUmr1YisbJNSh2dSIQMDsoKW2AvcnJM8c2BZo1U7OHGc2kUyfe5wh8GxWejwmiECwXo562TGRJPfOC0ooMYiE0XPegUlr7E9sCVTApCykntSrwJQBbJoAAEBJSEDsTozyBugih4LqhjAbDEbxv0SImcwm7uxgzAxpprx+hasUYcA").unwrap();

        let blockheight = 2300000;
        db_confirm_deposit(
            &db_path,
            &outpoint,
            blockheight,
            &fresh_unvault_tx,
            &fresh_cancel_tx,
            None,
            None,
        )
        .unwrap();

        let (tx_db_id, _) = db_cancel_transaction(&db_path, db_vault.id).unwrap();
        let mut cancel_tx = fresh_cancel_tx.clone();
        revault_tx_add_dummy_sig(&mut cancel_tx, 0);
        let handle = std::thread::spawn({
            let db_path = db_path.clone();
            let cancel_tx = cancel_tx.clone();
            let secp = revaultd.secp_ctx.clone();
            move || {
                for _ in 0..10 {
                    db_update_presigned_tx(
                        &db_path,
                        db_vault.id,
                        tx_db_id,
                        cancel_tx.inner_tx().inputs[0].partial_sigs.clone(),
                        &secp,
                    )
                    .unwrap();
                }
            }
        });
        for _ in 0..10 {
            db_update_presigned_tx(
                &db_path,
                db_vault.id,
                tx_db_id,
                cancel_tx.inner_tx().inputs[0].partial_sigs.clone(),
                &revaultd.secp_ctx,
            )
            .unwrap();
        }
        handle.join().unwrap();
    }

    fn test_db_spend_storage() {
        let mut revaultd = dummy_revaultd();
        let db_path = revaultd.db_file();
        let fresh_cancel_tx = CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAARoHs0elD2sCfWV4+b7PH3aRA+BkRVNf3m/P+Epjx2fNAAAAAAD9////AdLKAgAAAAAAIgAgB6abzQJ4vo5CO9XW3r3JnNumTwlpQbZm9FVICsLHPYQAAAAAAAEBK0ANAwAAAAAAIgAglEs6phQpv+twnAQSdjDvAEic65OtUIijeePBzAAqr50BAwSBAAAAAQWrIQO4lrAuffeRLuEEuwp2hAMZIPmqaHMTUySM3OwdA2hIW6xRh2R2qRTflccImFIy5NdTqwPuPZFB7g1pvYisa3apFOQxXoLeQv/aDFfav/l6YnYRKt+1iKxsk1KHZ1IhA32Q1DEqQ/kUP2MvQYFW46RCexZ5aYk17Arhp01th+37IQNrXQtfIXQdrv+RyyHLilJsb4ujlUMddG9X2jYkeXiWoFKvA3nxALJoAAEBR1IhA9+bpoeRoYk6Fehku5U6JFn6v0b8vq0SPVzELn/n6DqBIQPRrV6R4VL8XI/QyVm2kb8+fQjbDMB9jRL5kWvIHNlkZFKuAA==").unwrap();
        let fresh_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAUSDT2oqdQGG7zrBLphwlRmZDdQq579WyFQascyEsTxvAAAAAAD9////AkANAwAAAAAAIgAg8MPhtc3+VJnJ6OaWMYc+ptcjJPfCV7ddk3WDKDUJzxMwdQAAAAAAACIAIKSBXsawHlGnD7bjeTRKg0RjUn9YBHtCOJcRWwelwwkQAAAAAAABASuIlAMAAAAAACIAIMXXOiNpunncyn1S2nkS82ytVb6Vlkev2eyZrP1UfHg5AQMEAQAAAAEFR1IhA4hY1QUJ8eaMRBKwxS3PPHKE5rb9T4kBMu+A9qYoBKHEIQPDqUA1pPZIhTzbOrFzUwQ2iZBG9Myf/jaXNM2EAN7KPlKuAAEBqiECCCJb7ajSnGfrgiYJivthuk36hoa/2b8EOvpXD3kZjFasUYdkdqkUtJw6hgsD0uyDqCcstKVqwgxcfICIrGt2qRRSmYddIoGvSdw/O8UMT0nSLV9wIYisbJNSh2dSIQOAAQ9HvG5onjJ7+OjP9Yesw0S6QvQIvv8xwgI5JiEKmCEDCAgIhQzQi1myDL3dk2gj2hdut6Gf/EBe7x65BhzQnjRSrwJ4LrJoAAEBJSECCCJb7ajSnGfrgiYJivthuk36hoa/2b8EOvpXD3kZjFasUYcA").unwrap();
        let fullysigned_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAUSDT2oqdQGG7zrBLphwlRmZDdQq579WyFQascyEsTxvAAAAAAD9////AkANAwAAAAAAIgAg8MPhtc3+VJnJ6OaWMYc+ptcjJPfCV7ddk3WDKDUJzxMwdQAAAAAAACIAIKSBXsawHlGnD7bjeTRKg0RjUn9YBHtCOJcRWwelwwkQAAAAAAABASuIlAMAAAAAACIAIMXXOiNpunncyn1S2nkS82ytVb6Vlkev2eyZrP1UfHg5IgIDw6lANaT2SIU82zqxc1MENomQRvTMn/42lzTNhADeyj5HMEQCIGt6BWJotlXxWb1vFIFAXDMzVN21CkvTvXYoq8IgmansAiBuBkqPDyzU5DNzdYl6dFehL48bwG19SCkMH+PDVTO0YgEiAgOIWNUFCfHmjEQSsMUtzzxyhOa2/U+JATLvgPamKAShxEgwRQIhAJf1pJ2Ty3xbOJuboTrT10P9ipj7NR30r6iRIygtUkZZAiBVIU+6auH558K7qvvFDrgQWDaYIUQxdHdrNPwgR1iYzwEBAwQBAAAAAQVHUiEDiFjVBQnx5oxEErDFLc88coTmtv1PiQEy74D2pigEocQhA8OpQDWk9kiFPNs6sXNTBDaJkEb0zJ/+Npc0zYQA3so+Uq4AAQGqIQIIIlvtqNKcZ+uCJgmK+2G6TfqGhr/ZvwQ6+lcPeRmMVqxRh2R2qRS0nDqGCwPS7IOoJyy0pWrCDFx8gIisa3apFFKZh10iga9J3D87xQxPSdItX3AhiKxsk1KHZ1IhA4ABD0e8bmieMnv46M/1h6zDRLpC9Ai+/zHCAjkmIQqYIQMICAiFDNCLWbIMvd2TaCPaF263oZ/8QF7vHrkGHNCeNFKvAngusmgAAQElIQIIIlvtqNKcZ+uCJgmK+2G6TfqGhr/ZvwQ6+lcPeRmMVqxRhwA=").unwrap();

        setup_db(&mut revaultd).unwrap();

        // Let's insert a deposit
        let wallet_id = 1;
        let status = VaultStatus::Funded;
        let outpoint = OutPoint::from_str(
            "c9cf38058b720050bcba47490ee27f4a29d57a5aa2ee0f3c97731e140dbeced7:1",
        )
        .unwrap();
        let amount = Amount::from_sat(612345);
        let derivation_index = ChildNumber::from(349874);
        let received_at = 17890233;
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

        // Have the Unvault tx fully signed
        db_confirm_deposit(
            &db_path,
            &outpoint,
            9,
            &fresh_unvault_tx,
            &fresh_cancel_tx,
            None,
            None,
        )
        .unwrap();
        db_update_presigned_tx(
            &db_path,
            db_vault.id,
            db_unvault_transaction(&db_path, db_vault.id).unwrap().0,
            fullysigned_unvault_tx.inner_tx().inputs[0]
                .partial_sigs
                .clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();

        // We can store a Spend tx spending a single unvault and query it
        let spend_tx = SpendTransaction::from_psbt_str("cHNidP8BAGcCAAAAARdlVzMHyOWYPhrSslluxVphR04Vu1FkZFwhYQd9Hsa4AAAAAAD03QAAApAyAAAAAAAAIgAge2x1yRpaBoZgJhwSITI/Ycg/0tc80XahfOLJyfCduFSQjAIAAAAAAAAAAAAAAAEBK0ANAwAAAAAAIgAgzqV1Ar8huW7yhi1LtFuEF52PnEMhfiFRF1BvcI4txkABAwQBAAAAAQWrIQLqNHEkDw8EQRAtkj8nIiTREoIH9NnEOj2tqXHB2+ECcqxRh2R2qRSZGi2Oo23qaUaYI8v08iUsSyO/gIisa3apFAfsPi/Q8psFpddOAWOFWZOD3+iBiKxsk1KHZ1IhA8yAK0bRR08+P4A1MgJy0JaBzAc+yZn1bEe8n7w2cvr/IQON6TGY542Mlk5drLlU1b8mgwZyrrviwCZnJ9Cu+Yjw2VKvA/XdALJoAAEBJSEC6jRxJA8PBEEQLZI/JyIk0RKCB/TZxDo9ralxwdvhAnKsUYcAAA==").unwrap();
        let db_unvault = db_presigned_tx(
            &db_path,
            &db_vault.deposit_outpoint,
            TransactionType::Unvault,
        )
        .unwrap()
        .unwrap();
        db_insert_spend(&db_path, &[&db_unvault], &spend_tx).unwrap();
        assert_eq!(db_spend_transactions(&db_path).unwrap()[0].psbt, spend_tx);

        // We can update it, eg with a Spend with more sigs
        let spend_tx = SpendTransaction::from_psbt_str("cHNidP8BAGcCAAAAARdlVzMHyOWYPhrSslluxVphR04Vu1FkZFwhYQd9Hsa4AAAAAAD03QAAApAyAAAAAAAAIgAge2x1yRpaBoZgJhwSITI/Ycg/0tc80XahfOLJyfCduFSQjAIAAAAAAAAAAAAAAAEBK0ANAwAAAAAAIgAgzqV1Ar8huW7yhi1LtFuEF52PnEMhfiFRF1BvcI4txkAiAgLqNHEkDw8EQRAtkj8nIiTREoIH9NnEOj2tqXHB2+ECckgwRQIhAIctOS9u8Sasx1p9GIILypf8u3QrQrRhx7bKCk+IHbaYAiAlg2F6xZrktAQgo6fRa5o5xQB0/YKynzWTApXgL5yuKQEiAgON6TGY542Mlk5drLlU1b8mgwZyrrviwCZnJ9Cu+Yjw2UcwRAIgCYXUigFApDLlqDZ8BPVrBWhHaSAEMNSzgCEiydrSD8QCIHs8W6x0zd4l9NExXpC3Fg+/4ZT8IeCUR3FjgkCsddO8ASICA8yAK0bRR08+P4A1MgJy0JaBzAc+yZn1bEe8n7w2cvr/SDBFAiEA8saj4mK42f/Rm4k/Qv+6d26eZYdv4NyJmBLcu8JLUtQCIE6EdQsk4WG0i/UHA9cSuKCucNfLoNg3uM4cb55TNfsjAQEDBAEAAAABBashAuo0cSQPDwRBEC2SPyciJNESggf02cQ6Pa2pccHb4QJyrFGHZHapFJkaLY6jbeppRpgjy/TyJSxLI7+AiKxrdqkUB+w+L9DymwWl104BY4VZk4Pf6IGIrGyTUodnUiEDzIArRtFHTz4/gDUyAnLQloHMBz7JmfVsR7yfvDZy+v8hA43pMZjnjYyWTl2suVTVvyaDBnKuu+LAJmcn0K75iPDZUq8D9d0AsmgAAQElIQLqNHEkDw8EQRAtkj8nIiTREoIH9NnEOj2tqXHB2+ECcqxRhwAA").unwrap();
        db_update_spend(&db_path, &spend_tx).unwrap();
        assert_eq!(db_spend_transactions(&db_path).unwrap()[0].psbt, spend_tx);

        // And delete it
        db_delete_spend(&db_path, &spend_tx.inner_tx().global.unsigned_tx.txid()).unwrap();
        assert!(db_spend_transactions(&db_path).unwrap().is_empty());

        // And this works with multiple unvaults too

        // Re-insert the previous one so we have many references to the first Unvault
        db_insert_spend(&db_path, &[&db_unvault], &spend_tx).unwrap();

        // Same as above with a new vault
        let cancel_tx = CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAAc+BIbsSvYK/BWRNOAjazIlLfjlVzCCtXvoyN5/bydgEAAAAAAD9////AdLKAgAAAAAAIgAgFy2HNuxbT516bQQBY3R04IkEja348wJveLmF73Tj/owAAAAAAAEBK0ANAwAAAAAAIgAgZw+cwq8wJzworIDuy6s8cpOo3uF8fYyL5pECqg0UVagBAwSBAAAAAQWrIQLDtCYN0BlQw/h5zAcF0yXft2G7vAjkRsD9B9uoiyr1x6xRh2R2qRTGFACwvLOTrJHUPKb3ifnio7mt0Yisa3apFOZTIiKdGP+9rilwd09H1kOsfB/PiKxsk1KHZ1IhAtGKwcs21FeGy2qY+fzQ9uvI4X5ThtCqkwHsGtKQx0jYIQP93zm1sGAtxTNxsYQTkoXt26FoyKWNh1sx6hmk1yVzYlKvA8aOALJoAAEBR1IhA8HKPHwUwdE4CMkbosklbbI6mPPzzVnOom7LFxQbvCfYIQJ358C4w7CQrcz3UUcpo8eqsRn5JTM0Y0ge5Fz3CApS7lKuAA==").unwrap();
        let fresh_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAT7KJ+fkvbKBDobFTsm31LqtMUfhTiR5tWA5XJA9oYgOAAAAAAD9////AkANAwAAAAAAIgAgbMJH4U4sOCdd1R9PVUuEbmS4bkbnNNlJaqxZBqXHwCcwdQAAAAAAACIAIM8vNQyMFHWpzTmNSefLOTf0spivub9JuegPqYdx0rLvAAAAAAABASuIlAMAAAAAACIAIONmt9fso2OE03OxwV4EkzSucRgHSh3ylMy/KcBayrRaAQMEAQAAAAEFR1IhAum/3N5NY9BZnqXIJxEBNzNEhHwCOY4WQ5xdZZ9XN4+dIQNwiQrXHbeULZ18BN3FOfnYK48NrsVzMDAXVEiu7HfvylKuAAEBqiEDsTozyBugih4LqhjAbDEbxv0SImcwm7uxgzAxpprx+hasUYdkdqkUq3ciI2+fP8tZgD/nHHJDhb3wHtOIrGt2qRQHsYoc0BfpfAKimvmP+V1XXUmr1YisbJNSh2dSIQMDsoKW2AvcnJM8c2BZo1U7OHGc2kUyfe5wh8GxWejwmiECwXo562TGRJPfOC0ooMYiE0XPegUlr7E9sCVTApCykntSrwJQBbJoAAEBJSEDsTozyBugih4LqhjAbDEbxv0SImcwm7uxgzAxpprx+hasUYcA").unwrap();
        let fullysigned_unvault_tx = UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAT7KJ+fkvbKBDobFTsm31LqtMUfhTiR5tWA5XJA9oYgOAAAAAAD9////AkANAwAAAAAAIgAgbMJH4U4sOCdd1R9PVUuEbmS4bkbnNNlJaqxZBqXHwCcwdQAAAAAAACIAIM8vNQyMFHWpzTmNSefLOTf0spivub9JuegPqYdx0rLvAAAAAAABASuIlAMAAAAAACIAIONmt9fso2OE03OxwV4EkzSucRgHSh3ylMy/KcBayrRaIgIC6b/c3k1j0FmepcgnEQE3M0SEfAI5jhZDnF1ln1c3j51HMEQCIGFyxYLjg6lWDcVM80INdA3YLakH+VqoMc7qDkV6CimaAiBjp7k2X4q2lBPvf/BxsYV8NQ9LkNdq5r3tr5PxgO0EDAEiAgNwiQrXHbeULZ18BN3FOfnYK48NrsVzMDAXVEiu7HfvykgwRQIhALApfHxDE6dayC8XF1mv4Pn7/SceN5dQYHJ84ff8xnN9AiAA3v0lfO6cRJuatj5U7emyqEcHpPPM0886IMHM6CgchQEBAwQBAAAAAQVHUiEC6b/c3k1j0FmepcgnEQE3M0SEfAI5jhZDnF1ln1c3j50hA3CJCtcdt5QtnXwE3cU5+dgrjw2uxXMwMBdUSK7sd+/KUq4AAQGqIQOxOjPIG6CKHguqGMBsMRvG/RIiZzCbu7GDMDGmmvH6FqxRh2R2qRSrdyIjb58/y1mAP+ccckOFvfAe04isa3apFAexihzQF+l8AqKa+Y/5XVddSavViKxsk1KHZ1IhAwOygpbYC9yckzxzYFmjVTs4cZzaRTJ97nCHwbFZ6PCaIQLBejnrZMZEk984LSigxiITRc96BSWvsT2wJVMCkLKSe1KvAlAFsmgAAQElIQOxOjPIG6CKHguqGMBsMRvG/RIiZzCbu7GDMDGmmvH6FqxRhwA=").unwrap();
        let wallet_id = 1;
        let status = VaultStatus::Funded;
        let outpoint = OutPoint::from_str(
            "2117d7c3461ca013a099d8e60b0bcc6c33aec95db49f636c479ab85117479a91:0",
        )
        .unwrap();
        let amount = Amount::from_sat(112245);
        let derivation_index = ChildNumber::from(643874);
        let received_at = 2615297315;
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
        db_confirm_deposit(
            &db_path,
            &outpoint,
            9,
            &fresh_unvault_tx,
            &cancel_tx,
            None,
            None,
        )
        .unwrap();
        db_update_presigned_tx(
            &db_path,
            db_vault.id,
            db_unvault_transaction(&db_path, db_vault.id).unwrap().0,
            fullysigned_unvault_tx.inner_tx().inputs[0]
                .partial_sigs
                .clone(),
            &revaultd.secp_ctx,
        )
        .unwrap();

        let spend_tx_b = SpendTransaction::from_psbt_str("cHNidP8BAGcCAAAAAc+BIbsSvYK/BWRNOAjazIlLfjlVzCCtXvoyN5/bydgEAAAAAADFjgAAApAyAAAAAAAAIgAgC/9/hHKfpuelaggCOtb7lf6UkEQp1rp4xRO2jetbSFKQjAIAAAAAAAAAAAAAAAEBK0ANAwAAAAAAIgAgZw+cwq8wJzworIDuy6s8cpOo3uF8fYyL5pECqg0UVagBAwQBAAAAAQWrIQLDtCYN0BlQw/h5zAcF0yXft2G7vAjkRsD9B9uoiyr1x6xRh2R2qRTGFACwvLOTrJHUPKb3ifnio7mt0Yisa3apFOZTIiKdGP+9rilwd09H1kOsfB/PiKxsk1KHZ1IhAtGKwcs21FeGy2qY+fzQ9uvI4X5ThtCqkwHsGtKQx0jYIQP93zm1sGAtxTNxsYQTkoXt26FoyKWNh1sx6hmk1yVzYlKvA8aOALJoAAEBJSECw7QmDdAZUMP4ecwHBdMl37dhu7wI5EbA/QfbqIsq9cesUYcAAA==").unwrap();
        let db_unvault_b = db_presigned_tx(
            &db_path,
            &db_vault.deposit_outpoint,
            TransactionType::Unvault,
        )
        .unwrap()
        .unwrap();
        db_insert_spend(&db_path, &[&db_unvault, &db_unvault_b], &spend_tx_b).unwrap();
        assert_eq!(db_spend_transactions(&db_path).unwrap().len(), 2);

        let spend_tx_b = SpendTransaction::from_psbt_str("cHNidP8BAGcCAAAAAc+BIbsSvYK/BWRNOAjazIlLfjlVzCCtXvoyN5/bydgEAAAAAADFjgAAApAyAAAAAAAAIgAgC/9/hHKfpuelaggCOtb7lf6UkEQp1rp4xRO2jetbSFKQjAIAAAAAAAAAAAAAAAEBK0ANAwAAAAAAIgAgZw+cwq8wJzworIDuy6s8cpOo3uF8fYyL5pECqg0UVagiAgP93zm1sGAtxTNxsYQTkoXt26FoyKWNh1sx6hmk1yVzYkgwRQIhAMnhlNpNO7N7udIN2HnrjqFb6gEtck8rMC5WdEZK1EB7AiATzNpu03p/9t8fnPxziJOp5bfDHzHuIuyLk1Xedw+ztAEiAgLDtCYN0BlQw/h5zAcF0yXft2G7vAjkRsD9B9uoiyr1x0gwRQIhAMGp+GWnV6jWiqaO4gDqPol9TDgUYsPIEj8tFLeenfhHAiAXMm+MvFnkYZ4lcpLNaTbeSGt6t5hsdhZEmcVv1r172AEiAgLRisHLNtRXhstqmPn80PbryOF+U4bQqpMB7BrSkMdI2EcwRAIgPW/0MYMM9hRYNC6CUByPopDYCfkjWbyq6aRYx51NRbQCIDTw+NSPY6JkhetmaBPJEzqtu5UuuOD+/Zj673HW4ThMAQEDBAEAAAABBashAsO0Jg3QGVDD+HnMBwXTJd+3Ybu8CORGwP0H26iLKvXHrFGHZHapFMYUALC8s5OskdQ8pveJ+eKjua3RiKxrdqkU5lMiIp0Y/72uKXB3T0fWQ6x8H8+IrGyTUodnUiEC0YrByzbUV4bLapj5/ND268jhflOG0KqTAewa0pDHSNghA/3fObWwYC3FM3GxhBOShe3boWjIpY2HWzHqGaTXJXNiUq8Dxo4AsmgAAQElIQLDtCYN0BlQw/h5zAcF0yXft2G7vAjkRsD9B9uoiyr1x6xRhwAA").unwrap();
        db_update_spend(&db_path, &spend_tx_b).unwrap();

        // There are 2 Unvaults referenced by this Spend
        let db_spend =
            db_spend_transaction(&db_path, &spend_tx_b.inner_tx().global.unsigned_tx.txid())
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

        // And we can delete both..
        db_delete_spend(&db_path, &spend_tx_b.inner_tx().global.unsigned_tx.txid()).unwrap();
        db_delete_spend(&db_path, &spend_tx.inner_tx().global.unsigned_tx.txid()).unwrap();
    }

    // We disabled #[test] for the above, as they may erase the db concurrently.
    // Instead, run them sequentially.
    #[test]
    fn db_sequential_test_runner() {
        test_db_creation();
        test_db_fetch_deposits();
        test_db_store_presigned_txs();
        test_db_concurrent_write();
        test_db_spend_storage();
    }
}
