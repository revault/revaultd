use crate::{
    bitcoind::{
        interface::{BitcoinD, UtxoInfo},
        BitcoindError, ToBeCpfped,
    },
    database::{
        interface::{
            db_deposits, db_emer_transaction, db_unvault_emer_transaction, db_unvault_from_deposit,
            db_unvault_transaction, db_unvaulted_vaults, db_vault_by_deposit,
        },
        schema::DbVault,
    },
    revaultd::{RevaultD, VaultStatus},
};
use revault_tx::{
    bitcoin::consensus::encode,
    bitcoin::{Amount, OutPoint, TxOut, Txid},
    error::TransactionCreationError,
    miniscript::DescriptorTrait,
    transactions::CpfpTransaction,
    transactions::{
        transaction_chain, transaction_chain_manager, CancelTransaction, EmergencyTransaction,
        RevaultTransaction, UnvaultEmergencyTransaction, UnvaultTransaction,
    },
    txins::{CpfpTxIn, DepositTxIn, RevaultTxIn, UnvaultTxIn},
    txouts::{CpfpTxOut, DepositTxOut, RevaultTxOut},
};

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

/// Get fresh to-be-presigned transactions for this deposit utxo.
/// The Cancel transactions are sorted by increasing feerate.
pub fn presigned_transactions(
    revaultd: &RevaultD,
    outpoint: OutPoint,
    utxo: UtxoInfo,
) -> Result<
    (
        UnvaultTransaction,
        [CancelTransaction; 5],
        Option<EmergencyTransaction>,
        Option<UnvaultEmergencyTransaction>,
    ),
    BitcoindError,
> {
    // We use the same derivation index for all descriptors.
    let derivation_index = *revaultd
        .derivation_index_map
        .get(&utxo.txo.script_pubkey)
        .ok_or_else(|| {
            BitcoindError::Custom(format!("Unknown derivation index for: {:#?}", &utxo))
        })?;

    // Reconstruct the deposit UTXO and derive all pre-signed transactions out of it
    // if we are a stakeholder, and only the Unvault and the Cancels if we are a manager.
    if revaultd.is_stakeholder() {
        let emer_address = revaultd
            .emergency_address
            .clone()
            .expect("We are a stakeholder");
        let (unvault_tx, cancel_batch, emer_tx, unemer_tx) = transaction_chain(
            outpoint,
            Amount::from_sat(utxo.txo.value),
            &revaultd.deposit_descriptor,
            &revaultd.unvault_descriptor,
            &revaultd.cpfp_descriptor,
            derivation_index,
            emer_address,
            &revaultd.secp_ctx,
        )?;
        Ok((
            unvault_tx,
            cancel_batch.all_feerates(),
            Some(emer_tx),
            Some(unemer_tx),
        ))
    } else {
        let (unvault_tx, cancel_batch) = transaction_chain_manager(
            outpoint,
            Amount::from_sat(utxo.txo.value),
            &revaultd.deposit_descriptor,
            &revaultd.unvault_descriptor,
            &revaultd.cpfp_descriptor,
            derivation_index,
            &revaultd.secp_ctx,
        )?;
        Ok((unvault_tx, cancel_batch.all_feerates(), None, None))
    }
}

/// Derive the deposit UTxO of this vault
pub fn vault_deposit_utxo(revaultd: &RevaultD, db_vault: &DbVault) -> UtxoInfo {
    let der_deposit_descriptor = revaultd
        .deposit_descriptor
        .derive(db_vault.derivation_index, &revaultd.secp_ctx);
    let script_pubkey = der_deposit_descriptor.inner().script_pubkey();
    let txo = TxOut {
        script_pubkey,
        value: db_vault.amount.as_sat(),
    };
    UtxoInfo {
        txo,
        is_confirmed: !matches!(db_vault.status, VaultStatus::Unconfirmed),
    }
}

/// Fill up the deposit UTXOs cache from db vaults
pub fn populate_deposit_cache(
    revaultd: &RevaultD,
) -> Result<HashMap<OutPoint, UtxoInfo>, BitcoindError> {
    let db_vaults = db_deposits(&revaultd.db_file())?;
    let mut cache = HashMap::with_capacity(db_vaults.len());

    for db_vault in db_vaults.into_iter() {
        let utxo_info = vault_deposit_utxo(revaultd, &db_vault);
        cache.insert(db_vault.deposit_outpoint, utxo_info);
        log::debug!("Loaded deposit '{}' from db", db_vault.deposit_outpoint);
    }

    Ok(cache)
}

/// Fill up the unvault UTXOs cache from db vaults
pub fn populate_unvaults_cache(
    revaultd: &RevaultD,
) -> Result<HashMap<OutPoint, UtxoInfo>, BitcoindError> {
    let db_unvaults = db_unvaulted_vaults(&revaultd.db_file())?;
    let mut cache = HashMap::with_capacity(db_unvaults.len());

    for (db_vault, unvault_tx) in db_unvaults.into_iter() {
        let unvault_descriptor = revaultd.derived_unvault_descriptor(db_vault.derivation_index);
        let unvault_txin = unvault_tx.revault_unvault_txin(&unvault_descriptor);
        let unvault_outpoint = unvault_txin.outpoint();
        let txo = unvault_txin.into_txout().into_txout();
        cache.insert(
            unvault_outpoint,
            UtxoInfo {
                txo,
                is_confirmed: !matches!(db_vault.status, VaultStatus::Unvaulting),
            },
        );
        log::debug!("Loaded Unvault Utxo '{}' from db", unvault_outpoint);
    }

    Ok(cache)
}

/// Get the Unvault transaction outpoint from a deposit, trying first to fetch the transaction
/// from the DB and falling back to generating it.
/// Assumes the given deposit outpoint actually corresponds to an existing vaults, will panic
/// otherwise.
pub fn unvault_txin_from_deposit(
    revaultd: &Arc<RwLock<RevaultD>>,
    deposit_outpoint: &OutPoint,
    deposit_utxo: TxOut,
) -> Result<UnvaultTxIn, BitcoindError> {
    let revaultd = revaultd.read().unwrap();
    let db_path = revaultd.db_file();
    let db_vault = db_vault_by_deposit(&db_path, deposit_outpoint)?
        .expect("Checking Unvault txid for an unknow deposit");
    let unvault_descriptor = revaultd.derived_unvault_descriptor(db_vault.derivation_index);

    let unvault_tx = if let Some(tx) = db_unvault_from_deposit(&db_path, deposit_outpoint)? {
        tx
    } else {
        let deposit_descriptor = revaultd.derived_deposit_descriptor(db_vault.derivation_index);

        let deposit_txo =
            DepositTxOut::new(Amount::from_sat(deposit_utxo.value), &deposit_descriptor);
        let deposit_txin = DepositTxIn::new(*deposit_outpoint, deposit_txo);

        let cpfp_descriptor = revaultd.derived_cpfp_descriptor(db_vault.derivation_index);
        UnvaultTransaction::new(deposit_txin, &unvault_descriptor, &cpfp_descriptor)
            .map_err(|e| BitcoindError::Custom(format!("Error deriving Unvault tx: '{}'", e)))?
    };

    Ok(unvault_tx.revault_unvault_txin(&unvault_descriptor))
}

/// Get the Unvault txid of a given vault.
pub fn unvault_txid(revaultd: &RevaultD, db_vault: &DbVault) -> Result<Txid, BitcoindError> {
    let db_path = revaultd.db_file();

    let unvault_tx = if let Some(unvault_db_tx) = db_unvault_transaction(&db_path, db_vault.id)? {
        unvault_db_tx.psbt.assert_unvault()
    } else {
        let (unvault_tx, _) = transaction_chain_manager(
            db_vault.deposit_outpoint,
            db_vault.amount,
            &revaultd.deposit_descriptor,
            &revaultd.unvault_descriptor,
            &revaultd.cpfp_descriptor,
            db_vault.derivation_index,
            &revaultd.secp_ctx,
        )?;
        unvault_tx
    };

    Ok(unvault_tx.txid())
}

/// Get the Cancel txids of a give vault.
pub fn cancel_txids(
    revaultd: &Arc<RwLock<RevaultD>>,
    db_vault: &DbVault,
) -> Result<Vec<Txid>, BitcoindError> {
    let revaultd = revaultd.read().unwrap();

    let (_, cancel_batch) = transaction_chain_manager(
        db_vault.deposit_outpoint,
        db_vault.amount,
        &revaultd.deposit_descriptor,
        &revaultd.unvault_descriptor,
        &revaultd.cpfp_descriptor,
        db_vault.derivation_index,
        &revaultd.secp_ctx,
    )?;

    Ok(cancel_batch
        .all_feerates()
        .iter()
        .map(|cancel_tx| cancel_tx.txid())
        .collect())
}

/// Get the Unvault Emergency transaction id, if we are at all able to (ie if we are a stakeholder).
pub fn unemer_txid(
    revaultd: &Arc<RwLock<RevaultD>>,
    db_vault: &DbVault,
) -> Result<Option<Txid>, BitcoindError> {
    let revaultd = revaultd.read().unwrap();
    let db_path = revaultd.db_file();

    if revaultd.is_stakeholder() {
        let unemer_tx =
            if let Some(unemer_db_tx) = db_unvault_emer_transaction(&db_path, db_vault.id)? {
                unemer_db_tx.psbt.assert_unvault_emer()
            } else {
                let (_, _, _, unemer_tx) = transaction_chain(
                    db_vault.deposit_outpoint,
                    db_vault.amount,
                    &revaultd.deposit_descriptor,
                    &revaultd.unvault_descriptor,
                    &revaultd.cpfp_descriptor,
                    db_vault.derivation_index,
                    revaultd
                        .emergency_address
                        .clone()
                        .expect("Just checked we were a stakeholder"),
                    &revaultd.secp_ctx,
                )?;
                unemer_tx
            };

        return Ok(Some(unemer_tx.txid()));
    }

    Ok(None)
}

/// Get the Emergency transaction id, if we are at all able to (ie if we are a stakeholder).
pub fn emer_txid(
    revaultd: &Arc<RwLock<RevaultD>>,
    db_vault: &DbVault,
) -> Result<Option<Txid>, BitcoindError> {
    let revaultd = revaultd.read().unwrap();
    let db_path = revaultd.db_file();

    if revaultd.is_stakeholder() {
        let unemer_tx = if let Some(emer_db_tx) = db_emer_transaction(&db_path, db_vault.id)? {
            emer_db_tx.psbt.assert_emer()
        } else {
            let (_, _, emer_tx, _) = transaction_chain(
                db_vault.deposit_outpoint,
                db_vault.amount,
                &revaultd.deposit_descriptor,
                &revaultd.unvault_descriptor,
                &revaultd.cpfp_descriptor,
                db_vault.derivation_index,
                revaultd
                    .emergency_address
                    .clone()
                    .expect("Just checked we were a stakeholder"),
                &revaultd.secp_ctx,
            )?;
            emer_tx
        };

        return Ok(Some(unemer_tx.txid()));
    }

    Ok(None)
}

/// CPFP a bunch of transactions, bumping their feerate by at least `target_feerate`.
/// `target_feerate` is expressed in sat/kWU.
/// All the transactions' feerate MUST be below `target_feerate`.
pub fn cpfp_package(
    revaultd: &Arc<RwLock<RevaultD>>,
    bitcoind: &BitcoinD,
    to_be_cpfped: Vec<ToBeCpfped>,
    target_feerate: u64,
) -> Result<Vec<Txid>, BitcoindError> {
    let revaultd = revaultd.read().unwrap();
    let cpfp_descriptor = &revaultd.cpfp_descriptor;
    // First of all, compute all the information we need from the to-be-cpfped transactions.
    let mut txids = HashSet::with_capacity(to_be_cpfped.len());
    let mut package_weight = 0;
    let mut package_fees = Amount::from_sat(0);
    let mut txins = Vec::with_capacity(to_be_cpfped.len());
    for tx in to_be_cpfped.iter() {
        txids.insert(tx.txid());
        package_weight += tx.max_weight();
        package_fees += tx.fees();
        assert!(((package_fees.as_sat() * 1000 / package_weight) as u64) < target_feerate);
        match tx.cpfp_txin(cpfp_descriptor, &revaultd.secp_ctx) {
            Some(txin) => txins.push(txin),
            None => {
                log::error!("No CPFP txin for tx '{}'", tx.txid());
                return Ok(txids.into_iter().collect());
            }
        }
    }
    let tx_feerate = (package_fees.as_sat() * 1_000 / package_weight) as u64; // to sats/kWU
    assert!(tx_feerate < target_feerate);
    let added_feerate = target_feerate - tx_feerate;
    // Then construct the child PSBT
    let confirmed_cpfp_utxos: Vec<_> = bitcoind
        .list_unspent_cpfp()?
        .into_iter()
        .filter_map(|l| {
            // Not considering our own outputs nor UTXOs still in mempool
            if txids.contains(&l.outpoint.txid) || l.confirmations < 1 {
                None
            } else {
                let txout = CpfpTxOut::new(
                    Amount::from_sat(l.txo.value),
                    &revaultd.derived_cpfp_descriptor(l.derivation_index.expect("Must be here")),
                );
                Some(CpfpTxIn::new(l.outpoint, txout))
            }
        })
        .collect();
    let psbt = match CpfpTransaction::from_txins(
        txins,
        package_weight,
        package_fees,
        added_feerate,
        confirmed_cpfp_utxos,
    ) {
        Ok(tx) => tx,
        Err(TransactionCreationError::InsufficientFunds) => {
            // Well, we're poor.
            return Err(BitcoindError::RevaultTx(
                revault_tx::Error::TransactionCreation(TransactionCreationError::InsufficientFunds),
            ));
        }
        Err(e) => {
            return Err(BitcoindError::RevaultTx(
                revault_tx::Error::TransactionCreation(e),
            ));
        }
    };
    // Finally, sign and (try to) broadcast the CPFP transaction
    let (complete, psbt_signed) = bitcoind.sign_psbt(psbt.psbt())?;
    if !complete {
        return Err(BitcoindError::Custom(
            format!(
                "Bitcoind returned a non-finalized CPFP PSBT: {}",
                base64::encode(encode::serialize(&psbt_signed))
            )
            .to_string(),
        ));
    }
    let final_tx = psbt_signed.extract_tx();
    if let Err(e) = bitcoind.broadcast_transaction(&final_tx) {
        return Err(BitcoindError::Custom(
            format!("Error broadcasting '{:?}' CPFP tx: {}", txids, e).to_string(),
        ));
    }
    log::info!("CPFPed transactions with ids '{:?}'", txids);
    Ok(txids.into_iter().collect())
}
