use crate::{
    bitcoind::{interface::UtxoInfo, BitcoindError},
    database::{
        interface::{
            db_cancel_transaction, db_deposits, db_emer_transaction, db_unvault_emer_transaction,
            db_unvault_from_deposit, db_unvaulted_vaults, db_vault_by_deposit,
        },
        schema::DbVault,
    },
    revaultd::{RevaultD, VaultStatus},
};
use revault_tx::{
    bitcoin::{Amount, OutPoint, TxOut, Txid},
    miniscript::DescriptorTrait,
    transactions::{
        transaction_chain, transaction_chain_manager, CancelTransaction, EmergencyTransaction,
        RevaultTransaction, UnvaultEmergencyTransaction, UnvaultTransaction,
    },
    txins::{DepositTxIn, RevaultTxIn, UnvaultTxIn},
    txouts::{DepositTxOut, RevaultTxOut},
};

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

/// Get fresh to-be-presigned transactions for this deposit utxo
pub fn presigned_transactions(
    revaultd: &RevaultD,
    outpoint: OutPoint,
    utxo: UtxoInfo,
) -> Result<
    (
        UnvaultTransaction,
        CancelTransaction,
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
    // if we are a stakeholder, and only the Unvault and the Cancel if we are a manager.
    if revaultd.is_stakeholder() {
        let emer_address = revaultd
            .emergency_address
            .clone()
            .expect("We are a stakeholder");
        let (unvault_tx, cancel_tx, emer_tx, unemer_tx) = transaction_chain(
            outpoint,
            Amount::from_sat(utxo.txo.value),
            &revaultd.deposit_descriptor,
            &revaultd.unvault_descriptor,
            &revaultd.cpfp_descriptor,
            derivation_index,
            emer_address,
            revaultd.lock_time,
            &revaultd.secp_ctx,
        )?;
        Ok((unvault_tx, cancel_tx, Some(emer_tx), Some(unemer_tx)))
    } else {
        let (unvault_tx, cancel_tx) = transaction_chain_manager(
            outpoint,
            Amount::from_sat(utxo.txo.value),
            &revaultd.deposit_descriptor,
            &revaultd.unvault_descriptor,
            &revaultd.cpfp_descriptor,
            derivation_index,
            revaultd.lock_time,
            &revaultd.secp_ctx,
        )?;
        Ok((unvault_tx, cancel_tx, None, None))
    }
}

/// Fill up the deposit UTXOs cache from db vaults
pub fn populate_deposit_cache(
    revaultd: &RevaultD,
) -> Result<HashMap<OutPoint, UtxoInfo>, BitcoindError> {
    let db_vaults = db_deposits(&revaultd.db_file())?;
    let mut cache = HashMap::with_capacity(db_vaults.len());

    for db_vault in db_vaults.into_iter() {
        let der_deposit_descriptor = revaultd
            .deposit_descriptor
            .derive(db_vault.derivation_index, &revaultd.secp_ctx);
        let script_pubkey = der_deposit_descriptor.inner().script_pubkey();
        let txo = TxOut {
            script_pubkey,
            value: db_vault.amount.as_sat(),
        };
        cache.insert(
            db_vault.deposit_outpoint,
            UtxoInfo {
                txo,
                is_confirmed: !matches!(db_vault.status, VaultStatus::Unconfirmed),
            },
        );
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
    let db_vault = db_vault_by_deposit(&db_path, &deposit_outpoint)?
        .expect("Checking Unvault txid for an unknow deposit");
    let unvault_descriptor = revaultd.derived_unvault_descriptor(db_vault.derivation_index);

    let unvault_tx = if let Some(tx) = db_unvault_from_deposit(&db_path, &deposit_outpoint)? {
        tx
    } else {
        let deposit_descriptor = revaultd.derived_deposit_descriptor(db_vault.derivation_index);

        let deposit_txo =
            DepositTxOut::new(Amount::from_sat(deposit_utxo.value), &deposit_descriptor);
        let deposit_txin = DepositTxIn::new(*deposit_outpoint, deposit_txo);

        let cpfp_descriptor = revaultd.derived_cpfp_descriptor(db_vault.derivation_index);
        UnvaultTransaction::new(
            deposit_txin,
            &unvault_descriptor,
            &cpfp_descriptor,
            revaultd.lock_time,
        )
        .map_err(|e| BitcoindError::Custom(format!("Error deriving Unvault tx: '{}'", e)))?
    };

    Ok(unvault_tx.revault_unvault_txin(&unvault_descriptor))
}

/// Get the Cancel txid of a give vault, trying first to fetch the transaction from the DB and
/// falling back to generating it.
/// Assumes the given deposit outpoint actually corresponds to an existing vaults, will panic
/// otherwise.
pub fn cancel_txid(
    revaultd: &Arc<RwLock<RevaultD>>,
    db_vault: &DbVault,
) -> Result<Txid, BitcoindError> {
    let revaultd = revaultd.read().unwrap();
    let db_path = revaultd.db_file();

    let cancel_tx = if let Some((_, db_tx)) = db_cancel_transaction(&db_path, db_vault.id)? {
        db_tx
    } else {
        let (_, cancel_tx) = transaction_chain_manager(
            db_vault.deposit_outpoint,
            db_vault.amount,
            &revaultd.deposit_descriptor,
            &revaultd.unvault_descriptor,
            &revaultd.cpfp_descriptor,
            db_vault.derivation_index,
            revaultd.lock_time,
            &revaultd.secp_ctx,
        )?;
        cancel_tx
    };

    Ok(cancel_tx.txid())
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
            if let Some((_, db_tx)) = db_unvault_emer_transaction(&db_path, db_vault.id)? {
                db_tx
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
                    revaultd.lock_time,
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
        let unemer_tx = if let Some((_, db_tx)) = db_emer_transaction(&db_path, db_vault.id)? {
            db_tx
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
                revaultd.lock_time,
                &revaultd.secp_ctx,
            )?;
            emer_tx
        };

        return Ok(Some(unemer_tx.txid()));
    }

    Ok(None)
}
