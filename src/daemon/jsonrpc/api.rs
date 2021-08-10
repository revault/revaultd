//! Here we handle messages incoming from the RPC server. We only treat semantic of
//! *valid* JSONRPC2 commands here. All the communication and parsing is done in the
//! `server` mod.

use crate::{
    control::{
        announce_spend_transaction, bitcoind_broadcast, check_revocation_signatures,
        check_spend_signatures, check_spend_transaction_size, check_unvault_signatures,
        fetch_cosigs_signatures, finalized_emer_txs, listvaults_from_db, onchain_txs,
        presigned_txs, share_rev_signatures, share_unvault_signatures, vaults_from_deposits,
        ListSpendEntry, ListSpendStatus, RpcUtils,
    },
    database::{
        actions::{
            db_delete_spend, db_insert_spend, db_mark_activating_vault,
            db_mark_broadcastable_spend, db_mark_securing_vault, db_update_presigned_tx,
            db_update_spend,
        },
        interface::{
            db_cancel_transaction, db_emer_transaction, db_list_spends, db_spend_transaction,
            db_tip, db_unvault_emer_transaction, db_unvault_transaction, db_vault_by_deposit,
            db_vault_by_unvault_txid, db_vaults, db_vaults_from_spend, db_vaults_min_status,
        },
    },
    jsonrpc::UserRole,
    revaultd::{BlockchainTip, VaultStatus},
    threadmessages::*,
};
use common::VERSION;

use revault_tx::{
    bitcoin::{
        util::bip32, Address, Amount, OutPoint, Transaction as BitcoinTransaction, TxOut, Txid,
    },
    miniscript::DescriptorTrait,
    transactions::{
        spend_tx_from_deposits, transaction_chain, CancelTransaction, EmergencyTransaction,
        RevaultTransaction, SpendTransaction, UnvaultEmergencyTransaction, UnvaultTransaction,
    },
    txins::DepositTxIn,
    txouts::{DepositTxOut, SpendTxOut},
};

use std::{
    collections::BTreeMap,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
};

use jsonrpc_core::Error as JsonRpcError;
use jsonrpc_derive::rpc;
use serde_json::json;

#[derive(Clone)]
pub struct JsonRpcMetaData {
    pub shutdown: Arc<AtomicBool>,
    pub role: UserRole,
    pub rpc_utils: RpcUtils,
}
impl jsonrpc_core::Metadata for JsonRpcMetaData {}

impl JsonRpcMetaData {
    pub fn new(role: UserRole, rpc_utils: RpcUtils) -> Self {
        JsonRpcMetaData {
            shutdown: Arc::from(AtomicBool::from(false)),
            role,
            rpc_utils,
        }
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    pub fn shutdown(&self) {
        // Relaxed is fine, worse case we just stop at the next iteration on ARM
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

#[rpc(server)]
pub trait RpcApi {
    type Metadata;

    /// Stops the daemon
    #[rpc(meta, name = "stop")]
    fn stop(&self, meta: Self::Metadata) -> jsonrpc_core::Result<()>;

    /// Get informations about the daemon
    #[rpc(meta, name = "getinfo")]
    fn getinfo(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value>;

    /// Get a list of current vaults, which can be sorted by txids or status
    #[rpc(meta, name = "listvaults")]
    fn listvaults(
        &self,
        meta: Self::Metadata,
        statuses: Option<Vec<String>>,
        outpoints: Option<Vec<OutPoint>>,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    /// Get an address to receive funds to the stakeholders' descriptor
    #[rpc(meta, name = "getdepositaddress")]
    fn getdepositaddress(
        &self,
        meta: Self::Metadata,
        index: Option<bip32::ChildNumber>,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    /// Get the cancel and both emergency transactions for a vault identified by its deposit
    /// outpoint.
    #[rpc(meta, name = "getrevocationtxs")]
    fn getrevocationtxs(
        &self,
        meta: Self::Metadata,
        outpoint: OutPoint,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    /// Give the signed cancel, emergency, and unvault_emergency transactions (as
    /// base64-encoded PSBTs) for a vault identified by its deposit outpoint.
    #[rpc(meta, name = "revocationtxs")]
    fn revocationtxs(
        &self,
        meta: Self::Metadata,
        outpoint: OutPoint,
        cancel_tx: CancelTransaction,
        emergency_tx: EmergencyTransaction,
        emergency_unvault_tx: UnvaultEmergencyTransaction,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    /// Get the fresh Unvault transactions for a vault identified by its deposit
    /// outpoint.
    #[rpc(meta, name = "getunvaulttx")]
    fn getunvaulttx(
        &self,
        meta: Self::Metadata,
        outpoint: OutPoint,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    /// Give the signed cancel, emergency, and unvault_emergency transactions (as
    /// base64-encoded PSBTs) for a vault identified by its deposit outpoint.
    #[rpc(meta, name = "unvaulttx")]
    fn unvaulttx(
        &self,
        meta: Self::Metadata,
        outpoint: OutPoint,
        unvault_tx: UnvaultTransaction,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    /// Retrieve the presigned transactions of a list of vaults
    #[rpc(meta, name = "listpresignedtransactions")]
    fn listpresignedtransactions(
        &self,
        meta: Self::Metadata,
        outpoints: Option<Vec<OutPoint>>,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    /// Retrieve the onchain transactions of a list of vaults
    #[rpc(meta, name = "listonchaintransactions")]
    fn listonchaintransactions(
        &self,
        meta: Self::Metadata,
        outpoints: Option<Vec<OutPoint>>,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    #[rpc(meta, name = "getspendtx")]
    fn getspendtx(
        &self,
        meta: Self::Metadata,
        outpoint: Vec<OutPoint>,
        outputs: BTreeMap<Address, u64>,
        feerate: u64,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    #[rpc(meta, name = "updatespendtx")]
    fn updatespendtx(
        &self,
        meta: Self::Metadata,
        spend_tx: SpendTransaction,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    #[rpc(meta, name = "delspendtx")]
    fn delspendtx(
        &self,
        meta: Self::Metadata,
        spend_txid: Txid,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    #[rpc(meta, name = "listspendtxs")]
    fn listspendtxs(
        &self,
        meta: Self::Metadata,
        status: Option<Vec<ListSpendStatus>>,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    #[rpc(meta, name = "setspendtx")]
    fn setspendtx(
        &self,
        meta: Self::Metadata,
        spend_txid: Txid,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    #[rpc(meta, name = "revault")]
    fn revault(
        &self,
        meta: Self::Metadata,
        deposit_outpoint: OutPoint,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    #[rpc(meta, name = "emergency")]
    fn emergency(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value>;
}

// TODO: we should probably make these proc macros and apply them above?

macro_rules! stakeholder_only {
    ($meta:ident) => {
        match $meta.role {
            UserRole::Manager => {
                // TODO: we should declare some custom error codes instead of
                // abusing -32602
                return Err(JsonRpcError::invalid_params(
                    "This is a stakeholder command".to_string(),
                ));
            }
            _ => {}
        }
    };
}

macro_rules! manager_only {
    ($meta:ident) => {
        match $meta.role {
            UserRole::Stakeholder => {
                // TODO: we should declare some custom error codes instead of
                // abusing -32602
                return Err(JsonRpcError::invalid_params(
                    "This is a manager command".to_string(),
                ));
            }
            _ => {}
        }
    };
}

macro_rules! parse_vault_status {
    ($status:expr) => {
        VaultStatus::from_str(&$status).map_err(|_| {
            JsonRpcError::invalid_params(format!("'{}' is not a valid vault status", &$status))
        })
    };
}

macro_rules! internal_error {
    ($error: expr) => {
        JsonRpcError {
            code: jsonrpc_core::types::error::ErrorCode::InternalError,
            message: $error.to_string(),
            data: None,
        }
    };
}

macro_rules! unknown_outpoint {
    ($outpoint: expr) => {
        JsonRpcError::invalid_params(format!("No vault at '{}'", $outpoint))
    };
}

macro_rules! invalid_status {
    ($current: expr, $required: expr) => {
        JsonRpcError::invalid_params(format!(
            "Invalid vault status: '{}'. Need '{}'",
            $current, $required
        ))
    };
}

pub struct RpcImpl;
impl RpcApi for RpcImpl {
    type Metadata = JsonRpcMetaData;

    fn stop(&self, meta: JsonRpcMetaData) -> jsonrpc_core::Result<()> {
        log::info!("Stopping revaultd");

        meta.rpc_utils
            .bitcoind_tx
            .send(BitcoindMessageOut::Shutdown)
            .map_err(|e| internal_error!(e))?;
        meta.rpc_utils
            .sigfetcher_tx
            .send(SigFetcherMessageOut::Shutdown)
            .map_err(|e| internal_error!(e))?;
        meta.shutdown();

        Ok(())
    }

    fn getinfo(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value> {
        let (bitrep_tx, bitrep_rx) = mpsc::sync_channel(0);
        meta.rpc_utils
            .bitcoind_tx
            .send(BitcoindMessageOut::SyncProgress(bitrep_tx))
            .map_err(|e| internal_error!(e))?;
        let progress = bitrep_rx.recv().map_err(|e| internal_error!(e))?;

        let revaultd = meta.rpc_utils.revaultd.read().unwrap();

        // This means blockheight == 0 for IBD.
        let BlockchainTip {
            height: blockheight,
            ..
        } = db_tip(&revaultd.db_file()).map_err(|e| internal_error!(e))?;

        let number_of_vaults = listvaults_from_db(&revaultd, None, None)
            .map_err(|e| internal_error!(e))?
            .iter()
            .filter(|l| {
                l.status != VaultStatus::Spent
                    && l.status != VaultStatus::Canceled
                    && l.status != VaultStatus::Unvaulted
                    && l.status != VaultStatus::EmergencyVaulted
            })
            .count();

        let managers_threshold = meta.rpc_utils.revaultd.read().unwrap().managers_threshold();

        Ok(json!({
            "version": VERSION.to_string(),
            "network": revaultd.bitcoind_config.network.to_string(),
            "blockheight": blockheight,
            "sync": progress,
            "vaults": number_of_vaults,
            "managers_threshold": managers_threshold,
        }))
    }

    fn listvaults(
        &self,
        meta: Self::Metadata,
        statuses: Option<Vec<String>>,
        outpoints: Option<Vec<OutPoint>>,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let statuses = if let Some(statuses) = statuses {
            // If they give an empty array, it's not that they don't want any result, but rather
            // that they don't want this filter to be taken into account!
            if !statuses.is_empty() {
                Some(
                    statuses
                        .into_iter()
                        .map(|status_str| parse_vault_status!(status_str))
                        .collect::<jsonrpc_core::Result<Vec<VaultStatus>>>()?,
                )
            } else {
                None
            }
        } else {
            None
        };

        let vaults = listvaults_from_db(
            &meta.rpc_utils.revaultd.read().unwrap(),
            statuses,
            outpoints,
        )
        .map_err(|e| internal_error!(e))?;

        let vaults: Vec<serde_json::Value> = vaults
            .into_iter()
            .map(|entry| {
                let derivation_index: u32 = entry.derivation_index.into();
                json!({
                    "amount": entry.amount.as_sat(),
                    "blockheight": entry.blockheight,
                    "status": entry.status.to_string(),
                    "txid": entry.deposit_outpoint.txid.to_string(),
                    "vout": entry.deposit_outpoint.vout,
                    "derivation_index": derivation_index,
                    "address": entry.address.to_string(),
                    "received_at": entry.received_at,
                    "updated_at": entry.updated_at,
                })
            })
            .collect();

        Ok(json!({ "vaults": vaults }))
    }

    fn getdepositaddress(
        &self,
        meta: Self::Metadata,
        index: Option<bip32::ChildNumber>,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let address = if let Some(index) = index {
            meta.rpc_utils.revaultd.read().unwrap().vault_address(index)
        } else {
            meta.rpc_utils.revaultd.read().unwrap().deposit_address()
        };
        Ok(json!({ "address": address.to_string() }))
    }

    fn getrevocationtxs(
        &self,
        meta: Self::Metadata,
        outpoint: OutPoint,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        stakeholder_only!(meta);
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let db_file = &revaultd.db_file();

        // First, make sure the vault exists and is confirmed.
        let vault = db_vault_by_deposit(db_file, &outpoint)
            .map_err(|e| internal_error!(e))?
            .ok_or_else(|| {
                JsonRpcError::invalid_params(format!(
                    "'{}' does not refer to a known and confirmed vault",
                    &outpoint,
                ))
            })?;
        if matches!(vault.status, VaultStatus::Unconfirmed) {
            return Err(JsonRpcError::invalid_params(format!(
                "'{}' does not refer to a known and confirmed vault",
                &outpoint,
            )));
        };

        let emer_address = revaultd
            .emergency_address
            .clone()
            .expect("The JSONRPC API checked we were a stakeholder");

        let (_, cancel_tx, emergency_tx, unvault_emergency_tx) = transaction_chain(
            outpoint,
            vault.amount,
            &revaultd.deposit_descriptor,
            &revaultd.unvault_descriptor,
            &revaultd.cpfp_descriptor,
            vault.derivation_index,
            emer_address,
            revaultd.lock_time,
            &revaultd.secp_ctx,
        )
        .map_err(|e| internal_error!(e))?;

        Ok(json!({
            "cancel_tx": cancel_tx.as_psbt_string(),
            "emergency_tx": emergency_tx.as_psbt_string(),
            "emergency_unvault_tx": unvault_emergency_tx.as_psbt_string(),
        }))
    }

    fn revocationtxs(
        &self,
        meta: Self::Metadata,
        outpoint: OutPoint,
        cancel_tx: CancelTransaction,
        emergency_tx: EmergencyTransaction,
        unvault_emergency_tx: UnvaultEmergencyTransaction,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        stakeholder_only!(meta);

        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let db_path = revaultd.db_file();
        let secp_ctx = &revaultd.secp_ctx;

        // They may only send revocation transactions for confirmed and not-yet-presigned
        // vaults.
        let db_vault = db_vault_by_deposit(&db_path, &outpoint)
            .map_err(|e| internal_error!(e))?
            .ok_or_else(|| unknown_outpoint!(outpoint))?;
        if !matches!(db_vault.status, VaultStatus::Funded) {
            return Err(invalid_status!(db_vault.status, VaultStatus::Funded));
        };

        // Sanity check they didn't send us garbaged PSBTs
        // FIXME: this may not hold true in all cases, see https://github.com/revault/revaultd/issues/145
        let (cancel_db_id, db_cancel_tx) = db_cancel_transaction(&db_path, db_vault.id)
            .map_err(|e| internal_error!(e))?
            .expect("must be here if at least in 'Funded' state");
        let rpc_txid = cancel_tx.tx().wtxid();
        let db_txid = db_cancel_tx.tx().wtxid();
        if rpc_txid != db_txid {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid Cancel tx: db wtxid is '{}' but this PSBT's is '{}' ",
                db_txid, rpc_txid
            )));
        }
        // FIXME: this *might* not hold true in all cases, see https://github.com/revault/revaultd/issues/145
        let (emer_db_id, db_emergency_tx) = db_emer_transaction(&revaultd.db_file(), db_vault.id)
            .map_err(|e| internal_error!(e))?
            .expect("Must be here if 'funded'");
        let rpc_txid = emergency_tx.tx().wtxid();
        let db_txid = db_emergency_tx.tx().wtxid();
        if rpc_txid != db_txid {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid Emergency tx: db wtxid is '{}' but this PSBT's is '{}' ",
                db_txid, rpc_txid
            )));
        }
        // FIXME: this *might* not hold true in all cases, see https://github.com/revault/revaultd/issues/145
        let (unvault_emer_db_id, db_unemergency_tx) =
            db_unvault_emer_transaction(&revaultd.db_file(), db_vault.id)
                .map_err(|e| internal_error!(e))?
                .expect("Must be here if 'funded'");
        let rpc_txid = unvault_emergency_tx.tx().wtxid();
        let db_txid = db_unemergency_tx.tx().wtxid();
        if rpc_txid != db_txid {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid Unvault Emergency tx: db wtxid is '{}' but this PSBT's is '{}' ",
                db_txid, rpc_txid
            )));
        }

        let deriv_index = db_vault.derivation_index;
        let cancel_sigs = cancel_tx
            .psbt()
            .inputs
            .get(0)
            .expect("Cancel tx has a single input, inbefore fee bumping.")
            .partial_sigs
            .clone();
        let emer_sigs = emergency_tx
            .psbt()
            .inputs
            .get(0)
            .expect("Emergency tx has a single input, inbefore fee bumping.")
            .partial_sigs
            .clone();
        let unvault_emer_sigs = unvault_emergency_tx
            .psbt()
            .inputs
            .get(0)
            .expect("UnvaultEmergency tx has a single input, inbefore fee bumping.")
            .partial_sigs
            .clone();

        // They must have included *at least* a signature for our pubkey
        let our_pubkey = revaultd
            .our_stk_xpub_at(deriv_index)
            .expect("We are a stakeholder, checked at the beginning of the call.");
        if !cancel_sigs.contains_key(&our_pubkey) {
            return Err(JsonRpcError::invalid_params(format!(
                "No signature for ourselves ({}) in Cancel transaction",
                our_pubkey
            )));
        }
        // We use the same public key across the transaction chain, that's pretty
        // neat from an usability perspective.
        if !emer_sigs.contains_key(&our_pubkey) {
            return Err(JsonRpcError::invalid_params(
                "No signature for ourselves in Emergency transaction".to_string(),
            ));
        }
        if !unvault_emer_sigs.contains_key(&our_pubkey) {
            return Err(JsonRpcError::invalid_params(
                "No signature for ourselves in UnvaultEmergency transaction".to_string(),
            ));
        }

        // There is no reason for them to include an unnecessary signature, so be strict.
        let stk_keys = revaultd.stakeholders_xpubs_at(deriv_index);
        for (ref key, _) in cancel_sigs.iter() {
            if !stk_keys.contains(key) {
                return Err(JsonRpcError::invalid_params(format!(
                    "Unknown key in Cancel transaction signatures: {}",
                    key
                )));
            }
        }
        for (ref key, _) in emer_sigs.iter() {
            if !stk_keys.contains(key) {
                return Err(JsonRpcError::invalid_params(format!(
                    "Unknown key in Emergency transaction signatures: {}",
                    key
                )));
            }
        }
        for (ref key, _) in unvault_emer_sigs.iter() {
            if !stk_keys.contains(key) {
                return Err(JsonRpcError::invalid_params(format!(
                    "Unknown key in UnvaultEmergency transaction signatures: {}",
                    key
                )));
            }
        }

        // Don't share anything if we were given invalid signatures. This
        // checks for the presence (and the validity!) of a SIGHASH type flag.
        check_revocation_signatures(secp_ctx, &cancel_tx, &cancel_sigs).map_err(|e| {
            JsonRpcError::invalid_params(format!("Invalid signature in Cancel transaction: {}", e))
        })?;
        check_revocation_signatures(secp_ctx, &emergency_tx, &emer_sigs).map_err(|e| {
            JsonRpcError::invalid_params(format!(
                "Invalid signature in Emergency transaction: {}",
                e
            ))
        })?;
        check_revocation_signatures(secp_ctx, &unvault_emergency_tx, &unvault_emer_sigs).map_err(
            |e| {
                JsonRpcError::invalid_params(format!(
                    "Invalid signature in Unvault Emergency transaction: {}",
                    e
                ))
            },
        )?;

        // Ok, signatures look legit. Add them to the PSBTs in database.
        db_update_presigned_tx(
            &revaultd.db_file(),
            db_vault.id,
            cancel_db_id,
            cancel_sigs.clone(),
            secp_ctx,
        )
        .map_err(|e| internal_error!(e))?;
        db_update_presigned_tx(
            &revaultd.db_file(),
            db_vault.id,
            emer_db_id,
            emer_sigs.clone(),
            secp_ctx,
        )
        .map_err(|e| internal_error!(e))?;
        db_update_presigned_tx(
            &revaultd.db_file(),
            db_vault.id,
            unvault_emer_db_id,
            unvault_emer_sigs.clone(),
            secp_ctx,
        )
        .map_err(|e| internal_error!(e))?;

        // Share them with our felow stakeholders.
        share_rev_signatures(
            &revaultd,
            (&cancel_tx, cancel_sigs),
            (&emergency_tx, emer_sigs),
            (&unvault_emergency_tx, unvault_emer_sigs),
        )
        .map_err(|e| {
            JsonRpcError::invalid_params(format!("Error while sharing signatures: {}", e))
        })?;

        // NOTE: it will only mark it as 'securing' if it was 'funded', not if it was
        // marked as 'secured' by db_update_presigned_tx() !
        db_mark_securing_vault(&db_path, db_vault.id).map_err(|e| internal_error!(e))?;

        Ok(json!({}))
    }

    fn getunvaulttx(
        &self,
        meta: Self::Metadata,
        outpoint: OutPoint,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        stakeholder_only!(meta);
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let db_file = &revaultd.db_file();

        // We allow the call for Funded 'only' as unvaulttx would later fail if it's
        // not 'secured'.
        let vault = db_vault_by_deposit(db_file, &outpoint)
            .map_err(|e| internal_error!(e))?
            .ok_or_else(|| unknown_outpoint!(outpoint))?;
        if matches!(vault.status, VaultStatus::Unconfirmed) {
            return Err(invalid_status!(vault.status, VaultStatus::Funded));
        }

        // Derive the descriptors needed to create the UnvaultTransaction
        let deposit_descriptor = revaultd
            .deposit_descriptor
            .derive(vault.derivation_index, &revaultd.secp_ctx);
        let deposit_txin = DepositTxIn::new(
            outpoint,
            DepositTxOut::new(vault.amount, &deposit_descriptor),
        );
        let unvault_descriptor = revaultd
            .unvault_descriptor
            .derive(vault.derivation_index, &revaultd.secp_ctx);
        let cpfp_descriptor = revaultd
            .cpfp_descriptor
            .derive(vault.derivation_index, &revaultd.secp_ctx);

        let unvault_tx = UnvaultTransaction::new(
            deposit_txin,
            &unvault_descriptor,
            &cpfp_descriptor,
            revaultd.lock_time,
        )
        .map_err(|e| internal_error!(e))?;

        Ok(json!({
            "unvault_tx": unvault_tx.as_psbt_string(),
        }))
    }

    fn unvaulttx(
        &self,
        meta: Self::Metadata,
        outpoint: OutPoint,
        unvault_tx: UnvaultTransaction,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        stakeholder_only!(meta);
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let db_path = revaultd.db_file();
        let secp_ctx = &revaultd.secp_ctx;

        // If they haven't got all the signatures for the revocation transactions, we'd
        // better not send our unvault sig!
        // If the vault is already active (or more) there is no point in spamming the
        // coordinator.
        let db_vault = db_vault_by_deposit(&db_path, &outpoint)
            .map_err(|e| internal_error!(e))?
            .ok_or_else(|| unknown_outpoint!(outpoint))?;
        if !matches!(db_vault.status, VaultStatus::Secured) {
            return Err(invalid_status!(db_vault.status, VaultStatus::Funded));
        }

        // Sanity check they didn't send us a garbaged PSBT
        let (unvault_db_id, db_unvault_tx) =
            db_unvault_transaction(&db_path, db_vault.id).map_err(|e| internal_error!(e))?;
        let rpc_txid = unvault_tx.tx().wtxid();
        let db_txid = db_unvault_tx.tx().wtxid();
        if rpc_txid != db_txid {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid Unvault tx: db wtxid is '{}' but this PSBT's is '{}' ",
                db_txid, rpc_txid
            )));
        }

        let sigs = &unvault_tx
            .psbt()
            .inputs
            .get(0)
            .expect("UnvaultTransaction always has 1 input")
            .partial_sigs;
        let stk_keys = revaultd.stakeholders_xpubs_at(db_vault.derivation_index);
        let our_key = revaultd
            .our_stk_xpub_at(db_vault.derivation_index)
            .expect("We are a stakeholder, checked at the beginning.");
        // They must have included *at least* a signature for our pubkey, and must not include an
        // unnecessary signature.
        if !sigs.contains_key(&our_key) {
            return Err(JsonRpcError::invalid_params(format!(
                "No signature for ourselves ({}) in Unvault transaction",
                our_key
            )));
        }

        // There is no reason for them to include an unnecessary signature, so be strict.
        for (ref key, _) in sigs.iter() {
            if !stk_keys.contains(key) {
                return Err(JsonRpcError::invalid_params(format!(
                    "Unknown key in Cancel transaction signatures: {}",
                    key
                )));
            }
        }

        // Of course, don't send a PSBT with an invalid signature
        check_unvault_signatures(secp_ctx, &unvault_tx).map_err(|e| {
            JsonRpcError::invalid_params(format!(
                "Invalid signature in Unvault transaction: '{}'",
                e
            ))
        })?;

        // Sanity checks passed. Store it then share it.
        db_update_presigned_tx(
            &revaultd.db_file(),
            db_vault.id,
            unvault_db_id,
            sigs.clone(),
            secp_ctx,
        )
        .map_err(|e| internal_error!(e))?;
        share_unvault_signatures(&revaultd, &unvault_tx).map_err(|e| {
            JsonRpcError::invalid_params(format!(
                "Communication error while sharing Unvault signatures with coordinator: '{}'",
                e
            ))
        })?;

        // NOTE: it will only mark it as 'unvaulting' if it was 'secured', not if it was
        // marked as 'activated' by db_update_presigned_tx() !
        db_mark_activating_vault(&db_path, db_vault.id).map_err(|e| internal_error!(e))?;

        Ok(json!({}))
    }

    fn listpresignedtransactions(
        &self,
        meta: Self::Metadata,
        outpoints: Option<Vec<OutPoint>>,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let db_path = revaultd.db_file();

        // If they didn't provide us with a list of outpoints, catch'em all!
        let db_vaults = if let Some(outpoints) = outpoints {
            vaults_from_deposits(&db_path, &outpoints, &[VaultStatus::Unconfirmed])
                .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?
        } else {
            db_vaults_min_status(&db_path, VaultStatus::Funded).map_err(|e| internal_error!(e))?
        };
        let vaults = presigned_txs(&revaultd, db_vaults).map_err(|e| internal_error!(e))?;

        let vaults: Vec<serde_json::Value> = vaults
            .into_iter()
            .map(|v| {
                json!({
                    "vault_outpoint": v.outpoint,
                    "unvault": v.unvault,
                    "cancel": v.cancel,
                    "emergency": v.emergency,
                    "unvault_emergency": v.unvault_emergency,
                })
            })
            .collect();

        Ok(json!({ "presigned_transactions": vaults }))
    }

    fn listonchaintransactions(
        &self,
        meta: Self::Metadata,
        outpoints: Option<Vec<OutPoint>>,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let db_path = revaultd.db_file();

        // If they didn't provide us with a list of outpoints, catch'em all!
        let db_vaults = if let Some(outpoints) = outpoints {
            // We accept any status
            vaults_from_deposits(&db_path, &outpoints, &[])
                .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?
        } else {
            db_vaults(&db_path).map_err(|e| internal_error!(e))?
        };
        let vaults = onchain_txs(
            &meta.rpc_utils.revaultd.read().unwrap(),
            &meta.rpc_utils.bitcoind_tx,
            db_vaults,
        )
        .map_err(|e| internal_error!(e))?;

        fn wallet_tx_to_json(tx: WalletTransaction) -> serde_json::Value {
            json!({
                "blockheight": tx.blockheight.map(serde_json::Number::from),
                "received_at": serde_json::Number::from(tx.received_time),
                "hex": serde_json::Value::String(tx.hex),
            })
        }
        let vaults: Vec<serde_json::Value> = vaults
            .into_iter()
            .map(|v| {
                json!({
                    "vault_outpoint": v.outpoint,
                    "deposit": wallet_tx_to_json(v.deposit),
                    "unvault": v.unvault.map(wallet_tx_to_json),
                    "cancel": v.cancel.map(wallet_tx_to_json),
                    "emergency": v.emergency.map(wallet_tx_to_json),
                    "unvault_emergency": v.unvault_emergency.map(wallet_tx_to_json),
                    "spend": v.spend.map(wallet_tx_to_json),
                })
            })
            .collect();

        Ok(json!({
            "onchain_transactions": vaults,
        }))
    }

    fn getspendtx(
        &self,
        meta: Self::Metadata,
        outpoints: Vec<OutPoint>,
        destinations: BTreeMap<Address, u64>,
        feerate_vb: u64,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        manager_only!(meta);

        if feerate_vb < 1 {
            return Err(JsonRpcError::invalid_params(
                "Feerate can't be <1".to_string(),
            ));
        }

        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let db_file = &revaultd.db_file();

        // Reconstruct the DepositTxin s from the outpoints and the vaults informations
        let mut txins = Vec::with_capacity(outpoints.len());
        // If we need a change output, use the highest derivation index of the vaults
        // spent. This avoids leaking a new address needlessly while not introducing
        // disrepancy between our indexes.
        let mut change_index = bip32::ChildNumber::from(0);
        for outpoint in outpoints.iter() {
            let vault = db_vault_by_deposit(db_file, &outpoint)
                .map_err(|e| internal_error!(e))?
                .ok_or_else(|| unknown_outpoint!(outpoint))?;
            if matches!(vault.status, VaultStatus::Active) {
                if vault.derivation_index > change_index {
                    change_index = vault.derivation_index;
                }
                txins.push((*outpoint, vault.amount, vault.derivation_index));
            } else {
                return Err(invalid_status!(vault.status, VaultStatus::Active));
            }
        }

        // Mutable as we *may* add a change output
        let mut txos: Vec<SpendTxOut> = destinations
            .into_iter()
            .map(|(addr, value)| {
                let script_pubkey = addr.script_pubkey();
                SpendTxOut::Destination(TxOut {
                    value,
                    script_pubkey,
                })
            })
            .collect();

        log::debug!(
            "Creating a Spend transaction with deposit txins: '{:?}' and txos: '{:?}'",
            &txins,
            &txos
        );

        // This adds the CPFP output so create a dummy one to accurately compute the
        // feerate.
        let nochange_tx = spend_tx_from_deposits(
            txins.clone(),
            txos.clone(),
            &revaultd.deposit_descriptor,
            &revaultd.unvault_descriptor,
            &revaultd.cpfp_descriptor,
            revaultd.lock_time,
            /* Deactivate insane feerate check */
            false,
            &revaultd.secp_ctx,
        )
        .map_err(|e| {
            JsonRpcError::invalid_params(format!("Error while building spend transaction: {}", e))
        })?;

        log::debug!(
            "Spend tx without change: '{}'",
            nochange_tx.as_psbt_string()
        );

        // If the feerate of the transaction would be much lower (< 90/100) than what they
        // requested for, tell them.
        let nochange_feerate_vb = nochange_tx
            .max_feerate()
            .checked_mul(4)
            .expect("bug in feerate computation");
        if nochange_feerate_vb * 10 < feerate_vb * 9 {
            return Err(JsonRpcError::invalid_params(format!(
                "Required feerate ('{}') is significantly higher than actual feerate ('{}')",
                feerate_vb, nochange_feerate_vb
            )));
        }

        // Add a change output if it would not be dust according to our standard (200k sats
        // atm, see DUST_LIMIT).
        // 8 (amount) + 1 (len) + 1 (v0) + 1 (push) + 32 (witscript hash)
        const P2WSH_TXO_WEIGHT: u64 = 43 * 4;
        let with_change_weight = nochange_tx
            .max_weight()
            .checked_add(P2WSH_TXO_WEIGHT)
            .expect("weight computation bug");
        let cur_fees = nochange_tx.fees();
        let want_fees = with_change_weight
            // Mental gymnastic: sat/vbyte to sat/wu rounded up
            .checked_mul(feerate_vb + 3)
            .map(|vbyte| vbyte.checked_div(4).unwrap());
        let change_value = want_fees.map(|f| cur_fees.checked_sub(f));
        log::debug!(
            "Weight with change: '{}'  --  Fees without change: '{}'  --  Wanted feerate: '{}'  \
                    --  Wanted fees: '{:?}'  --  Change value: '{:?}'",
            with_change_weight,
            cur_fees,
            feerate_vb,
            want_fees,
            change_value
        );

        if let Some(Some(change_value)) = change_value {
            // The overhead incurred to the value of the CPFP output by the change output
            // See https://github.com/revault/practical-revault/blob/master/transactions.md#spend_tx
            let cpfp_overhead = 16 * P2WSH_TXO_WEIGHT;
            if change_value > revault_tx::transactions::DUST_LIMIT + cpfp_overhead {
                let change_txo = DepositTxOut::new(
                    // arithmetic checked above
                    Amount::from_sat(change_value - cpfp_overhead),
                    &revaultd
                        .deposit_descriptor
                        .derive(change_index, &revaultd.secp_ctx),
                );
                log::debug!("Adding a change txo: '{:?}'", change_txo);
                txos.push(SpendTxOut::Change(change_txo));
            }
        }

        // Now we can hand them the resulting transaction (sanity checked for insane fees).
        let tx_res = spend_tx_from_deposits(
            txins,
            txos,
            &revaultd.deposit_descriptor,
            &revaultd.unvault_descriptor,
            &revaultd.cpfp_descriptor,
            revaultd.lock_time,
            true,
            &revaultd.secp_ctx,
        )
        .map_err(|e| {
            JsonRpcError::invalid_params(format!("Error while building spend transaction: {}", e))
        })?;

        if !check_spend_transaction_size(&revaultd, tx_res.clone()) {
            return Err(JsonRpcError::invalid_params(format!(
                "Spend transaction is too large, try spending less outpoints"
            )));
        };
        log::debug!("Final Spend transaction: '{:?}'", tx_res);

        Ok(json!({
            "spend_tx": tx_res.as_psbt_string(),
        }))
    }

    fn updatespendtx(
        &self,
        meta: Self::Metadata,
        spend_tx: SpendTransaction,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        manager_only!(meta);
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let db_path = revaultd.db_file();
        let spend_txid = spend_tx.tx().txid();

        // Fetch the Unvault it spends from the DB
        let spend_inputs = &spend_tx.tx().input;
        let mut db_unvaults = Vec::with_capacity(spend_inputs.len());
        for txin in spend_inputs.iter() {
            let (db_vault, db_unvault) =
                db_vault_by_unvault_txid(&db_path, &txin.previous_output.txid)
                    .map_err(|e| internal_error!(e))?
                    .ok_or_else(|| {
                        JsonRpcError::invalid_params(format!(
                            "Spend transaction refers an unknown Unvault: '{}'",
                            txin.previous_output.txid
                        ))
                    })?;

            if !matches!(db_vault.status, VaultStatus::Active) {
                return Err(invalid_status!(db_vault.status, VaultStatus::Active));
            }

            db_unvaults.push(db_unvault);
        }

        if db_spend_transaction(&db_path, &spend_txid)
            .map_err(|e| internal_error!(e))?
            .is_some()
        {
            log::debug!("Updating Spend transaction '{}'", spend_txid);
            db_update_spend(&db_path, &spend_tx).map_err(|e| internal_error!(e))?;
        } else {
            log::debug!("Storing new Spend transaction '{}'", spend_txid);
            db_insert_spend(&db_path, &db_unvaults, &spend_tx).map_err(|e| internal_error!(e))?;
        }

        Ok(json!({}))
    }

    fn delspendtx(
        &self,
        meta: Self::Metadata,
        spend_txid: Txid,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        manager_only!(meta);

        let db_path = meta.rpc_utils.revaultd.read().unwrap().db_file();

        db_delete_spend(&db_path, &spend_txid)
            .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;

        Ok(json!({}))
    }

    fn listspendtxs(
        &self,
        meta: Self::Metadata,
        status: Option<Vec<ListSpendStatus>>,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        manager_only!(meta);

        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let db_path = revaultd.db_file();

        let spend_tx_map = db_list_spends(&db_path).map_err(|e| internal_error!(e))?;
        let mut listspend_entries = Vec::with_capacity(spend_tx_map.len());
        for (_, (db_spend, dep_outpoints)) in spend_tx_map {
            // Filter by status
            if let Some(s) = &status {
                let status = if let Some(true) = db_spend.broadcasted {
                    ListSpendStatus::Broadcasted
                } else if let Some(false) = db_spend.broadcasted {
                    ListSpendStatus::Pending
                } else {
                    ListSpendStatus::NonFinal
                };

                if !s.contains(&status) {
                    continue;
                }
            }

            let spent_vaults = db_vaults_from_spend(&db_path, &db_spend.psbt.txid())
                .map_err(|e| internal_error!(e))?;

            // FIXME: a temporary hack for the GUI to be able to use its signer properly. Remove
            // after the demo release in favour of having the derivation indexes in the PSBT.
            let mut deposit_outpoints = dep_outpoints.clone();
            for v in spent_vaults.values() {
                let deposit_descriptor = revaultd
                    .deposit_descriptor
                    .derive(v.derivation_index, &revaultd.secp_ctx);
                let deposit_txin = DepositTxIn::new(
                    v.deposit_outpoint,
                    DepositTxOut::new(v.amount, &deposit_descriptor),
                );
                let unvault_descriptor = revaultd
                    .unvault_descriptor
                    .derive(v.derivation_index, &revaultd.secp_ctx);
                let cpfp_descriptor = revaultd
                    .cpfp_descriptor
                    .derive(v.derivation_index, &revaultd.secp_ctx);

                let unvault_tx = UnvaultTransaction::new(
                    deposit_txin,
                    &unvault_descriptor,
                    &cpfp_descriptor,
                    revaultd.lock_time,
                )
                .map_err(|e| internal_error!(e))?;
                let i = db_spend
                    .psbt
                    .tx()
                    .input
                    .iter()
                    .position(|i| i.previous_output.txid == unvault_tx.txid())
                    .expect("Must be there, deposit_outpoints are queried by spend_tx");
                deposit_outpoints[i] = v.deposit_outpoint;
            }

            let derivation_index = spent_vaults
                .values()
                .map(|v| v.derivation_index)
                .max()
                .expect("Spent vaults should not be empty");
            let cpfp_script_pubkey = revaultd
                .cpfp_descriptor
                .derive(derivation_index, &revaultd.secp_ctx)
                .into_inner()
                .script_pubkey();
            let deposit_address = revaultd
                .deposit_descriptor
                .derive(derivation_index, &revaultd.secp_ctx)
                .into_inner()
                .script_pubkey();
            let mut cpfp_index = None;
            let mut change_index = None;
            for (i, txout) in db_spend.psbt.tx().output.iter().enumerate() {
                if cpfp_index.is_none() && cpfp_script_pubkey == txout.script_pubkey {
                    cpfp_index = Some(i);
                }

                if deposit_address == txout.script_pubkey {
                    change_index = Some(i);
                }
            }

            listspend_entries.push(ListSpendEntry {
                psbt: db_spend.psbt,
                deposit_outpoints,
                cpfp_index: cpfp_index.expect("We always create a CPFP output"),
                change_index,
            });
        }

        Ok(json!({ "spend_txs": listspend_entries }))
    }

    fn setspendtx(
        &self,
        meta: Self::Metadata,
        spend_txid: Txid,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        manager_only!(meta);

        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let db_path = revaultd.db_file();

        // Get the Spend they reference from DB
        let mut spend_tx = db_spend_transaction(&db_path, &spend_txid)
            .map_err(|e| internal_error!(e))?
            .ok_or_else(|| JsonRpcError::invalid_params("Unknown Spend transaction".to_string()))?;

        // Then check all our fellow managers already signed it
        let spent_vaults =
            db_vaults_from_spend(&db_path, &spend_txid).map_err(|e| internal_error!(e))?;
        let tx = &spend_tx.psbt.tx();
        if spent_vaults.len() < tx.input.len() {
            return Err(JsonRpcError::invalid_params(
                "Spend transaction refers to an already spent vault".to_string(),
            ));
        }
        #[cfg(debug_assertions)]
        {
            for i in tx.input.iter() {
                assert!(
                    spent_vaults.contains_key(&i.previous_output.txid),
                    "Insane DB: Spend transaction refers to unknown vaults"
                );
            }
        }
        check_spend_signatures(
            &revaultd.secp_ctx,
            revaultd.managers_threshold(),
            &spend_tx.psbt,
            revaultd.managers_xpubs(),
            &spent_vaults,
        )
        .map_err(|e| {
            JsonRpcError::invalid_params(format!(
                "Error checking Spend transaction signature: '{}'",
                e.to_string()
            ))
        })?;

        // Check that we can actually send the tx to the coordinator...
        if !check_spend_transaction_size(&revaultd, spend_tx.psbt.clone()) {
            return Err(JsonRpcError::invalid_params(format!(
                "Spend transaction is too large, try spending less outpoints"
            )));
        };

        // Now we can ask all the cosigning servers for their signatures
        log::debug!("Fetching signatures from Cosigning servers");
        fetch_cosigs_signatures(&revaultd, &mut spend_tx.psbt).map_err(|e| {
            JsonRpcError::invalid_params(format!(
                "Communication error while fetching cosigner signatures: {}",
                e,
            ))
        })?;
        let mut finalized_spend = spend_tx.psbt.clone();
        finalized_spend.finalize(&revaultd.secp_ctx).map_err(|e| {
            JsonRpcError::invalid_params(format!(
                "Invalid signature given by the cosigners, psbt: '{}' (error: '{}')",
                spend_tx.psbt.as_psbt_string(),
                e
            ))
        })?;

        // And then announce it to the Coordinator
        let deposit_outpoints: Vec<_> = spent_vaults
            .values()
            .map(|db_vault| db_vault.deposit_outpoint)
            .collect();
        announce_spend_transaction(&revaultd, finalized_spend, deposit_outpoints).map_err(|e| {
            JsonRpcError::invalid_params(format!(
                "Communication error while announcing the Spend transaction: {}",
                e
            ))
        })?;
        db_update_spend(&db_path, &spend_tx.psbt).map_err(|e| internal_error!(e))?;

        // Finally we can broadcast the Unvault(s) transaction(s) and store the Spend
        // transaction for later broadcast
        log::debug!(
            "Broadcasting Unvault transactions with ids '{:?}'",
            spent_vaults.keys()
        );
        let bitcoin_txs = spent_vaults
            .values()
            .into_iter()
            .map(|db_vault| {
                let (_, mut unvault_tx) = db_unvault_transaction(&db_path, db_vault.id)
                    .map_err(|e| internal_error!(e))?;
                unvault_tx
                    .finalize(&revaultd.secp_ctx)
                    .map_err(|e| internal_error!(e))?;
                Ok(unvault_tx.into_psbt().extract_tx())
            })
            .collect::<Result<Vec<BitcoinTransaction>, JsonRpcError>>()?;
        bitcoind_broadcast(&meta.rpc_utils.bitcoind_tx, bitcoin_txs).map_err(|e| {
            internal_error!(format!("Broadcasting Unvault transaction(s): '{}'", e))
        })?;
        db_mark_broadcastable_spend(&db_path, &spend_txid).map_err(|e| internal_error!(e))?;

        Ok(json!({}))
    }

    fn revault(
        &self,
        meta: Self::Metadata,
        deposit_outpoint: OutPoint,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let db_path = revaultd.db_file();

        // Checking that the vault is secured, otherwise we don't have the cancel
        // transaction
        let vault = db_vault_by_deposit(&db_path, &deposit_outpoint)
            .map_err(|e| internal_error!(e))?
            .ok_or_else(|| unknown_outpoint!(deposit_outpoint))?;

        if !matches!(
            vault.status,
            VaultStatus::Unvaulting | VaultStatus::Unvaulted | VaultStatus::Spending
        ) {
            return Err(invalid_status!(vault.status, VaultStatus::Unvaulting));
        }

        let (_, mut cancel_tx) = db_cancel_transaction(&db_path, vault.id)
            .map_err(|e| internal_error!(e))?
            .expect("Must be in DB post 'Secured' status");

        cancel_tx
            .finalize(&revaultd.secp_ctx)
            .map_err(|e| internal_error!(e))?;
        let transaction = cancel_tx.into_psbt().extract_tx();
        log::debug!(
            "Broadcasting Cancel transactions with id '{:?}'",
            transaction.txid()
        );
        bitcoind_broadcast(&meta.rpc_utils.bitcoind_tx, vec![transaction])
            .map_err(|e| internal_error!(format!("Broadcasting Cancel transaction: '{}'", e)))?;

        Ok(json!({}))
    }

    fn emergency(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value> {
        stakeholder_only!(meta);
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let bitcoind_tx = &meta.rpc_utils.bitcoind_tx;

        // FIXME: there is a ton of edge cases not covered here. We should additionally opt for a
        // bulk method, like broadcasting all Emergency transactions in a thread forever without
        // trying to be smart by differentiating between Emer and UnvaultEmer until we die or all
        // vaults are confirmed in the EDV.
        let emers = finalized_emer_txs(&revaultd).map_err(|e| internal_error!(e))?;
        bitcoind_broadcast(bitcoind_tx, emers).map_err(|e| internal_error!(e))?;

        Ok(json!({}))
    }
}
