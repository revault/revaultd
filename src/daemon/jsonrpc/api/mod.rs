//! Here we handle messages incoming from the RPC server. We only treat semantic of
//! *valid* JSONRPC2 commands here. All the communication and parsing is done in the
//! `server` mod.

mod error;
use error::Error;

use crate::common::VERSION;
use crate::daemon::{
    bitcoind::interface::WalletTransaction,
    communication::{
        announce_spend_transaction, check_spend_transaction_size, coord_share_rev_signatures,
        coordinator_status, cosigners_status, fetch_cosigs_signatures, share_unvault_signatures,
        watchtowers_status, wts_share_emer_signatures, wts_share_second_stage_signatures,
    },
    control::{
        finalized_emer_txs, get_history, listvaults_from_db, onchain_txs, presigned_txs,
        vaults_from_deposits, HistoryEventKind, ListSpendEntry, ListSpendStatus, RpcUtils,
    },
    database::{
        actions::{
            db_delete_spend, db_insert_spend, db_mark_activating_vault,
            db_mark_broadcastable_spend, db_mark_securing_vault, db_update_presigned_txs,
            db_update_spend, db_update_vault_status,
        },
        interface::{
            db_cancel_transaction, db_emer_transaction, db_list_spends, db_spend_transaction,
            db_tip, db_unvault_emer_transaction, db_unvault_transaction, db_vault_by_deposit,
            db_vault_by_unvault_txid, db_vaults, db_vaults_from_spend, db_vaults_min_status,
        },
    },
    jsonrpc::UserRole,
    revaultd::{BlockchainTip, VaultStatus},
    threadmessages::{BitcoindThread, SigFetcherMessageOut},
};

use revault_tx::{
    bitcoin::{
        consensus::encode, secp256k1, util::bip32, Address, Amount, OutPoint,
        PublicKey as BitcoinPubKey, Transaction as BitcoinTransaction, TxOut, Txid,
    },
    miniscript::DescriptorTrait,
    transactions::{
        spend_tx_from_deposits, transaction_chain, CancelTransaction, CpfpableTransaction,
        EmergencyTransaction, RevaultTransaction, SpendTransaction, UnvaultEmergencyTransaction,
        UnvaultTransaction,
    },
    txins::DepositTxIn,
    txouts::{DepositTxOut, SpendTxOut},
};

use std::{
    collections::BTreeMap,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
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

    /// Print all available commands
    #[rpc(meta, name = "help")]
    fn help(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value>;

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
        priority: Option<bool>,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    #[rpc(meta, name = "revault")]
    fn revault(
        &self,
        meta: Self::Metadata,
        deposit_outpoint: OutPoint,
    ) -> jsonrpc_core::Result<serde_json::Value>;

    #[rpc(meta, name = "emergency")]
    fn emergency(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value>;

    #[rpc(meta, name = "getserverstatus")]
    fn getserverstatus(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value>;

    /// Retrieve the accounting history
    #[rpc(meta, name = "gethistory")]
    fn gethistory(
        &self,
        meta: Self::Metadata,
        kind: Vec<HistoryEventKind>,
        start: u32,
        end: u32,
        limit: u64,
    ) -> jsonrpc_core::Result<serde_json::Value>;
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

        meta.rpc_utils.bitcoind_conn.shutdown();
        meta.rpc_utils
            .sigfetcher_tx
            .send(SigFetcherMessageOut::Shutdown)
            .map_err(Error::from)?;
        meta.shutdown();

        Ok(())
    }

    fn getinfo(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value> {
        let progress = meta.rpc_utils.bitcoind_conn.sync_progress();

        let revaultd = meta.rpc_utils.revaultd.read().unwrap();

        let deposit_desc = &revaultd.deposit_descriptor.to_string();
        let cpfp_desc = &revaultd.cpfp_descriptor.to_string();
        let unvault_desc = &revaultd.unvault_descriptor.to_string();

        // This means blockheight == 0 for IBD.
        let BlockchainTip {
            height: blockheight,
            ..
        } = db_tip(&revaultd.db_file()).map_err(Error::from)?;

        let number_of_vaults = listvaults_from_db(&revaultd, None, None)
            .map_err(Error::from)?
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
            "descriptors": {
                "deposit": deposit_desc,
                "unvault": unvault_desc,
                "cpfp": cpfp_desc,
            },
        }))
    }

    fn help(&self, _: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value> {
        Ok(json!(
        {
            "commands": [
                {
                  "name": "getinfo",
                  "parameters": [],
                  "description": "Display general information",
                },
                {
                    "name": "getrevocationtxs",
                    "parameters": [
                        "outpoint"
                    ],
                    "description": "Retrieve the Revault revocation transactions to sign",
                },
                {
                    "name": "getunvaulttx",
                    "parameters": [
                        "outpoint"
                    ],
                    "description": "Retrieve the Revault unvault transaction to sign"
                },
                {
                    "name": "getspendtx",
                    "parameters": [
                        "outpoints",
                        "outputs",
                        "feerate",
                    ],
                    "description": "Retrieve the Revault spend transaction to sign"
                },
                {
                    "name": "listpresignedtransactions",
                    "parameters": [
                        "[outpoints]"
                    ],
                    "description": "List presigned transactions of a confirmed vault"
                },
                {
                    "name": "listonchaintransactions",
                    "parameters": [
                        "[outpoints]"
                    ],
                    "description": "List broadcast transactions of a vault"
                },
                {
                    "name": "listvaults",
                    "parameters": [
                        "[status]",
                        "[outpoints]"
                    ],
                    "description": "Display a paginated list of vaults"
                },
                {
                    "name": "revocationtxs",
                    "parameters": [],
                    "description": "Give back the revocation transactions signed"
                },
                {
                    "name": "unvaulttx",
                    "parameters": [],
                    "description": "Give back the unvault transaction signed"
                },
                {
                    "name": "updatespendtx",
                    "parameters": [],
                    "description": "Store or update the stored Spend transaction"
                },
                {
                    "name": "delspendtx",
                    "parameters": [],
                    "description": "Delete a stored Spend transaction"
                },
                {
                    "name": "setspendtx",
                    "parameters": [],
                    "description": "Announce and broadcast this Spend transaction"
                },
                {
                    "name": "listspendtxs",
                    "parameters": [],
                    "description": "List all stored Spend transactions"
                },
                {
                    "name": "gethistory",
                    "parameters": ["[kind]", "start", "end", "limit"],
                    "description": "Retrieve history of funds"
                },
                {
                    "name": "emergency",
                    "parameters": [],
                    "description": "Broadcast all Emergency signed transactions"
                }
            ]
        }
        ))
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
        .map_err(Error::from)?;

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
                    "funded_at": entry.funded_at,
                    "secured_at": entry.secured_at,
                    "delegated_at": entry.delegated_at,
                    "moved_at": entry.moved_at,
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
            .map_err(Error::from)?
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
        .map_err(Error::from)?;

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
            .map_err(Error::from)?
            .ok_or_else(|| unknown_outpoint!(outpoint))?;
        if !matches!(db_vault.status, VaultStatus::Funded) {
            return Err(invalid_status!(db_vault.status, VaultStatus::Funded));
        };

        // Sanity check they didn't send us garbaged PSBTs
        let mut cancel_db_tx = db_cancel_transaction(&db_path, db_vault.id)?
            .ok_or_else(JsonRpcError::internal_error)?;
        let rpc_txid = cancel_tx.tx().wtxid();
        let db_txid = cancel_db_tx.psbt.wtxid();
        if rpc_txid != db_txid {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid Cancel tx: db wtxid is '{}' but this PSBT's is '{}' ",
                db_txid, rpc_txid
            )));
        }
        let mut emer_db_tx = db_emer_transaction(&revaultd.db_file(), db_vault.id)?
            .ok_or_else(JsonRpcError::internal_error)?;
        let rpc_txid = emergency_tx.tx().wtxid();
        let db_txid = emer_db_tx.psbt.wtxid();
        if rpc_txid != db_txid {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid Emergency tx: db wtxid is '{}' but this PSBT's is '{}' ",
                db_txid, rpc_txid
            )));
        }
        let mut unvault_emer_db_tx = db_unvault_emer_transaction(&revaultd.db_file(), db_vault.id)?
            .ok_or_else(JsonRpcError::internal_error)?;
        let rpc_txid = unvault_emergency_tx.tx().wtxid();
        let db_txid = unvault_emer_db_tx.psbt.wtxid();
        if rpc_txid != db_txid {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid Unvault Emergency tx: db wtxid is '{}' but this PSBT's is '{}' ",
                db_txid, rpc_txid
            )));
        }

        // Alias some vars we'll reuse
        let deriv_index = db_vault.derivation_index;
        let cancel_sigs = &cancel_tx
            .psbt()
            .inputs
            .get(0)
            .expect("Cancel tx has a single input, inbefore fee bumping.")
            .partial_sigs;
        let emer_sigs = &emergency_tx
            .psbt()
            .inputs
            .get(0)
            .expect("Emergency tx has a single input, inbefore fee bumping.")
            .partial_sigs;
        let unvault_emer_sigs = &unvault_emergency_tx
            .psbt()
            .inputs
            .get(0)
            .expect("UnvaultEmergency tx has a single input, inbefore fee bumping.")
            .partial_sigs;

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

        // Add the signatures to the DB transactions.
        for (key, sig) in cancel_sigs {
            if sig.is_empty() {
                return Err(JsonRpcError::invalid_params(format!(
                    "Empty signature for key '{}' in Cancel PSBT",
                    key
                )));
            }
            let sig = secp256k1::Signature::from_der(&sig[..sig.len() - 1]).map_err(|_| {
                JsonRpcError::invalid_params("Non DER signature in Cancel PSBT".to_string())
            })?;
            cancel_db_tx
                .psbt
                .add_signature(key.key, sig, secp_ctx)
                .map_err(|e| {
                    JsonRpcError::invalid_params(format!(
                        "Invalid signature '{}' in Cancel PSBT: '{}'",
                        sig, e
                    ))
                })?;
        }
        for (key, sig) in emer_sigs {
            if sig.is_empty() {
                return Err(JsonRpcError::invalid_params(format!(
                    "Empty signature for key '{}' in Emergency PSBT",
                    key
                )));
            }
            let sig = secp256k1::Signature::from_der(&sig[..sig.len() - 1]).map_err(|_| {
                JsonRpcError::invalid_params("Non DER signature in Emergency PSBT".to_string())
            })?;
            emer_db_tx
                .psbt
                .add_signature(key.key, sig, secp_ctx)
                .map_err(|e| {
                    JsonRpcError::invalid_params(format!(
                        "Invalid signature '{}' in Emergency PSBT: '{}'",
                        sig, e
                    ))
                })?;
        }
        for (key, sig) in unvault_emer_sigs {
            if sig.is_empty() {
                return Err(JsonRpcError::invalid_params(format!(
                    "Empty signature for key '{}' in UnvaultEmergency PSBT",
                    key
                )));
            }
            let sig = secp256k1::Signature::from_der(&sig[..sig.len() - 1]).map_err(|_| {
                JsonRpcError::invalid_params(
                    "Non DER signature in UnvaultEmergency PSBT".to_string(),
                )
            })?;
            unvault_emer_db_tx
                .psbt
                .add_signature(key.key, sig, secp_ctx)
                .map_err(|e| {
                    JsonRpcError::invalid_params(format!(
                        "Invalid signature '{}' in UnvaultEmergency PSBT: '{}'",
                        sig, e
                    ))
                })?;
        }

        // Then add them to the PSBTs in database. Take care to update the vault
        // status if all signatures were given via the RPC.
        let rev_txs = vec![cancel_db_tx, emer_db_tx, unvault_emer_db_tx];
        db_update_presigned_txs(&db_path, &db_vault, rev_txs.clone(), secp_ctx)?;
        db_mark_securing_vault(&db_path, db_vault.id)?;

        // If this made the Emergency fully signed and we are a stakeholder, share
        // it with our watchtowers.
        let emer_db_tx =
            db_emer_transaction(&db_path, db_vault.id)?.ok_or_else(JsonRpcError::internal_error)?;
        if !db_vault.emer_shared && emer_db_tx.psbt.unwrap_emer().is_finalizable(secp_ctx) {
            if let Some(ref watchtowers) = revaultd.watchtowers {
                wts_share_emer_signatures(
                    &revaultd.noise_secret,
                    watchtowers,
                    db_vault.deposit_outpoint,
                    db_vault.derivation_index,
                    &emer_db_tx,
                )?;
            }
        }
        db_update_vault_status(&db_path, &db_vault)?;

        // Share them with our felow stakeholders.
        coord_share_rev_signatures(
            revaultd.coordinator_host,
            &revaultd.noise_secret,
            &revaultd.coordinator_noisekey,
            &rev_txs,
        )
        .map_err(Error::from)?;

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
            .map_err(Error::from)?
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
        .map_err(Error::from)?;

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
        let db_vault =
            db_vault_by_deposit(&db_path, &outpoint)?.ok_or_else(|| unknown_outpoint!(outpoint))?;
        if !matches!(db_vault.status, VaultStatus::Secured) {
            return Err(invalid_status!(db_vault.status, VaultStatus::Funded));
        }

        // Sanity check they didn't send us a garbaged PSBT
        let mut unvault_db_tx = db_unvault_transaction(&db_path, db_vault.id)?
            .ok_or_else(JsonRpcError::internal_error)?;
        let rpc_txid = unvault_tx.tx().wtxid();
        let db_txid = unvault_db_tx.psbt.wtxid();
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

        for (key, sig) in sigs {
            // There is no reason for them to include an unnecessary signature, so be strict.
            if !stk_keys.contains(key) {
                return Err(JsonRpcError::invalid_params(format!(
                    "Unknown key in Unvault transaction signatures: {}",
                    key
                )));
            }

            if sig.is_empty() {
                return Err(JsonRpcError::invalid_params(format!(
                    "Empty signature for key '{}' in Unvault PSBT",
                    key
                )));
            }
            let sig = secp256k1::Signature::from_der(&sig[..sig.len() - 1]).map_err(|_| {
                JsonRpcError::invalid_params("Non DER signature in Unvault PSBT".to_string())
            })?;

            unvault_db_tx
                .psbt
                .add_signature(key.key, sig, secp_ctx)
                .map_err(|e| {
                    JsonRpcError::invalid_params(format!(
                        "Invalid signature '{}' in Unvault PSBT: '{}'",
                        sig, e
                    ))
                })?;
        }

        // The watchtower(s) MUST have our second-stage (UnvaultEmer, Cancel) signatures
        // before we share the Unvault one.
        if let Some(ref watchtowers) = revaultd.watchtowers {
            let unemer_db_tx = db_unvault_emer_transaction(&db_path, db_vault.id)?
                .ok_or_else(JsonRpcError::internal_error)?;
            let cancel_db_tx = db_cancel_transaction(&db_path, db_vault.id)?
                .ok_or_else(JsonRpcError::internal_error)?;
            wts_share_second_stage_signatures(
                &revaultd.noise_secret,
                watchtowers,
                db_vault.deposit_outpoint,
                db_vault.derivation_index,
                &cancel_db_tx,
                &unemer_db_tx,
            )?;
        }

        // Sanity checks passed. Store it then share it.
        db_update_presigned_txs(&db_path, &db_vault, vec![unvault_db_tx.clone()], secp_ctx)?;
        db_mark_activating_vault(&db_path, db_vault.id)?;
        db_update_vault_status(&db_path, &db_vault)?;
        share_unvault_signatures(
            revaultd.coordinator_host,
            &revaultd.noise_secret,
            &revaultd.coordinator_noisekey,
            &unvault_db_tx,
        )
        .map_err(|e| {
            JsonRpcError::invalid_params(format!(
                "Communication error while sharing Unvault signatures with coordinator: '{}'",
                e
            ))
        })?;

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
            db_vaults_min_status(&db_path, VaultStatus::Funded).map_err(Error::from)?
        };
        let vaults = presigned_txs(&revaultd, db_vaults).map_err(Error::from)?;

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
            db_vaults(&db_path).map_err(Error::from)?
        };
        let vaults = onchain_txs(
            &meta.rpc_utils.revaultd.read().unwrap(),
            &meta.rpc_utils.bitcoind_conn,
            db_vaults,
        )
        .map_err(Error::from)?;

        fn wallet_tx_to_json(tx: WalletTransaction) -> serde_json::Value {
            json!({
                "blockheight": tx.blockheight.map(serde_json::Number::from),
                "blocktime": tx.blocktime.map(serde_json::Number::from),
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
            let vault = db_vault_by_deposit(db_file, outpoint)
                .map_err(Error::from)?
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

        let txos: Vec<SpendTxOut> = destinations
            .into_iter()
            .map(|(addr, value)| {
                let script_pubkey = addr.script_pubkey();
                SpendTxOut::new(TxOut {
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
            None, // No change :)
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
        let change_value = want_fees.map(|f| cur_fees.checked_sub(f)).flatten();
        log::debug!(
            "Weight with change: '{}'  --  Fees without change: '{}'  --  Wanted feerate: '{}'  \
                    --  Wanted fees: '{:?}'  --  Change value: '{:?}'",
            with_change_weight,
            cur_fees,
            feerate_vb,
            want_fees,
            change_value
        );

        let change_txo = change_value.and_then(|change_value| {
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
                Some(change_txo)
            } else {
                None
            }
        });

        // Now we can hand them the resulting transaction (sanity checked for insane fees).
        let tx_res = spend_tx_from_deposits(
            txins,
            txos,
            change_txo,
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
            return Err(JsonRpcError::invalid_params(
                "Spend transaction is too large, try spending less outpoints".to_string(),
            ));
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
                    .map_err(Error::from)?
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

        // The user has the ability to set priority to the transaction in
        // setspendtx, here we always set it to false.

        if db_spend_transaction(&db_path, &spend_txid)
            .map_err(Error::from)?
            .is_some()
        {
            log::debug!("Updating Spend transaction '{}'", spend_txid);
            db_update_spend(&db_path, &spend_tx, false).map_err(Error::from)?;
        } else {
            log::debug!("Storing new Spend transaction '{}'", spend_txid);
            db_insert_spend(&db_path, &db_unvaults, &spend_tx).map_err(Error::from)?;
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

        let spend_tx_map = db_list_spends(&db_path).map_err(Error::from)?;
        let mut listspend_entries = Vec::with_capacity(spend_tx_map.len());
        for (_, (db_spend, deposit_outpoints)) in spend_tx_map {
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

            let spent_vaults =
                db_vaults_from_spend(&db_path, &db_spend.psbt.txid()).map_err(Error::from)?;

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
        priority: Option<bool>,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        manager_only!(meta);

        let priority = priority.unwrap_or(false);
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let db_path = revaultd.db_file();

        if priority && revaultd.cpfp_key.is_none() {
            return Err(JsonRpcError::invalid_params(
                "Can't read the cpfp key. \
                    Make sure you have a file called cpfp_secret containing \
                    the private key in your datadir"
                    .to_string(),
            ));
        }

        // Get the referenced Spend and the vaults it spends from the DB
        let mut spend_tx = db_spend_transaction(&db_path, &spend_txid)
            .map_err(Error::from)?
            .ok_or_else(|| JsonRpcError::invalid_params("Unknown Spend transaction".to_string()))?;
        let spent_vaults = db_vaults_from_spend(&db_path, &spend_txid).map_err(Error::from)?;
        let tx = &spend_tx.psbt.tx();
        if spent_vaults.len() < tx.input.len() {
            return Err(JsonRpcError::invalid_params(
                "Spend transaction refers to an already spent vault".to_string(),
            ));
        }

        // Sanity check the Spend transaction is actually valid before announcing
        // it. revault_tx already implements the signature checks so don't duplicate
        // the logic and re-add the signatures to the PSBT.
        let signatures: Vec<BTreeMap<BitcoinPubKey, Vec<u8>>> = spend_tx
            .psbt
            .psbt()
            .inputs
            .iter()
            .map(|i| i.partial_sigs.clone())
            .collect();
        let mans_thresh = revaultd.managers_threshold();
        for (i, sigmap) in signatures.iter().enumerate() {
            if sigmap.len() < mans_thresh {
                return Err(JsonRpcError::invalid_params(format!(
                    "Not enough signatures, needed: {}, current: {}",
                    mans_thresh,
                    sigmap.len()
                )));
            }
            for (pubkey, sig) in sigmap {
                let sig = secp256k1::Signature::from_der(&sig[..sig.len() - 1]).map_err(|_| {
                    JsonRpcError::invalid_params(format!(
                        "Spend PSBT contains an invalid signature: '{}'",
                        encode::serialize_hex(&sig)
                    ))
                })?;
                spend_tx
                    .psbt
                    .add_signature(i, pubkey.key, sig, &revaultd.secp_ctx)
                    .map_err(|_| {
                        JsonRpcError::invalid_params(format!(
                            "Spend PSBT contains an invalid signature: '{}'",
                            encode::serialize_hex(&sig.serialize_der().to_vec())
                        ))
                    })?
                    .expect("The signature was already there");
            }
        }

        // Check that we can actually send the tx to the coordinator...
        if !check_spend_transaction_size(&revaultd, spend_tx.psbt.clone()) {
            return Err(JsonRpcError::invalid_params(
                "Spend transaction is too large, try spending less outpoints".to_string(),
            ));
        };

        // Now, if needed, we can ask all the cosigning servers for their
        // signatures
        let cosigs = revaultd.cosigs.as_ref().expect("We are manager");
        if !cosigs.is_empty() {
            log::debug!("Fetching signatures from Cosigning servers");
            fetch_cosigs_signatures(
                &revaultd.secp_ctx,
                &revaultd.noise_secret,
                &mut spend_tx.psbt,
                cosigs,
            )
            .map_err(|e| {
                JsonRpcError::invalid_params(format!(
                    "Communication error while fetching cosigner signatures: {}",
                    e,
                ))
            })?;
        }
        let mut finalized_spend = spend_tx.psbt.clone();
        finalized_spend.finalize(&revaultd.secp_ctx).map_err(|e| {
            JsonRpcError::invalid_params(format!(
                "Could not finalize Spend transaction, psbt: '{}' (error: '{}')",
                spend_tx.psbt, e
            ))
        })?;

        // And then announce it to the Coordinator
        let deposit_outpoints: Vec<_> = spent_vaults
            .values()
            .map(|db_vault| db_vault.deposit_outpoint)
            .collect();
        announce_spend_transaction(
            revaultd.coordinator_host,
            &revaultd.noise_secret,
            &revaultd.coordinator_noisekey,
            finalized_spend,
            deposit_outpoints,
        )
        .map_err(|e| {
            JsonRpcError::invalid_params(format!(
                "Communication error while announcing the Spend transaction: {}",
                e
            ))
        })?;
        db_update_spend(&db_path, &spend_tx.psbt, priority).map_err(Error::from)?;

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
                let mut unvault_tx = db_unvault_transaction(&db_path, db_vault.id)?
                    .ok_or_else(JsonRpcError::internal_error)?
                    .psbt
                    .assert_unvault();
                unvault_tx
                    .finalize(&revaultd.secp_ctx)
                    .map_err(Error::from)?;
                Ok(unvault_tx.into_psbt().extract_tx())
            })
            .collect::<Result<Vec<BitcoinTransaction>, JsonRpcError>>()?;
        meta.rpc_utils
            .bitcoind_conn
            .broadcast(bitcoin_txs)
            .map_err(Error::from)?;
        db_mark_broadcastable_spend(&db_path, &spend_txid).map_err(Error::from)?;

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
            .map_err(Error::from)?
            .ok_or_else(|| unknown_outpoint!(deposit_outpoint))?;

        if !matches!(
            vault.status,
            VaultStatus::Unvaulting | VaultStatus::Unvaulted | VaultStatus::Spending
        ) {
            return Err(invalid_status!(vault.status, VaultStatus::Unvaulting));
        }

        let mut cancel_tx = db_cancel_transaction(&db_path, vault.id)?
            .ok_or_else(JsonRpcError::internal_error)?
            .psbt
            .assert_cancel();

        cancel_tx
            .finalize(&revaultd.secp_ctx)
            .map_err(Error::from)?;
        let transaction = cancel_tx.into_psbt().extract_tx();
        log::debug!(
            "Broadcasting Cancel transactions with id '{:?}'",
            transaction.txid()
        );
        meta.rpc_utils
            .bitcoind_conn
            .broadcast(vec![transaction])
            .map_err(Error::from)?;

        Ok(json!({}))
    }

    fn emergency(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value> {
        stakeholder_only!(meta);
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();

        // FIXME: there is a ton of edge cases not covered here. We should additionally opt for a
        // bulk method, like broadcasting all Emergency transactions in a thread forever without
        // trying to be smart by differentiating between Emer and UnvaultEmer until we die or all
        // vaults are confirmed in the EDV.
        let emers = finalized_emer_txs(&revaultd).map_err(Error::from)?;
        meta.rpc_utils
            .bitcoind_conn
            .broadcast(emers)
            .map_err(Error::from)?;

        Ok(json!({}))
    }

    fn getserverstatus(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let coordinator = coordinator_status(&revaultd);
        let cosigners = cosigners_status(&revaultd);
        let watchtowers = watchtowers_status(&revaultd);
        Ok(json!({
            "coordinator": coordinator,
            "cosigners": cosigners,
            "watchtowers": watchtowers,
        }))
    }

    /// get_history retrieves a limited list of events which occured between two given dates.
    fn gethistory(
        &self,
        meta: Self::Metadata,
        kind: Vec<HistoryEventKind>,
        start: u32,
        end: u32,
        limit: u64,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();

        let events = get_history(
            &revaultd,
            &meta.rpc_utils.bitcoind_conn,
            start,
            end,
            limit,
            kind,
        )
        .map_err(Error::from)?;

        Ok(json!({
            "events": events,
        }))
    }
}
