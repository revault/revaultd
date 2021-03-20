//! Here we handle messages incoming from the RPC server. We only treat semantic of
//! *valid* JSONRPC2 commands here. All the communication and parsing is done in the
//! `server` mod.

use crate::{jsonrpc::UserRole, revaultd::VaultStatus, threadmessages::*};
use common::{assume_ok, VERSION};

use revault_tx::{
    bitcoin::{Address, OutPoint, Txid},
    transactions::{
        CancelTransaction, EmergencyTransaction, RevaultTransaction, SpendTransaction,
        UnvaultEmergencyTransaction, UnvaultTransaction,
    },
};

use std::{
    collections::BTreeMap,
    process,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender},
        Arc,
    },
};

use jsonrpc_core::Error as JsonRpcError;
use jsonrpc_derive::rpc;
use serde_json::json;

#[derive(Clone)]
pub struct JsonRpcMetaData {
    pub tx: Sender<RpcMessageIn>,
    pub shutdown: Arc<AtomicBool>,
    pub role: UserRole,
}
impl jsonrpc_core::Metadata for JsonRpcMetaData {}

impl JsonRpcMetaData {
    pub fn new(tx: Sender<RpcMessageIn>, role: UserRole) -> Self {
        JsonRpcMetaData {
            tx,
            shutdown: Arc::from(AtomicBool::from(false)),
            role,
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
    fn getdepositaddress(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value>;

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
    fn listspendtxs(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value>;
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

pub struct RpcImpl;
impl RpcApi for RpcImpl {
    type Metadata = JsonRpcMetaData;

    fn stop(&self, meta: JsonRpcMetaData) -> jsonrpc_core::Result<()> {
        meta.shutdown();
        meta.tx.send(RpcMessageIn::Shutdown).unwrap();
        Ok(())
    }

    fn getinfo(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value> {
        let (response_tx, response_rx) = mpsc::sync_channel(0);
        assume_ok!(
            meta.tx.send(RpcMessageIn::GetInfo(response_tx)),
            "Sending 'getinfo' to main thread"
        );
        let (net, height, progress, number_of_vaults) = assume_ok!(
            response_rx.recv(),
            "Receiving 'getinfo' result from main thread"
        );

        Ok(json!({
            "version": VERSION.to_string(),
            "network": net,
            "blockheight": height,
            "sync": progress,
            "vaults": number_of_vaults,
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

        let (response_tx, response_rx) = mpsc::sync_channel(0);
        assume_ok!(
            meta.tx
                .send(RpcMessageIn::ListVaults((statuses, outpoints), response_tx)),
            "Sending 'listvaults' to main thread"
        );
        let vaults = assume_ok!(
            response_rx.recv(),
            "Receiving 'listvaults' result from main thread"
        );
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

    fn getdepositaddress(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value> {
        let (response_tx, response_rx) = mpsc::sync_channel(0);
        assume_ok!(
            meta.tx.send(RpcMessageIn::DepositAddr(response_tx)),
            "Sending 'depositaddr' to main thread"
        );
        let address = assume_ok!(
            response_rx.recv(),
            "Receiving 'depositaddr' result from main thread"
        );

        Ok(json!({ "address": address.to_string() }))
    }

    fn getrevocationtxs(
        &self,
        meta: Self::Metadata,
        outpoint: OutPoint,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        stakeholder_only!(meta);

        let (response_tx, response_rx) = mpsc::sync_channel(0);
        assume_ok!(
            meta.tx
                .send(RpcMessageIn::GetRevocationTxs(outpoint, response_tx)),
            "Sending 'getrevocationtxs' to main thread"
        );
        let (cancel_tx, emer_tx, unemer_tx) = assume_ok!(
            response_rx.recv(),
            "Receiving 'getrevocationtxs' from main thread"
        )
        .ok_or_else(|| {
            JsonRpcError::invalid_params(format!(
                "'{}' does not refer to a known and confirmed vault",
                &outpoint,
            ))
        })?;

        Ok(json!({
            "cancel_tx": cancel_tx.as_psbt_string(),
            "emergency_tx": emer_tx.as_psbt_string(),
            "emergency_unvault_tx": unemer_tx.as_psbt_string(),
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

        let (response_tx, response_rx) = mpsc::sync_channel(0);
        assume_ok!(
            meta.tx.send(RpcMessageIn::RevocationTxs(
                (outpoint, cancel_tx, emergency_tx, unvault_emergency_tx),
                response_tx,
            )),
            "Sending 'revocationtxs' to main thread"
        );

        if let Some(err_str) =
            assume_ok!(response_rx.recv(), "Sending 'revocationtxs' to main thread")
        {
            // This could not really be related to the params, but hey.
            return Err(JsonRpcError::invalid_params(err_str));
        }

        Ok(json!({}))
    }

    fn listpresignedtransactions(
        &self,
        meta: Self::Metadata,
        outpoints: Option<Vec<OutPoint>>,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let (response_tx, response_rx) = mpsc::sync_channel(0);
        assume_ok!(
            meta.tx.send(RpcMessageIn::ListPresignedTransactions(
                outpoints,
                response_tx
            )),
            "Sending 'listpresignedtransactions' to main thread"
        );
        let vaults = assume_ok!(
            response_rx.recv(),
            "Receiving 'listpresignedtransactions' from main thread"
        )
        .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;

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
        let (response_tx, response_rx) = mpsc::sync_channel(0);
        assume_ok!(
            meta.tx.send(RpcMessageIn::ListOnchainTransactions(
                outpoints,
                response_tx
            )),
            "Sending 'listonchaintransactions' to main thread"
        );
        let vaults = assume_ok!(
            response_rx.recv(),
            "Receiving 'listonchaintransactions' from main thread"
        )
        .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;

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

    fn getunvaulttx(
        &self,
        meta: Self::Metadata,
        outpoint: OutPoint,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        stakeholder_only!(meta);

        let (response_tx, response_rx) = mpsc::sync_channel(0);
        assume_ok!(
            meta.tx
                .send(RpcMessageIn::GetUnvaultTx(outpoint, response_tx)),
            "Sending 'getunvaulttx' to main thread"
        );
        let unvault_tx = assume_ok!(
            response_rx.recv(),
            "Receiving 'getunvaulttx' from main thread"
        )
        .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;

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

        let (response_tx, response_rx) = mpsc::sync_channel(0);
        assume_ok!(
            meta.tx
                .send(RpcMessageIn::UnvaultTx((outpoint, unvault_tx), response_tx)),
            "Sending 'unvaulttx' to main thread"
        );
        assume_ok!(response_rx.recv(), "Receiving 'unvaulttx' from main thread")
            .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;

        Ok(json!({}))
    }

    fn getspendtx(
        &self,
        meta: Self::Metadata,
        outpoints: Vec<OutPoint>,
        destinations: BTreeMap<Address, u64>,
        feerate: u64,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        manager_only!(meta);

        if feerate < 1 {
            return Err(JsonRpcError::invalid_params(
                "Feerate can't be <1".to_string(),
            ));
        }

        let (response_tx, response_rx) = mpsc::sync_channel(0);
        assume_ok!(
            meta.tx.send(RpcMessageIn::GetSpendTx(
                outpoints,
                destinations,
                feerate,
                response_tx
            )),
            "Sending 'getspendtx' to main thread"
        );

        let spend_tx = assume_ok!(
            response_rx.recv(),
            "Receiving 'getspendtx' from main thread"
        )
        .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;

        Ok(json!({
            "spend_tx": spend_tx.as_psbt_string(),
        }))
    }

    fn updatespendtx(
        &self,
        meta: Self::Metadata,
        spend_tx: SpendTransaction,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        manager_only!(meta);

        let (response_tx, response_rx) = mpsc::sync_channel(0);
        assume_ok!(
            meta.tx
                .send(RpcMessageIn::UpdateSpendTx(spend_tx, response_tx)),
            "Sending 'updatespendtx' to main thread"
        );

        assume_ok!(
            response_rx.recv(),
            "Receiving 'updatespendtx' result from main thread"
        )
        .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;

        Ok(json!({}))
    }

    fn delspendtx(
        &self,
        meta: Self::Metadata,
        spend_txid: Txid,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        manager_only!(meta);

        let (response_tx, response_rx) = mpsc::sync_channel(0);
        assume_ok!(
            meta.tx
                .send(RpcMessageIn::DelSpendTx(spend_txid, response_tx)),
            "Sending 'delspendtx' to main thread"
        );

        assume_ok!(
            response_rx.recv(),
            "Receiving 'delspendtx' result from main thread"
        )
        .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;

        Ok(json!({}))
    }

    fn listspendtxs(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value> {
        manager_only!(meta);

        let (response_tx, response_rx) = mpsc::sync_channel(0);
        assume_ok!(
            meta.tx.send(RpcMessageIn::ListSpendTxs(response_tx)),
            "Sending 'listspendtxs' to main thread"
        );

        let spendtx_entries = assume_ok!(
            response_rx.recv(),
            "Receiving 'listspendtxs' result from main thread"
        )
        .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;

        Ok(json!({ "spend_txs": spendtx_entries }))
    }
}
