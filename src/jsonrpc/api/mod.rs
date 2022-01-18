//! Here we handle messages incoming from the RPC server. We only treat semantic of
//! *valid* JSONRPC2 commands here. All the communication and parsing is done in the
//! `server` mod.

mod error;

use crate::{
    commands::{
        del_spend_tx, emergency, get_history, get_servers_statuses, get_spend_tx, get_unvault_tx,
        getinfo, getrevocationtxs, list_spend_txs, listvaults, onchain_transactions,
        presigned_transactions, revault, revocationtxs, set_spend_tx, set_unvault_tx,
        update_spend_tx, HistoryEventKind, ListSpendStatus,
    },
    revaultd::VaultStatus,
    DaemonControl,
};

use revault_tx::{
    bitcoin::{util::bip32, Address, OutPoint, Txid},
    transactions::{
        CancelTransaction, EmergencyTransaction, SpendTransaction, UnvaultEmergencyTransaction,
        UnvaultTransaction,
    },
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
    pub rpc_utils: DaemonControl,
}
impl jsonrpc_core::Metadata for JsonRpcMetaData {}

impl JsonRpcMetaData {
    pub fn new(rpc_utils: DaemonControl) -> Self {
        JsonRpcMetaData {
            shutdown: Arc::from(AtomicBool::from(false)),
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
        // Stop the server loop. Caller will clean up itself.
        meta.shutdown();
        Ok(())
    }

    fn getinfo(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let bitcoind = meta.rpc_utils.bitcoind_conn;

        Ok(json!(getinfo(&revaultd, &bitcoind)))
    }

    fn help(&self, _: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value> {
        Ok(json!({
            "stop": [

            ],
            "getinfo": [

            ],
            "getdepositaddress": [
                "[index]",
            ],
            "getserverstatus": [

            ],
            "listvaults": [
                "[status]",
                "[outpoints]",
            ],
            "listpresignedtransactions": [
                "[outpoints]",
            ],
            "listonchaintransactions": [
                "[outpoints]",
            ],
            "getrevocationtxs": [
                "outpoint",
            ],
            "revocationtxs": [

            ],
            "getunvaulttx": [
                "outpoint",
            ],
            "unvaulttx": [

            ],
            "getspendtx": [
                "outpoints",
                "outputs",
                "feerate",
            ],
            "updatespendtx": [
                "spend_tx",
            ],
            "delspendtx": [
                "spend_txid",
            ],
            "listspendtxs": [

            ],
            "setspendtx": [
                "spend_txid",
                "[priority]",
            ],
            "gethistory": [
                "[kind]",
                "cursor",
                "limit",
                "kind",
            ],
            "emergency": [

            ],
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

        let res = listvaults(
            &meta.rpc_utils.revaultd.read().unwrap(),
            statuses,
            outpoints,
        );
        Ok(json!(res))
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
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let res = getrevocationtxs(&revaultd, outpoint)?;

        Ok(json!(res))
    }

    fn revocationtxs(
        &self,
        meta: Self::Metadata,
        outpoint: OutPoint,
        cancel_tx: CancelTransaction,
        emergency_tx: EmergencyTransaction,
        unvault_emergency_tx: UnvaultEmergencyTransaction,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        revocationtxs(
            &revaultd,
            outpoint,
            cancel_tx,
            emergency_tx,
            unvault_emergency_tx,
        )?;

        Ok(json!({}))
    }

    fn getunvaulttx(
        &self,
        meta: Self::Metadata,
        outpoint: OutPoint,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let unvault_tx = get_unvault_tx(&revaultd, outpoint)?;

        Ok(json!({
            "unvault_tx": unvault_tx,
        }))
    }

    fn unvaulttx(
        &self,
        meta: Self::Metadata,
        outpoint: OutPoint,
        unvault_tx: UnvaultTransaction,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();

        set_unvault_tx(&revaultd, outpoint, unvault_tx)?;

        Ok(json!({}))
    }

    fn listpresignedtransactions(
        &self,
        meta: Self::Metadata,
        outpoints: Option<Vec<OutPoint>>, // FIXME: this needs not be a Vec
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();

        let pres_txs = presigned_transactions(&revaultd, &outpoints.as_deref().unwrap_or(&[]))?;
        Ok(json!({ "presigned_transactions": pres_txs }))
    }

    fn listonchaintransactions(
        &self,
        meta: Self::Metadata,
        outpoints: Option<Vec<OutPoint>>,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let bitcoind = meta.rpc_utils.bitcoind_conn;

        let txs = onchain_transactions(&revaultd, &bitcoind, &outpoints.as_deref().unwrap_or(&[]))?;
        Ok(json!({
            "onchain_transactions": txs,
        }))
    }

    fn getspendtx(
        &self,
        meta: Self::Metadata,
        outpoints: Vec<OutPoint>,
        destinations: BTreeMap<Address, u64>,
        feerate_vb: u64,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        if feerate_vb < 1 {
            return Err(JsonRpcError::invalid_params(
                "Feerate can't be <1".to_string(),
            ));
        }

        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let tx = get_spend_tx(&revaultd, &outpoints, destinations, feerate_vb)?;
        Ok(json!({
            "spend_tx": tx,
        }))
    }

    fn updatespendtx(
        &self,
        meta: Self::Metadata,
        spend_tx: SpendTransaction,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        update_spend_tx(&revaultd, spend_tx)?;

        Ok(json!({}))
    }

    fn delspendtx(
        &self,
        meta: Self::Metadata,
        spend_txid: Txid,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        del_spend_tx(&revaultd, &spend_txid)?;

        Ok(json!({}))
    }

    fn listspendtxs(
        &self,
        meta: Self::Metadata,
        status: Option<Vec<ListSpendStatus>>,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let txs = list_spend_txs(&revaultd, status.as_deref())?;

        Ok(json!({ "spend_txs": txs }))
    }

    fn setspendtx(
        &self,
        meta: Self::Metadata,
        spend_txid: Txid,
        priority: Option<bool>,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let priority = priority.unwrap_or(false);
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let bitcoind = meta.rpc_utils.bitcoind_conn;
        set_spend_tx(&revaultd, &bitcoind, &spend_txid, priority)?;

        Ok(json!({}))
    }

    fn revault(
        &self,
        meta: Self::Metadata,
        deposit_outpoint: OutPoint,
    ) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let bitcoind = meta.rpc_utils.bitcoind_conn;
        revault(&revaultd, &bitcoind, &deposit_outpoint)?;

        Ok(json!({}))
    }

    fn emergency(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let bitcoind = meta.rpc_utils.bitcoind_conn;
        emergency(&revaultd, &bitcoind)?;

        Ok(json!({}))
    }

    fn getserverstatus(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value> {
        let revaultd = meta.rpc_utils.revaultd.read().unwrap();
        let status = get_servers_statuses(&revaultd);
        Ok(json!(status))
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
        )?;

        Ok(json!({
            "events": events,
        }))
    }
}
