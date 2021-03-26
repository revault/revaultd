//! Here we handle messages incoming from the RPC server. We only treat semantic of
//! *valid* JSONRPC2 commands here. All the communication and parsing is done in the
//! `server` mod.

use crate::{
    control::{
        announce_spend_transaction, bitcoind_broadcast_cancel, bitcoind_broadcast_unvaults,
        check_revocation_signatures, check_spend_signatures, check_unvault_signatures,
        fetch_cosigner_signatures, listvaults_from_db, onchain_txs_list_from_outpoints,
        presigned_txs_list_from_outpoints, share_rev_signatures, share_unvault_signatures,
        RpcUtils,
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
            db_vault_by_unvault_txid, db_vaults_from_spend,
        },
    },
    jsonrpc::UserRole,
    revaultd::{BlockchainTip, VaultStatus},
    threadmessages::*,
};
use common::{assume_ok, VERSION};

use revault_tx::{
    bitcoin::{util::bip32, Address, OutPoint, TxOut, Txid},
    transactions::{
        spend_tx_from_deposits, transaction_chain, CancelTransaction, EmergencyTransaction,
        RevaultTransaction, SpendTransaction, UnvaultEmergencyTransaction, UnvaultTransaction,
    },
    txins::DepositTxIn,
    txouts::{DepositTxOut, ExternalTxOut, SpendTxOut},
};

use std::{
    collections::BTreeMap,
    process,
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
            rpc_utils: rpc_utils,
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
    fn listspendtxs(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value>;

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
            message: format!("Internal error: {:?}", $error),
            data: None,
        }
    };
}

pub struct RpcImpl;
impl RpcApi for RpcImpl {
    type Metadata = JsonRpcMetaData;

    fn stop(&self, meta: JsonRpcMetaData) -> jsonrpc_core::Result<()> {
        meta.rpc_utils
            .bitcoind_tx
            .send(BitcoindMessageOut::Shutdown)
            .map_err(|e| internal_error!(e))?;
        meta.rpc_utils
            .sigfetcher_tx
            .send(SigFetcherMessageOut::Shutdown)
            .map_err(|e| internal_error!(e))?;
        assume_ok!(
            meta.rpc_utils
                .bitcoind_thread
                .write()
                .unwrap()
                .take()
                .unwrap()
                .join(),
            "Joining bitcoind thread"
        );
        assume_ok!(
            meta.rpc_utils
                .sigfetcher_thread
                .write()
                .unwrap()
                .take()
                .unwrap()
                .join(),
            "Joining sigfetcher thread"
        );
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

        // This means blockheight == 0 for IBD.
        let BlockchainTip {
            height: blockheight,
            ..
        } = db_tip(&meta.rpc_utils.revaultd.read().unwrap().db_file())
            .map_err(|e| internal_error!(e))?;

        let number_of_vaults =
            listvaults_from_db(&meta.rpc_utils.revaultd.read().unwrap(), None, None)
                .map_err(|e| internal_error!(e))?
                .iter()
                .filter(|l| {
                    l.status != VaultStatus::Spent
                        && l.status != VaultStatus::Canceled
                        && l.status != VaultStatus::Unvaulted
                        && l.status != VaultStatus::EmergencyVaulted
                })
                .collect::<Vec<_>>()
                .len();

        Ok(json!({
            "version": VERSION.to_string(),
            "network": meta.rpc_utils.revaultd.read().unwrap().bitcoind_config.network.to_string(),
            "blockheight": blockheight,
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
        let vault = match db_vault_by_deposit(db_file, &outpoint).map_err(|e| internal_error!(e))? {
            None => Err(JsonRpcError::invalid_params(format!(
                "'{}' does not refer to a known and confirmed vault",
                &outpoint,
            ))),
            Some(vault) => match vault.status {
                VaultStatus::Unconfirmed => Err(JsonRpcError::invalid_params(format!(
                    "'{}' does not refer to a known and confirmed vault",
                    &outpoint,
                ))),
                _ => Ok(vault),
            },
        }?;

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
        let db_vault =
            match db_vault_by_deposit(&db_path, &outpoint).map_err(|e| internal_error!(e))? {
                Some(v) => match v.status {
                    VaultStatus::Funded => v,
                    status => {
                        return Err(JsonRpcError::invalid_params(format!(
                            "Invalid vault status: expected {} but got {}",
                            VaultStatus::Funded,
                            status
                        )));
                    }
                },
                None => {
                    return Err(JsonRpcError::invalid_params(
                        "Outpoint does not correspond to an existing vault".to_string(),
                    ));
                }
            };

        // Sanity check they didn't send us garbaged PSBTs
        // FIXME: this may not hold true in all cases, see https://github.com/revault/revaultd/issues/145
        let (cancel_db_id, db_cancel_tx) = db_cancel_transaction(&db_path, db_vault.id)
            .map_err(|e| internal_error!(e))?
            .expect("must be here if at least in 'Funded' state");
        let rpc_txid = cancel_tx.inner_tx().global.unsigned_tx.wtxid();
        let db_txid = db_cancel_tx.inner_tx().global.unsigned_tx.wtxid();
        if rpc_txid != db_txid {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid Cancel tx: db wtxid is '{}' but this PSBT's is '{}' ",
                db_txid, rpc_txid
            )));
        }
        let (emer_db_id, db_emergency_tx) = db_emer_transaction(&revaultd.db_file(), db_vault.id)
            .map_err(|e| internal_error!(e))?;
        let rpc_txid = emergency_tx.inner_tx().global.unsigned_tx.wtxid();
        let db_txid = db_emergency_tx.inner_tx().global.unsigned_tx.wtxid();
        if rpc_txid != db_txid {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid Emergency tx: db wtxid is '{}' but this PSBT's is '{}' ",
                db_txid, rpc_txid
            )));
        }
        let (unvault_emer_db_id, db_unemergency_tx) =
            db_unvault_emer_transaction(&revaultd.db_file(), db_vault.id)
                .map_err(|e| internal_error!(e))?;
        let rpc_txid = unvault_emergency_tx.inner_tx().global.unsigned_tx.wtxid();
        let db_txid = db_unemergency_tx.inner_tx().global.unsigned_tx.wtxid();
        if rpc_txid != db_txid {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid Unvault Emergency tx: db wtxid is '{}' but this PSBT's is '{}' ",
                db_txid, rpc_txid
            )));
        }

        let deriv_index = db_vault.derivation_index;
        let cancel_sigs = cancel_tx
            .inner_tx()
            .inputs
            .get(0)
            .expect("Cancel tx has a single input, inbefore fee bumping.")
            .partial_sigs
            .clone();
        let emer_sigs = emergency_tx
            .inner_tx()
            .inputs
            .get(0)
            .expect("Emergency tx has a single input, inbefore fee bumping.")
            .partial_sigs
            .clone();
        let unvault_emer_sigs = unvault_emergency_tx
            .inner_tx()
            .inputs
            .get(0)
            .expect("UnvaultEmergency tx has a single input, inbefore fee bumping.")
            .partial_sigs
            .clone();

        // They must have included *at least* a signature for our pubkey
        let our_pubkey = revaultd
            .our_stk_xpub
            .expect("We are a stakeholder")
            .derive_pub(secp_ctx, &[deriv_index])
            .expect("The derivation index stored in the database is sane (unhardened)")
            .public_key;
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

        // Don't share anything if we were given invalid signatures. This
        // checks for the presence (and the validity!) of a SIGHASH type flag.
        if let Err(e) = check_revocation_signatures(secp_ctx, &cancel_tx, &cancel_sigs) {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid signature in Cancel transaction: {}",
                e
            )));
        }
        if let Err(e) = check_revocation_signatures(secp_ctx, &emergency_tx, &emer_sigs) {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid signature in Emergency transaction: {}",
                e
            )));
        }
        if let Err(e) =
            check_revocation_signatures(secp_ctx, &unvault_emergency_tx, &unvault_emer_sigs)
        {
            return Err(JsonRpcError::invalid_params(format!(
                "Invalid signature in Unvault Emergency transaction: {}",
                e
            )));
        }

        // Ok, signatures look legit. Add them to the PSBTs in database.
        // FIXME: edgy edge case: don't crash here, rather return an error if
        // deposit tx was reorged out in between now and the above status check.
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
        if let Err(e) = share_rev_signatures(
            &revaultd,
            (&cancel_tx, cancel_sigs),
            (&emergency_tx, emer_sigs),
            (&unvault_emergency_tx, unvault_emer_sigs),
        ) {
            return Err(JsonRpcError::invalid_params(format!(
                "Error while sharing signatures: {}",
                e
            )));
        }

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
        let vault = match db_vault_by_deposit(db_file, &outpoint).map_err(|e| internal_error!(e))? {
            None => {
                return Err(JsonRpcError::invalid_params(
                    RpcControlError::UnknownOutpoint(outpoint).to_string(),
                ));
            }
            Some(vault) => match vault.status {
                VaultStatus::Unconfirmed => {
                    return Err(JsonRpcError::invalid_params(
                        RpcControlError::InvalidStatus((vault.status, VaultStatus::Funded))
                            .to_string(),
                    ));
                }
                _ => vault,
            },
        };

        // Derive the descriptors needed to create the UnvaultTransaction
        let deposit_descriptor = revaultd
            .deposit_descriptor
            .derive(vault.derivation_index, &revaultd.secp_ctx);
        let deposit_txin = DepositTxIn::new(
            outpoint,
            DepositTxOut::new(vault.amount.as_sat(), &deposit_descriptor),
        );
        let unvault_descriptor = revaultd
            .unvault_descriptor
            .derive(vault.derivation_index, &revaultd.secp_ctx);
        let cpfp_descriptor = revaultd
            .cpfp_descriptor
            .derive(vault.derivation_index, &revaultd.secp_ctx);

        let unvault_tx =
            UnvaultTransaction::new(deposit_txin, &unvault_descriptor, &cpfp_descriptor, 0)
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
        let db_vault =
            match db_vault_by_deposit(&db_path, &outpoint).map_err(|e| internal_error!(e))? {
                None => {
                    return Err(JsonRpcError::invalid_params(
                        RpcControlError::UnknownOutpoint(outpoint).to_string(),
                    ));
                }
                Some(vault) => match vault.status {
                    VaultStatus::Secured => vault,
                    s => {
                        return Err(JsonRpcError::invalid_params(
                            RpcControlError::InvalidStatus((s, VaultStatus::Funded)).to_string(),
                        ));
                    }
                },
            };

        // Sanity check they didn't send us a garbaged PSBT
        let (unvault_db_id, db_unvault_tx) =
            db_unvault_transaction(&db_path, db_vault.id).map_err(|e| internal_error!(e))?;
        let rpc_txid = unvault_tx.inner_tx().global.unsigned_tx.wtxid();
        let db_txid = db_unvault_tx.inner_tx().global.unsigned_tx.wtxid();
        if rpc_txid != db_txid {
            return Err(JsonRpcError::invalid_params(
                RpcControlError::InvalidPsbt(format!(
                    "Invalid Unvault tx: db wtxid is '{}' but this PSBT's is '{}' ",
                    db_txid, rpc_txid
                ))
                .to_string(),
            ));
        }

        let sigs = &unvault_tx
            .inner_tx()
            .inputs
            .get(0)
            .expect("UnvaultTransaction always has 1 input")
            .partial_sigs;
        // They must have included *at least* a signature for our pubkey
        let our_pubkey = revaultd
            .our_stk_xpub
            .expect("We are a stakeholder")
            .derive_pub(secp_ctx, &[db_vault.derivation_index])
            .expect("The derivation index stored in the database is sane (unhardened)")
            .public_key;
        if !sigs.contains_key(&our_pubkey) {
            return Err(JsonRpcError::invalid_params(
                RpcControlError::InvalidPsbt(format!(
                    "No signature for ourselves ({}) in Unvault transaction",
                    our_pubkey
                ))
                .to_string(),
            ));
        }

        // Of course, don't send a PSBT with an invalid signature
        if let Err(e) = check_unvault_signatures(secp_ctx, &unvault_tx) {
            return Err(JsonRpcError::invalid_params(
                RpcControlError::InvalidPsbt(format!(
                    "Invalid signature in Unvault transaction: '{}'",
                    e
                ))
                .to_string(),
            ));
        }

        // Sanity checks passed. Store it then share it.
        // FIXME: edgy edge case: don't crash here, rather return an error if
        // deposit tx was reorged out in between now and the above status check.
        db_update_presigned_tx(
            &revaultd.db_file(),
            db_vault.id,
            unvault_db_id,
            sigs.clone(),
            secp_ctx,
        )
        .map_err(|e| internal_error!(e))?;
        if let Err(e) = share_unvault_signatures(&revaultd, &unvault_tx) {
            return Err(JsonRpcError::invalid_params(
                RpcControlError::Communication(format!(
                    "Sharing Unvault signatures with coordinator: '{}'",
                    e
                ))
                .to_string(),
            ));
        }

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
        let vaults =
            presigned_txs_list_from_outpoints(&meta.rpc_utils.revaultd.read().unwrap(), outpoints)
                .map_err(|e| internal_error!(e))?
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
        let vaults = onchain_txs_list_from_outpoints(
            &meta.rpc_utils.revaultd.read().unwrap(),
            &meta.rpc_utils.bitcoind_tx,
            outpoints,
        )
        .map_err(|e| internal_error!(e))?
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
            match db_vault_by_deposit(db_file, &outpoint).map_err(|e| internal_error!(e))? {
                Some(vault) => match vault.status {
                    VaultStatus::Active => {
                        if vault.derivation_index > change_index {
                            change_index = vault.derivation_index;
                        }
                        txins.push((*outpoint, vault.amount, vault.derivation_index));
                    }
                    status => {
                        return Err(JsonRpcError::invalid_params(
                            RpcControlError::InvalidStatus((status, VaultStatus::Active))
                                .to_string(),
                        ));
                    }
                },
                None => {
                    return Err(JsonRpcError::invalid_params(
                        RpcControlError::UnknownOutpoint(*outpoint).to_string(),
                    ));
                }
            }
        }

        // Mutable as we *may* add a change output
        let mut txos: Vec<SpendTxOut> = destinations
            .into_iter()
            .map(|(addr, value)| {
                let script_pubkey = addr.script_pubkey();
                SpendTxOut::Destination(ExternalTxOut::new(TxOut {
                    value,
                    script_pubkey,
                }))
            })
            .collect();

        log::debug!(
            "Creating a Spend transaction with deposit txins: '{:?}' and txos: '{:?}'",
            &txins,
            &txos
        );

        // This adds the CPFP output so create a dummy one to accurately compute the
        // feerate.
        let nochange_tx = match spend_tx_from_deposits(
            txins.clone(),
            txos.clone(),
            &revaultd.deposit_descriptor,
            &revaultd.unvault_descriptor,
            &revaultd.cpfp_descriptor,
            revaultd.lock_time,
            /* Deactivate insane feerate check */
            false,
            &revaultd.secp_ctx,
        ) {
            Ok(tx) => tx,
            Err(e) => {
                return Err(JsonRpcError::invalid_params(
                    RpcControlError::Transaction(e.into()).to_string(),
                ));
            }
        };

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
            return Err(JsonRpcError::invalid_params(
                RpcControlError::SpendLowFeerate(feerate_vb, nochange_feerate_vb).to_string(),
            ));
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
                    change_value - cpfp_overhead,
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
            JsonRpcError::invalid_params(RpcControlError::Transaction(e.into()).to_string())
        })?
        .as_psbt_string();
        log::debug!("Final Spend transaction: '{:?}'", tx_res);

        Ok(json!({
            "spend_tx": tx_res,
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
        let spend_txid = spend_tx.inner_tx().global.unsigned_tx.txid();

        // Fetch the Unvault it spends from the DB
        let spend_inputs = &spend_tx.inner_tx().global.unsigned_tx.input;
        let mut db_unvaults = Vec::with_capacity(spend_inputs.len());
        for txin in spend_inputs.iter() {
            let (db_vault, db_unvault) =
                match db_vault_by_unvault_txid(&db_path, &txin.previous_output.txid)
                    .map_err(|e| internal_error!(e))?
                {
                    Some(res) => res,
                    None => {
                        return Err(JsonRpcError::invalid_params(
                            RpcControlError::SpendUnknownUnvault(txin.previous_output.txid)
                                .to_string(),
                        ));
                    }
                };

            if !matches!(db_vault.status, VaultStatus::Active) {
                return Err(JsonRpcError::invalid_params(
                    RpcControlError::InvalidStatus((db_vault.status, VaultStatus::Active))
                        .to_string(),
                ));
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

    fn listspendtxs(&self, meta: Self::Metadata) -> jsonrpc_core::Result<serde_json::Value> {
        manager_only!(meta);

        let db_path = meta.rpc_utils.revaultd.read().unwrap().db_file();

        let spend_tx_map = db_list_spends(&db_path).map_err(|e| internal_error!(e))?;
        let mut listspend_entries = Vec::with_capacity(spend_tx_map.len());
        for (_, (psbt, deposit_outpoints)) in spend_tx_map {
            listspend_entries.push(ListSpendEntry {
                psbt,
                deposit_outpoints,
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
        let mut spend_tx =
            match db_spend_transaction(&db_path, &spend_txid).map_err(|e| internal_error!(e))? {
                Some(tx) => tx,
                None => {
                    return Err(JsonRpcError::invalid_params(
                        RpcControlError::UnknownSpend.to_string(),
                    ));
                }
            };

        // Then check all our fellow managers already signed it
        let spent_vaults =
            db_vaults_from_spend(&db_path, &spend_txid).map_err(|e| internal_error!(e))?;
        let tx = &spend_tx.psbt.inner_tx().global.unsigned_tx;
        if spent_vaults.len() < tx.input.len() {
            return Err(JsonRpcError::invalid_params(
                RpcControlError::AlreadySpentVault.to_string(),
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
        match check_spend_signatures(
            &revaultd.secp_ctx,
            &spend_tx.psbt,
            revaultd.managers_pubkeys.clone(),
            &spent_vaults,
        ) {
            Ok(()) => {}
            Err(e) => {
                return Err(JsonRpcError::invalid_params(
                    RpcControlError::SpendSignature(e.to_string()).to_string(),
                ));
            }
        }

        // Now we can ask all the cosigning servers for their signatures
        log::debug!("Fetching signatures from Cosigning servers");
        match fetch_cosigner_signatures(&revaultd, &mut spend_tx.psbt) {
            Ok(()) => {}
            Err(e) => {
                return Err(JsonRpcError::invalid_params(
                    RpcControlError::Communication(e.to_string()).to_string(),
                ));
            }
        }
        let mut finalized_spend = spend_tx.psbt.clone();
        match finalized_spend.finalize(&revaultd.secp_ctx) {
            Ok(()) => {}
            Err(e) => {
                return Err(JsonRpcError::invalid_params(
                    RpcControlError::CosigningServer(format!(
                        "Invalid signature given by the cosigners, psbt: '{}' (error: '{}')",
                        spend_tx.psbt.as_psbt_string(),
                        e
                    ))
                    .to_string(),
                ));
            }
        }

        // And then announce it to the Coordinator
        let deposit_outpoints = spent_vaults
            .values()
            .map(|db_vault| db_vault.deposit_outpoint)
            .collect();
        match announce_spend_transaction(&revaultd, finalized_spend, deposit_outpoints) {
            Ok(()) => {}
            Err(e) => {
                return Err(JsonRpcError::invalid_params(
                    RpcControlError::Communication(e.to_string()).to_string(),
                ));
            }
        }
        db_update_spend(&db_path, &spend_tx.psbt).map_err(|e| internal_error!(e))?;

        // Finally we can broadcast the Unvault(s) transaction(s) and store the Spend
        // transaction for later broadcast
        match bitcoind_broadcast_unvaults(
            &meta.rpc_utils.bitcoind_tx,
            &meta.rpc_utils.revaultd.read().unwrap().db_file(),
            &revaultd.secp_ctx,
            &spent_vaults,
        ) {
            Ok(()) => {}
            Err(e) => {
                return Err(JsonRpcError::invalid_params(
                    RpcControlError::UnvaultBroadcast(e.to_string()).to_string(),
                ));
            }
        }
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
        let vault = if let Some(vault) =
            db_vault_by_deposit(&db_path, &deposit_outpoint).map_err(|e| internal_error!(e))?
        {
            match vault.status {
                VaultStatus::Unvaulting | VaultStatus::Unvaulted | VaultStatus::Spending => vault,
                _ => {
                    return Err(JsonRpcError::invalid_params(
                        RpcControlError::InvalidStatus((vault.status, VaultStatus::Unvaulting))
                            .to_string(),
                    ));
                }
            }
        } else {
            return Err(JsonRpcError::invalid_params(
                RpcControlError::UnknownOutpoint(deposit_outpoint).to_string(),
            ));
        };

        bitcoind_broadcast_cancel(
            &meta.rpc_utils.bitcoind_tx,
            &db_path,
            &revaultd.secp_ctx,
            vault,
        )
        .map_err(|e| {
            JsonRpcError::invalid_params(
                RpcControlError::CancelBroadcast(e.to_string()).to_string(),
            )
        })?;

        Ok(json!({}))
    }
}
