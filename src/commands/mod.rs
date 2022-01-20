//! # Revault daemon command interface.
//!
//! This module regroups multiple commands to query or alter the state of the Revault daemon.
//! All commands here assume an accessible and sane database. They will **panic** on a failure
//! to query it.

mod utils;
pub use crate::{
    bitcoind::{interface::WalletTransaction, BitcoindError},
    communication::ServerStatus,
    revaultd::{BlockchainTip, VaultStatus},
};
use crate::{
    communication::{
        announce_spend_transaction, check_spend_transaction_size, coord_share_rev_signatures,
        coordinator_status, cosigners_status, fetch_cosigs_signatures, share_unvault_signatures,
        watchtowers_status, wts_share_rev_signatures, CommunicationError,
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
    threadmessages::BitcoindThread,
    DaemonControl, VERSION,
};
use utils::{
    deser_amount_from_sats, deser_from_str, finalized_emer_txs, gethistory, listvaults_from_db,
    presigned_txs, ser_amount, ser_to_string, serialize_option_tx_hex, vaults_from_deposits,
};

use revault_tx::{
    bitcoin::{
        consensus::encode, secp256k1, util::bip32, Address, Amount, Network, OutPoint,
        PublicKey as BitcoinPubKey, Transaction as BitcoinTransaction, TxOut, Txid,
    },
    miniscript::DescriptorTrait,
    scripts::{CpfpDescriptor, DepositDescriptor, UnvaultDescriptor},
    transactions::{
        spend_tx_from_deposits, transaction_chain, CancelTransaction, CpfpableTransaction,
        EmergencyTransaction, RevaultTransaction, SpendTransaction, UnvaultEmergencyTransaction,
        UnvaultTransaction,
    },
    txins::DepositTxIn,
    txouts::{DepositTxOut, SpendTxOut},
};

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

/// An error raised when calling a command
#[derive(Debug)]
pub enum CommandError {
    UnknownOutpoint(OutPoint),
    /// (Got, Expected)
    InvalidStatus(VaultStatus, VaultStatus),
    InvalidStatusFor(VaultStatus, OutPoint),
    // TODO: remove in favour of specific variants
    InvalidParams(String),
    Communication(CommunicationError),
    Bitcoind(BitcoindError),
    Tx(revault_tx::Error),
    /// (Required, Actual)
    SpendFeerateTooLow(u64, u64),
    SpendTooLarge,
    SpendUnknownUnVault(Txid),
    UnknownSpend(Txid),
    SpendSpent(Txid),
    /// (Got, Expected)
    SpendNotEnoughSig(usize, usize),
    SpendInvalidSig(Vec<u8>),
    MissingCpfpKey,
    ManagerOnly,
    StakeholderOnly,
    Race,
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::UnknownOutpoint(op) => write!(f, "No vault at '{}'", op),
            Self::InvalidStatus(got, expected) => {
                write!(f, "Invalid vault status: '{}'. Need '{}'.", got, expected)
            }
            Self::InvalidStatusFor(status, outpoint) => write!(
                f,
                "Invalid vault status '{}' for deposit outpoint '{}'",
                status, outpoint
            ),
            Self::InvalidParams(e) => write!(f, "{}", e),
            Self::Communication(e) => write!(f, "Communication error: '{}'", e),
            Self::Bitcoind(e) => write!(f, "Bitcoind error: '{}'", e),
            Self::Tx(e) => write!(f, "Transaction related error: '{}'", e),
            Self::SpendFeerateTooLow(req, actual) => write!(
                f,
                "Required feerate ('{}') is significantly higher than actual feerate ('{}')",
                req, actual
            ),
            Self::SpendTooLarge => write!(
                f,
                "Spend transaction is too large, try spending less outpoints"
            ),
            Self::SpendUnknownUnVault(txid) => {
                write!(f, "Spend transaction refers an unknown Unvault: '{}'", txid)
            }
            Self::UnknownSpend(txid) => {
                write!(f, "Unknown Spend transaction '{}'", txid)
            }
            Self::SpendSpent(txid) => {
                write!(f, "Spend '{}' refers to a spent vault", txid)
            }
            Self::MissingCpfpKey => {
                write!(
                    f,
                    "Can't read the cpfp key. Make sure you have a file called \
                     cpfp_secret containing the private key in your datadir and \
                     restart the daemon."
                )
            }
            Self::SpendNotEnoughSig(got, req) => {
                write!(
                    f,
                    "Not enough signatures, needed: {}, current: {}",
                    req, got
                )
            }
            Self::SpendInvalidSig(sig) => {
                write!(
                    f,
                    "Spend PSBT contains an invalid signature: '{}'",
                    encode::serialize_hex(&sig)
                )
            }
            Self::StakeholderOnly => {
                write!(f, "This is a stakeholder command")
            }
            Self::ManagerOnly => {
                write!(f, "This is a manager command")
            }
            Self::Race => write!(f, "Internal error due to a race. Please try again."),
        }
    }
}

impl std::error::Error for CommandError {}

impl From<BitcoindError> for CommandError {
    fn from(e: BitcoindError) -> Self {
        Self::Bitcoind(e)
    }
}

impl From<CommunicationError> for CommandError {
    fn from(e: CommunicationError) -> Self {
        Self::Communication(e)
    }
}

impl From<revault_tx::Error> for CommandError {
    fn from(e: revault_tx::Error) -> Self {
        Self::Tx(e)
    }
}

impl CommandError {
    pub fn code(&self) -> ErrorCode {
        match self {
            CommandError::UnknownOutpoint(_) => ErrorCode::RESOURCE_NOT_FOUND_ERROR,
            CommandError::InvalidStatus(..) => ErrorCode::INVALID_STATUS_ERROR,
            CommandError::InvalidStatusFor(..) => ErrorCode::INVALID_STATUS_ERROR,
            CommandError::InvalidParams(_) => ErrorCode::INVALID_PARAMS,
            CommandError::Communication(e) => match e {
                CommunicationError::Net(_) => ErrorCode::TRANSPORT_ERROR,
                CommunicationError::WatchtowerNack(_, _) => ErrorCode::WT_SIG_NACK,
                CommunicationError::SignatureStorage => ErrorCode::COORDINATOR_SIG_STORE_ERROR,
                CommunicationError::SpendTxStorage => ErrorCode::COORDINATOR_SPEND_STORE_ERROR,
                CommunicationError::CosigAlreadySigned => ErrorCode::COSIGNER_ALREADY_SIGN_ERROR,
                CommunicationError::CosigInsanePsbt => ErrorCode::COSIGNER_INSANE_ERROR,
            },
            CommandError::Bitcoind(_) => ErrorCode::BITCOIND_ERROR,
            CommandError::Tx(_) => ErrorCode::INTERNAL_ERROR,
            CommandError::SpendFeerateTooLow(_, _) => ErrorCode::INVALID_PARAMS,
            // TODO: some of these probably need specific error codes
            CommandError::SpendTooLarge
            | CommandError::SpendUnknownUnVault(_)
            | CommandError::UnknownSpend(_)
            | CommandError::SpendSpent(_)
            | CommandError::SpendNotEnoughSig(_, _)
            | CommandError::SpendInvalidSig(_)
            | CommandError::MissingCpfpKey => ErrorCode::INVALID_PARAMS,

            CommandError::StakeholderOnly | CommandError::ManagerOnly => ErrorCode::INVALID_REQUEST,
            CommandError::Race => ErrorCode::INTERNAL_ERROR,
        }
    }
}

#[allow(non_camel_case_types)]
pub enum ErrorCode {
    /// Invalid Params (identical to jsonrpc error code)
    INVALID_PARAMS = -32602,
    /// Invalid Request (identical to jsonrpc error code)
    INVALID_REQUEST = -32600,
    /// Internal error (identical to jsonrpc error code)
    INTERNAL_ERROR = -32603,
    /// An error internal to revault_net, generally a transport error
    TRANSPORT_ERROR = 12000,
    /// The watchtower refused our signatures
    WT_SIG_NACK = 13_000,
    /// The Coordinator told us they could not store our signature
    COORDINATOR_SIG_STORE_ERROR = 13100,
    /// The Coordinator told us they could not store our Spend transaction
    COORDINATOR_SPEND_STORE_ERROR = 13101,
    /// The Cosigning Server returned null to our request!
    COSIGNER_ALREADY_SIGN_ERROR = 13201,
    /// The Cosigning Server tried to fool us!
    COSIGNER_INSANE_ERROR = 13202,
    /// Bitcoind error
    BITCOIND_ERROR = 14000,
    /// Resource not found
    RESOURCE_NOT_FOUND_ERROR = 15000,
    /// Vault status was invalid
    INVALID_STATUS_ERROR = 15001,
}

macro_rules! stakeholder_only {
    ($revaultd:ident) => {
        if !$revaultd.is_stakeholder() {
            return Err(CommandError::StakeholderOnly);
        }
    };
}

macro_rules! manager_only {
    ($revaultd:ident) => {
        if !$revaultd.is_manager() {
            return Err(CommandError::ManagerOnly);
        }
    };
}

impl DaemonControl {
    /// Get information about the current state of the daemon
    pub fn get_info(&self) -> GetInfoResult {
        let revaultd = self.revaultd.read().unwrap();

        // This means blockheight == 0 for IBD.
        let BlockchainTip {
            height: blockheight,
            ..
        } = db_tip(&revaultd.db_file()).expect("Database must not be dead");
        let number_of_vaults = self
            .list_vaults(None, None)
            .iter()
            .filter(|l| {
                l.status != VaultStatus::Spent
                    && l.status != VaultStatus::Canceled
                    && l.status != VaultStatus::Unvaulted
                    && l.status != VaultStatus::EmergencyVaulted
            })
            .count();

        GetInfoResult {
            version: VERSION.to_string(),
            network: revaultd.bitcoind_config.network,
            blockheight: blockheight as i32,
            sync: self.bitcoind_conn.sync_progress(),
            vaults: number_of_vaults,
            managers_threshold: revaultd.managers_threshold(),
            descriptors: GetInfoDescriptors {
                deposit: revaultd.deposit_descriptor.clone(),
                unvault: revaultd.unvault_descriptor.clone(),
                cpfp: revaultd.cpfp_descriptor.clone(),
            },
        }
    }

    /// List the current vaults, optionally filtered by status and/or deposit outpoints.
    pub fn list_vaults(
        &self,
        statuses: Option<&[VaultStatus]>,
        deposit_outpoints: Option<&[OutPoint]>,
    ) -> Vec<ListVaultsEntry> {
        let revaultd = self.revaultd.read().unwrap();
        listvaults_from_db(&revaultd, statuses, deposit_outpoints)
            .expect("Database must be available")
    }

    /// Get the deposit address at the lowest still unused derivation index
    pub fn get_deposit_address(&self) -> Address {
        self.revaultd.read().unwrap().deposit_address()
    }

    // Internal only, used for testing
    pub(crate) fn get_deposit_address_at(&self, index: bip32::ChildNumber) -> Address {
        self.revaultd.read().unwrap().vault_address(index)
    }

    /// Get the revocation transactions for the vault identified by this outpoint.
    /// Returns None if there are no *confirmed* vault at this outpoint.
    ///
    /// ## Errors
    /// - If called by a non-stakeholder
    /// - If called for an unknown or unconfirmed vault
    pub fn get_revocation_txs(
        &self,
        deposit_outpoint: OutPoint,
    ) -> Result<RevocationTransactions, CommandError> {
        let revaultd = self.revaultd.read().unwrap();
        stakeholder_only!(revaultd);
        let db_path = &revaultd.db_file();

        // First, make sure the vault exists and is confirmed.
        let vault = db_vault_by_deposit(db_path, &deposit_outpoint)
            .expect("Database must be available")
            .ok_or_else(|| CommandError::UnknownOutpoint(deposit_outpoint))?;
        if matches!(vault.status, VaultStatus::Unconfirmed) {
            return Err(CommandError::InvalidStatus(
                vault.status,
                VaultStatus::Funded,
            ));
        };

        let emer_address = revaultd
            .emergency_address
            .clone()
            .expect("Must be stakeholder");
        let (_, cancel_tx, emergency_tx, emergency_unvault_tx) = transaction_chain(
            deposit_outpoint,
            vault.amount,
            &revaultd.deposit_descriptor,
            &revaultd.unvault_descriptor,
            &revaultd.cpfp_descriptor,
            vault.derivation_index,
            emer_address,
            revaultd.lock_time,
            &revaultd.secp_ctx,
        )
        .expect("We wouldn't have put a vault with an invalid chain in DB");

        Ok(RevocationTransactions {
            cancel_tx,
            emergency_tx,
            emergency_unvault_tx,
        })
    }

    /// Set the signed revocation transactions for the vault at this outpoint.
    ///
    /// ## Errors
    /// - If called for a non-stakeholder
    /// - If called for an unknown or not 'funded' vault
    /// - If given insane revocation txs PSBTs (without our signatures, with invalid sigs, ..)
    pub fn set_revocation_txs(
        &self,
        deposit_outpoint: OutPoint,
        cancel_tx: CancelTransaction,
        emergency_tx: EmergencyTransaction,
        unvault_emergency_tx: UnvaultEmergencyTransaction,
    ) -> Result<(), CommandError> {
        let revaultd = self.revaultd.read().unwrap();
        stakeholder_only!(revaultd);
        let db_path = revaultd.db_file();
        let secp_ctx = &revaultd.secp_ctx;

        assert!(revaultd.is_stakeholder());

        // They may only send revocation transactions for confirmed and not-yet-presigned
        // vaults.
        let db_vault = db_vault_by_deposit(&db_path, &deposit_outpoint)
            .expect("Database must be available")
            .ok_or_else(|| CommandError::UnknownOutpoint(deposit_outpoint))?;
        if !matches!(db_vault.status, VaultStatus::Funded) {
            return Err(CommandError::InvalidStatus(
                db_vault.status,
                VaultStatus::Funded,
            ));
        };

        // Sanity check they didn't send us garbaged PSBTs
        let mut cancel_db_tx = db_cancel_transaction(&db_path, db_vault.id)
            .expect("The database must be available")
            .ok_or(CommandError::Race)?;
        let rpc_txid = cancel_tx.tx().wtxid();
        let db_txid = cancel_db_tx.psbt.wtxid();
        if rpc_txid != db_txid {
            return Err(CommandError::InvalidParams(format!(
                "Invalid Cancel tx: db wtxid is '{}' but this PSBT's is '{}' ",
                db_txid, rpc_txid
            )));
        }
        let mut emer_db_tx = db_emer_transaction(&revaultd.db_file(), db_vault.id)
            .expect("The database must be available")
            .ok_or(CommandError::Race)?;
        let rpc_txid = emergency_tx.tx().wtxid();
        let db_txid = emer_db_tx.psbt.wtxid();
        if rpc_txid != db_txid {
            return Err(CommandError::InvalidParams(format!(
                "Invalid Emergency tx: db wtxid is '{}' but this PSBT's is '{}' ",
                db_txid, rpc_txid
            )));
        }
        let mut unvault_emer_db_tx = db_unvault_emer_transaction(&revaultd.db_file(), db_vault.id)
            .expect("The database must be available")
            .ok_or(CommandError::Race)?;
        let rpc_txid = unvault_emergency_tx.tx().wtxid();
        let db_txid = unvault_emer_db_tx.psbt.wtxid();
        if rpc_txid != db_txid {
            return Err(CommandError::InvalidParams(format!(
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
            return Err(CommandError::InvalidParams(format!(
                "No signature for ourselves ({}) in Cancel transaction",
                our_pubkey
            )));
        }
        // We use the same public key across the transaction chain, that's pretty
        // neat from an usability perspective.
        if !emer_sigs.contains_key(&our_pubkey) {
            return Err(CommandError::InvalidParams(
                "No signature for ourselves in Emergency transaction".to_string(),
            ));
        }
        if !unvault_emer_sigs.contains_key(&our_pubkey) {
            return Err(CommandError::InvalidParams(
                "No signature for ourselves in UnvaultEmergency transaction".to_string(),
            ));
        }

        // There is no reason for them to include an unnecessary signature, so be strict.
        let stk_keys = revaultd.stakeholders_xpubs_at(deriv_index);
        for (ref key, _) in cancel_sigs.iter() {
            if !stk_keys.contains(key) {
                return Err(CommandError::InvalidParams(format!(
                    "Unknown key in Cancel transaction signatures: {}",
                    key
                )));
            }
        }
        for (ref key, _) in emer_sigs.iter() {
            if !stk_keys.contains(key) {
                return Err(CommandError::InvalidParams(format!(
                    "Unknown key in Emergency transaction signatures: {}",
                    key
                )));
            }
        }
        for (ref key, _) in unvault_emer_sigs.iter() {
            if !stk_keys.contains(key) {
                return Err(CommandError::InvalidParams(format!(
                    "Unknown key in UnvaultEmergency transaction signatures: {}",
                    key
                )));
            }
        }

        // Add the signatures to the DB transactions.
        for (key, sig) in cancel_sigs {
            if sig.is_empty() {
                return Err(CommandError::InvalidParams(format!(
                    "Empty signature for key '{}' in Cancel PSBT",
                    key
                )));
            }
            let sig = secp256k1::Signature::from_der(&sig[..sig.len() - 1]).map_err(|_| {
                CommandError::InvalidParams(format!("Non DER signature in Cancel PSBT"))
            })?;
            cancel_db_tx
                .psbt
                .add_signature(key.key, sig, secp_ctx)
                .map_err(|e| {
                    CommandError::InvalidParams(format!(
                        "Invalid signature '{}' in Cancel PSBT: '{}'",
                        sig, e
                    ))
                })?;
        }
        for (key, sig) in emer_sigs {
            if sig.is_empty() {
                return Err(CommandError::InvalidParams(format!(
                    "Empty signature for key '{}' in Emergency PSBT",
                    key
                )));
            }
            let sig = secp256k1::Signature::from_der(&sig[..sig.len() - 1]).map_err(|_| {
                CommandError::InvalidParams(format!("Non DER signature in Emergency PSBT"))
            })?;
            emer_db_tx
                .psbt
                .add_signature(key.key, sig, secp_ctx)
                .map_err(|e| {
                    CommandError::InvalidParams(format!(
                        "Invalid signature '{}' in Emergency PSBT: '{}'",
                        sig, e
                    ))
                })?;
        }
        for (key, sig) in unvault_emer_sigs {
            if sig.is_empty() {
                return Err(CommandError::InvalidParams(format!(
                    "Empty signature for key '{}' in UnvaultEmergency PSBT",
                    key
                )));
            }
            let sig = secp256k1::Signature::from_der(&sig[..sig.len() - 1]).map_err(|_| {
                CommandError::InvalidParams(format!("Non DER signature in UnvaultEmergency PSBT",))
            })?;
            unvault_emer_db_tx
                .psbt
                .add_signature(key.key, sig, secp_ctx)
                .map_err(|e| {
                    CommandError::InvalidParams(format!(
                        "Invalid signature '{}' in UnvaultEmergency PSBT: '{}'",
                        sig, e
                    ))
                })?;
        }

        // Then add them to the PSBTs in database. Take care to update the vault
        // status if all signatures were given via the RPC.
        let rev_txs = vec![cancel_db_tx, emer_db_tx, unvault_emer_db_tx];
        db_update_presigned_txs(&db_path, &db_vault, rev_txs.clone(), secp_ctx)
            .expect("The database must be available");
        db_mark_securing_vault(&db_path, db_vault.id).expect("The database must be available");

        // Now, check whether this made all revocation transactions fully signed
        let emer_tx = db_emer_transaction(&db_path, db_vault.id)
            .expect("Database must be available")
            .ok_or(CommandError::Race)?;
        let cancel_tx = db_cancel_transaction(&db_path, db_vault.id)
            .expect("Database must be available")
            .ok_or(CommandError::Race)?;
        let unemer_tx = db_unvault_emer_transaction(&db_path, db_vault.id)
            .expect("Database must be available")
            .ok_or(CommandError::Race)?;
        let all_rev_fully_signed = emer_tx
            .psbt
            .unwrap_emer()
            .is_finalizable(&revaultd.secp_ctx)
            && cancel_tx
                .psbt
                .unwrap_cancel()
                .is_finalizable(&revaultd.secp_ctx)
            && unemer_tx
                .psbt
                .unwrap_unvault_emer()
                .is_finalizable(&revaultd.secp_ctx);

        // If it did, share their signatures with our watchtowers
        if all_rev_fully_signed {
            if let Some(ref watchtowers) = revaultd.watchtowers {
                wts_share_rev_signatures(
                    &revaultd.noise_secret,
                    &watchtowers,
                    db_vault.deposit_outpoint,
                    db_vault.derivation_index,
                    &emer_tx,
                    &cancel_tx,
                    &unemer_tx,
                )?;
            }
        }
        db_update_vault_status(&db_path, &db_vault).expect("The database must be available");

        // Share them with our felow stakeholders.
        coord_share_rev_signatures(
            revaultd.coordinator_host,
            &revaultd.noise_secret,
            &revaultd.coordinator_noisekey,
            &rev_txs,
        )?;

        Ok(())
    }

    /// Get the unvault transaction for the vault identified by this outpoint.
    /// Returns None if there are no *confirmed* vault at this outpoint.
    ///
    /// ## Errors
    /// - If called for a non stakeholder
    /// - If called for an unknown or not 'funded' vault
    pub fn get_unvault_tx(
        &self,
        deposit_outpoint: OutPoint,
    ) -> Result<UnvaultTransaction, CommandError> {
        let revaultd = self.revaultd.read().unwrap();
        stakeholder_only!(revaultd);
        let db_path = &revaultd.db_file();
        assert!(revaultd.is_stakeholder());

        // We allow the call for Funded 'only' as unvaulttx would later fail if it's
        // not 'secured'.
        let vault = db_vault_by_deposit(db_path, &deposit_outpoint)
            .expect("The database must be available")
            .ok_or_else(|| CommandError::UnknownOutpoint(deposit_outpoint))?;
        if matches!(vault.status, VaultStatus::Unconfirmed) {
            return Err(CommandError::InvalidStatus(
                vault.status,
                VaultStatus::Funded,
            ));
        }

        // Derive the descriptors needed to create the UnvaultTransaction
        let deposit_descriptor = revaultd
            .deposit_descriptor
            .derive(vault.derivation_index, &revaultd.secp_ctx);
        let deposit_txin = DepositTxIn::new(
            deposit_outpoint,
            DepositTxOut::new(vault.amount, &deposit_descriptor),
        );
        let unvault_descriptor = revaultd
            .unvault_descriptor
            .derive(vault.derivation_index, &revaultd.secp_ctx);
        let cpfp_descriptor = revaultd
            .cpfp_descriptor
            .derive(vault.derivation_index, &revaultd.secp_ctx);

        Ok(UnvaultTransaction::new(
            deposit_txin,
            &unvault_descriptor,
            &cpfp_descriptor,
            revaultd.lock_time,
        )
        .expect("We wouldn't have a vault with an invalid Unvault in DB"))
    }

    /// Set the signed unvault transaction for the vault at this outpoint.
    ///
    /// ## Errors
    /// - If called for a non-stakeholder
    /// - If called for an unknown or not 'secured' vault
    /// - If passed an insane Unvault transaction (no sig for ourselves, invalid sig, ..)
    pub fn set_unvault_tx(
        &self,
        deposit_outpoint: OutPoint,
        unvault_tx: UnvaultTransaction,
    ) -> Result<(), CommandError> {
        let revaultd = self.revaultd.read().unwrap();
        stakeholder_only!(revaultd);
        let db_path = revaultd.db_file();
        let secp_ctx = &revaultd.secp_ctx;

        // If they haven't got all the signatures for the revocation transactions, we'd
        // better not send our unvault sig!
        // If the vault is already active (or more) there is no point in spamming the
        // coordinator.
        let db_vault = db_vault_by_deposit(&db_path, &deposit_outpoint)
            .expect("The database must be available")
            .ok_or_else(|| CommandError::UnknownOutpoint(deposit_outpoint))?;
        if !matches!(db_vault.status, VaultStatus::Secured) {
            return Err(CommandError::InvalidStatus(
                db_vault.status,
                VaultStatus::Secured,
            ));
        }

        // Sanity check they didn't send us a garbaged PSBT
        let mut unvault_db_tx = db_unvault_transaction(&db_path, db_vault.id)
            .expect("The database must be available")
            .ok_or(CommandError::Race)?;
        let rpc_txid = unvault_tx.tx().wtxid();
        let db_txid = unvault_db_tx.psbt.wtxid();
        if rpc_txid != db_txid {
            return Err(CommandError::InvalidParams(format!(
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
            return Err(CommandError::InvalidParams(format!(
                "No signature for ourselves ({}) in Unvault transaction",
                our_key
            )));
        }

        for (key, sig) in sigs {
            // There is no reason for them to include an unnecessary signature, so be strict.
            if !stk_keys.contains(&key) {
                return Err(CommandError::InvalidParams(format!(
                    "Unknown key in Unvault transaction signatures: {}",
                    key
                )));
            }

            if sig.is_empty() {
                return Err(CommandError::InvalidParams(format!(
                    "Empty signature for key '{}' in Unvault PSBT",
                    key
                )));
            }
            let sig = secp256k1::Signature::from_der(&sig[..sig.len() - 1]).map_err(|_| {
                CommandError::InvalidParams(format!("Non DER signature in Unvault PSBT"))
            })?;

            unvault_db_tx
                .psbt
                .add_signature(key.key, sig, secp_ctx)
                .map_err(|e| {
                    CommandError::InvalidParams(format!(
                        "Invalid signature '{}' in Unvault PSBT: '{}'",
                        sig, e
                    ))
                })?;
        }

        // Sanity checks passed. Store it then share it.
        db_update_presigned_txs(&db_path, &db_vault, vec![unvault_db_tx.clone()], secp_ctx)
            .expect("The database must be available");
        db_mark_activating_vault(&db_path, db_vault.id).expect("The database must be available");
        db_update_vault_status(&db_path, &db_vault).expect("The database must be available");
        share_unvault_signatures(
            revaultd.coordinator_host,
            &revaultd.noise_secret,
            &revaultd.coordinator_noisekey,
            &unvault_db_tx,
        )?;

        Ok(())
    }

    /// List the presigned transactions for the vaults at these outpoints. If `outpoints` is empty,
    /// list the presigned transactions for all vaults.
    ///
    /// # Errors
    /// - If an outpoint does not refer to a known deposit, or if the status of the vault is
    /// part of `invalid_statuses`.
    pub fn list_presigned_txs(
        &self,
        outpoints: &[OutPoint],
    ) -> Result<Vec<ListPresignedTxEntry>, CommandError> {
        let revaultd = self.revaultd.read().unwrap();
        let db_path = revaultd.db_file();
        let db_vaults = if outpoints.is_empty() {
            db_vaults_min_status(&db_path, VaultStatus::Funded).expect("Database must be available")
        } else {
            vaults_from_deposits(&db_path, &outpoints, &[VaultStatus::Unconfirmed])?
        };

        presigned_txs(&revaultd, db_vaults).ok_or(CommandError::Race)
    }

    /// List the onchain transactions for the vaults at these outpoints. If `outpoints` is empty, list
    /// the onchain transactions for all vaults.
    ///
    /// # Errors
    /// - If an outpoint does not refer to a known deposit, or if the status of the vault is
    /// part of `invalid_statuses`.
    pub fn list_onchain_txs(
        &self,
        outpoints: &[OutPoint],
    ) -> Result<Vec<ListOnchainTxEntry>, CommandError> {
        let revaultd = self.revaultd.read().unwrap();
        let db_path = &revaultd.db_file();

        let db_vaults = if outpoints.is_empty() {
            db_vaults(&db_path).expect("Database must be available")
        } else {
            // We accept any status
            vaults_from_deposits(&db_path, &outpoints, &[])?
        };

        let mut tx_list = Vec::with_capacity(db_vaults.len());
        for db_vault in db_vaults {
            let vault_outpoint = db_vault.deposit_outpoint;

            // If the vault exist, there must always be a deposit transaction available.
            let deposit = self
                .bitcoind_conn
                .wallet_tx(db_vault.deposit_outpoint.txid)?
                .expect("Vault exists but not deposit tx?");

            // For the other transactions, it depends on the status of the vault. For the sake of
            // simplicity bitcoind will tell us (but we could have some optimisation eventually here,
            // eg returning None early on Funded vaults).
            let (unvault, cancel, emergency, unvault_emergency, spend) = match db_vault.status {
                VaultStatus::Unvaulting | VaultStatus::Unvaulted => {
                    let unvault_db_tx = db_unvault_transaction(db_path, db_vault.id)
                        .expect("Database must be available")
                        .ok_or(CommandError::Race)?;
                    let unvault = self.bitcoind_conn.wallet_tx(unvault_db_tx.psbt.txid())?;
                    (unvault, None, None, None, None)
                }
                VaultStatus::Spending | VaultStatus::Spent => {
                    let unvault_db_tx = db_unvault_transaction(db_path, db_vault.id)
                        .expect("Database must be available")
                        .ok_or(CommandError::Race)?;
                    let unvault = self.bitcoind_conn.wallet_tx(unvault_db_tx.psbt.txid())?;
                    let spend = if let Some(spend_txid) = db_vault.final_txid {
                        self.bitcoind_conn.wallet_tx(spend_txid)?
                    } else {
                        None
                    };
                    (unvault, None, None, None, spend)
                }
                VaultStatus::Canceling | VaultStatus::Canceled => {
                    let unvault_db_tx = db_unvault_transaction(db_path, db_vault.id)
                        .expect("Database must be available")
                        .ok_or(CommandError::Race)?;
                    let unvault = self.bitcoind_conn.wallet_tx(unvault_db_tx.psbt.txid())?;
                    let cancel = if let Some(cancel_txid) = db_vault.final_txid {
                        self.bitcoind_conn.wallet_tx(cancel_txid)?
                    } else {
                        None
                    };
                    (unvault, cancel, None, None, None)
                }
                VaultStatus::EmergencyVaulting | VaultStatus::EmergencyVaulted => {
                    // Emergencies are only for stakeholders!
                    if revaultd.is_stakeholder() {
                        let emer_db_tx = db_emer_transaction(db_path, db_vault.id)
                            .expect("Database must be available")
                            .ok_or(CommandError::Race)?;
                        let emergency = self.bitcoind_conn.wallet_tx(emer_db_tx.psbt.txid())?;
                        (None, None, emergency, None, None)
                    } else {
                        (None, None, None, None, None)
                    }
                }
                VaultStatus::UnvaultEmergencyVaulting | VaultStatus::UnvaultEmergencyVaulted => {
                    let unvault_db_tx = db_unvault_transaction(db_path, db_vault.id)
                        .expect("Database must be available")
                        .ok_or(CommandError::Race)?;
                    let unvault = self.bitcoind_conn.wallet_tx(unvault_db_tx.psbt.txid())?;

                    // Emergencies are only for stakeholders!
                    if revaultd.is_stakeholder() {
                        let unemer_db_tx = db_emer_transaction(db_path, db_vault.id)
                            .expect("Database must be available")
                            .ok_or(CommandError::Race)?;
                        let unvault_emergency =
                            self.bitcoind_conn.wallet_tx(unemer_db_tx.psbt.txid())?;
                        (unvault, None, None, unvault_emergency, None)
                    } else {
                        (unvault, None, None, None, None)
                    }
                }
                // Other statuses do not have on chain transactions apart the deposit.
                VaultStatus::Unconfirmed
                | VaultStatus::Funded
                | VaultStatus::Securing
                | VaultStatus::Secured
                | VaultStatus::Activating
                | VaultStatus::Active => (None, None, None, None, None),
            };

            tx_list.push(ListOnchainTxEntry {
                vault_outpoint,
                deposit,
                unvault,
                cancel,
                emergency,
                unvault_emergency,
                spend,
            });
        }

        Ok(tx_list)
    }

    /// Create a Spend transaction for these deposit outpoints, paying to the specified addresses
    /// at the given feerate (with a tolerance of 10% below it and any % above it if we can't create
    /// a change output).
    /// Mind we add a CPFP output, which must be taken into account by the feerate.
    ///
    /// # Errors
    /// - If called for a non-manager
    /// - If provided outpoints for unknown or not 'active' vaults
    /// - If the Spend transaction creation fails (for instance due to too-high fees or dust outputs)
    /// - If the created Spend transaction's feerate is more than 10% below the required feerate
    /// - If the created Spend transaction is too large to be transmitted to the coordinator
    pub fn get_spend_tx(
        &self,
        outpoints: &[OutPoint],
        destinations: &BTreeMap<Address, u64>,
        feerate_vb: u64,
    ) -> Result<SpendTransaction, CommandError> {
        let revaultd = self.revaultd.read().unwrap();
        manager_only!(revaultd);
        let db_file = &revaultd.db_file();

        // FIXME: have a feerate type to avoid that
        assert!(feerate_vb > 0, "Spend feerate can't be null.");

        // Reconstruct the DepositTxin s from the outpoints and the vaults informations
        let mut txins = Vec::with_capacity(outpoints.len());
        // If we need a change output, use the highest derivation index of the vaults
        // spent. This avoids leaking a new address needlessly while not introducing
        // disrepancy between our indexes.
        let mut change_index = bip32::ChildNumber::from(0);
        for outpoint in outpoints {
            let vault = db_vault_by_deposit(db_file, outpoint)
                .expect("Database must be available")
                .ok_or_else(|| CommandError::UnknownOutpoint(*outpoint))?;
            if matches!(vault.status, VaultStatus::Active) {
                if vault.derivation_index > change_index {
                    change_index = vault.derivation_index;
                }
                txins.push((*outpoint, vault.amount, vault.derivation_index));
            } else {
                return Err(CommandError::InvalidStatus(
                    vault.status,
                    VaultStatus::Active,
                ));
            }
        }

        let txos: Vec<SpendTxOut> = destinations
            .iter()
            .map(|(addr, value)| {
                let script_pubkey = addr.script_pubkey();
                SpendTxOut::new(TxOut {
                    value: *value,
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
        .map_err(|e| revault_tx::Error::from(e))?;

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
            return Err(CommandError::SpendFeerateTooLow(
                feerate_vb,
                nochange_feerate_vb,
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
        .map_err(|e| revault_tx::Error::from(e))?;

        if !check_spend_transaction_size(&revaultd, tx_res.clone()) {
            return Err(CommandError::SpendTooLarge);
        };
        log::debug!("Final Spend transaction: '{:?}'", tx_res);

        Ok(tx_res)
    }

    /// Store a new or update an existing Spend transaction in database.
    ///
    /// ## Errors
    /// - If called for a non-manager
    /// - If the given Spend transaction refers to an unknown Unvault txid
    /// - If the Spend refers to an Unvault of a vault that isn't 'active'
    pub fn update_spend_tx(&self, spend_tx: SpendTransaction) -> Result<(), CommandError> {
        let revaultd = self.revaultd.read().unwrap();
        manager_only!(revaultd);
        let db_path = revaultd.db_file();
        let spend_txid = spend_tx.tx().txid();

        // Fetch the Unvault it spends from the DB
        let spend_inputs = &spend_tx.tx().input;
        let mut db_unvaults = Vec::with_capacity(spend_inputs.len());
        for txin in spend_inputs.iter() {
            let (db_vault, db_unvault) =
                db_vault_by_unvault_txid(&db_path, &txin.previous_output.txid)
                    .expect("Database must be available")
                    .ok_or_else(|| CommandError::SpendUnknownUnVault(txin.previous_output.txid))?;

            if !matches!(db_vault.status, VaultStatus::Active) {
                return Err(CommandError::InvalidStatus(
                    db_vault.status,
                    VaultStatus::Active,
                ));
            }

            db_unvaults.push(db_unvault);
        }

        // The user has the ability to set priority to the transaction in
        // setspendtx, here we always set it to false.
        if db_spend_transaction(&db_path, &spend_txid)
            .expect("Database must be available")
            .is_some()
        {
            log::debug!("Updating Spend transaction '{}'", spend_txid);
            db_update_spend(&db_path, &spend_tx, false).expect("Database must be available");
        } else {
            log::debug!("Storing new Spend transaction '{}'", spend_txid);
            db_insert_spend(&db_path, &db_unvaults, &spend_tx).expect("Database must be available");
        }

        Ok(())
    }

    /// Delete a Spend transaction by txid.
    /// **Note**: this does nothing if no Spend with this txid exist.
    ///
    /// ## Errors
    /// - If called for a non-manager
    pub fn del_spend_tx(&self, spend_txid: &Txid) -> Result<(), CommandError> {
        let revaultd = self.revaultd.read().unwrap();
        manager_only!(revaultd);
        let db_path = revaultd.db_file();
        db_delete_spend(&db_path, spend_txid).expect("Database must be available");
        Ok(())
    }

    /// List all Spend transaction, optionally curated by their status.
    ///
    /// ## Errors
    /// - If called for a non-manager
    pub fn list_spend_txs(
        &self,
        statuses: Option<&[ListSpendStatus]>,
    ) -> Result<Vec<ListSpendEntry>, CommandError> {
        let revaultd = self.revaultd.read().unwrap();
        manager_only!(revaultd);
        let db_path = revaultd.db_file();

        let spend_tx_map = db_list_spends(&db_path).expect("Database must be available");
        let mut listspend_entries = Vec::with_capacity(spend_tx_map.len());
        for (_, (db_spend, deposit_outpoints)) in spend_tx_map {
            // Filter by status
            if let Some(s) = &statuses {
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
                .expect("Database must be available");

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

        Ok(listspend_entries)
    }

    /// Announce a Spend transaction to be used (after having optionally polled the cosigning servers),
    /// broadcast its corresponding Unvault transactions and register it for being broadcast it as soon
    /// as the timelock expires.
    /// If `priority` is set to `true`, we'll automatically try to feebump the Unvault and then the
    /// Spend transactions in the background if they don't confirm.
    ///
    /// ## Errors
    /// - If `priority` is set to `true` and we don't have access to a CPFP private key
    /// - If the txid doesn't refer to a known Spend (must be stored using `updatespendtx` first)
    /// - If the Spend PSBT doesn't contain enough signatures, or contain invalid ones
    /// - If the Spend is too large to be announced
    pub fn set_spend_tx(&self, spend_txid: &Txid, priority: bool) -> Result<(), CommandError> {
        let revaultd = self.revaultd.read().unwrap();
        manager_only!(revaultd);
        let db_path = revaultd.db_file();

        if priority && revaultd.cpfp_key.is_none() {
            return Err(CommandError::MissingCpfpKey);
        }

        // Get the referenced Spend and the vaults it spends from the DB
        let mut spend_tx = db_spend_transaction(&db_path, &spend_txid)
            .expect("Database must be available")
            .ok_or_else(|| CommandError::UnknownSpend(*spend_txid))?;
        let spent_vaults =
            db_vaults_from_spend(&db_path, &spend_txid).expect("Database must be available");
        let tx = &spend_tx.psbt.tx();
        if spent_vaults.len() < tx.input.len() {
            return Err(CommandError::SpendSpent(*spend_txid));
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
                return Err(CommandError::SpendNotEnoughSig(sigmap.len(), mans_thresh));
            }
            for (pubkey, raw_sig) in sigmap {
                let sig = secp256k1::Signature::from_der(&raw_sig[..raw_sig.len() - 1])
                    .map_err(|_| CommandError::SpendInvalidSig(raw_sig.clone()))?;
                spend_tx
                    .psbt
                    .add_signature(i, pubkey.key, sig, &revaultd.secp_ctx)
                    .map_err(|_| CommandError::SpendInvalidSig(raw_sig.clone()))?
                    .expect("The signature was already there");
            }
        }

        // FIXME: shouldn't `updatespendtx` make sure this doesn't happen??
        // Check that we can actually send the tx to the coordinator...
        if !check_spend_transaction_size(&revaultd, spend_tx.psbt.clone()) {
            return Err(CommandError::SpendTooLarge);
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
            )?;
        }
        let mut finalized_spend = spend_tx.psbt.clone();
        finalized_spend.finalize(&revaultd.secp_ctx)?;

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
        )?;
        db_update_spend(&db_path, &spend_tx.psbt, priority).expect("Database must be available");

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
                let mut unvault_tx = db_unvault_transaction(&db_path, db_vault.id)
                    .expect("Database must be available")
                    .ok_or(CommandError::Race)?
                    .psbt
                    .assert_unvault();
                unvault_tx.finalize(&revaultd.secp_ctx)?;
                Ok(unvault_tx.into_psbt().extract_tx())
            })
            .collect::<Result<Vec<BitcoinTransaction>, CommandError>>()?;
        self.bitcoind_conn.broadcast(bitcoin_txs)?;
        db_mark_broadcastable_spend(&db_path, spend_txid).expect("Database must be available");

        Ok(())
    }

    /// Broadcast the Cancel transaction for an unvaulted vault.
    ///
    /// ## Errors
    /// - If the outpoint doesn't refer to an existing, unvaulted (or unvaulting) vault
    /// - If the transaction broadcast fails for some reason
    pub fn revault(&self, deposit_outpoint: &OutPoint) -> Result<(), CommandError> {
        let revaultd = self.revaultd.read().unwrap();
        let db_path = revaultd.db_file();

        // Checking that the vault is secured, otherwise we don't have the cancel
        // transaction
        let vault = db_vault_by_deposit(&db_path, deposit_outpoint)
            .expect("Database must be accessible")
            .ok_or_else(|| CommandError::UnknownOutpoint(*deposit_outpoint))?;

        if !matches!(
            vault.status,
            VaultStatus::Unvaulting | VaultStatus::Unvaulted | VaultStatus::Spending
        ) {
            return Err(CommandError::InvalidStatus(
                vault.status,
                VaultStatus::Unvaulting,
            ));
        }

        let mut cancel_tx = db_cancel_transaction(&db_path, vault.id)
            .expect("Database must be available")
            .ok_or(CommandError::Race)?
            .psbt
            .assert_cancel();

        cancel_tx.finalize(&revaultd.secp_ctx)?;
        let transaction = cancel_tx.into_psbt().extract_tx();
        log::debug!(
            "Broadcasting Cancel transactions with id '{:?}'",
            transaction.txid()
        );
        self.bitcoind_conn.broadcast(vec![transaction])?;

        Ok(())
    }

    /// Broadcast Emergency transactions for all existing vaults.
    ///
    /// ## Errors
    /// - If called for a non-stakeholder
    pub fn emergency(&self) -> Result<(), CommandError> {
        let revaultd = self.revaultd.read().unwrap();
        stakeholder_only!(revaultd);

        // FIXME: there is a ton of edge cases not covered here. We should additionally opt for a
        // bulk method, like broadcasting all Emergency transactions in a thread forever without
        // trying to be smart by differentiating between Emer and UnvaultEmer until we die or all
        // vaults are confirmed in the EDV.
        let emers = finalized_emer_txs(&revaultd)?;
        self.bitcoind_conn.broadcast(emers)?;

        Ok(())
    }

    /// Get information about all the configured servers.
    pub fn get_servers_statuses(&self) -> ServersStatuses {
        let revaultd = self.revaultd.read().unwrap();
        let coordinator = coordinator_status(&revaultd);
        let cosigners = cosigners_status(&revaultd);
        let watchtowers = watchtowers_status(&revaultd);

        ServersStatuses {
            coordinator,
            cosigners,
            watchtowers,
        }
    }

    /// Get a paginated list of accounting events. This returns a maximum of `limit` events occuring
    /// between the dates `start` and `end`, filtered by kind of events.
    /// Aiming to give an accounting point of view, the amounts returned by this call are the total
    /// of inflows and outflows net of any change amount (that is technically a transaction output, but
    /// not a cash outflow).
    pub fn get_history(
        &self,
        start: u32,
        end: u32,
        limit: u64,
        kind: &[HistoryEventKind],
    ) -> Result<Vec<HistoryEvent>, CommandError> {
        let revaultd = self.revaultd.read().unwrap();
        gethistory(&revaultd, &self.bitcoind_conn, start, end, limit, kind)
    }
}

/// Descriptors the daemon was configured with
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetInfoDescriptors {
    #[serde(serialize_with = "ser_to_string", deserialize_with = "deser_from_str")]
    pub deposit: DepositDescriptor,
    #[serde(serialize_with = "ser_to_string", deserialize_with = "deser_from_str")]
    pub unvault: UnvaultDescriptor,
    #[serde(serialize_with = "ser_to_string", deserialize_with = "deser_from_str")]
    pub cpfp: CpfpDescriptor,
}

/// Information about the current state of the daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetInfoResult {
    pub version: String,
    pub network: Network,
    pub blockheight: i32,
    pub sync: f64,
    pub vaults: usize,
    pub managers_threshold: usize,
    pub descriptors: GetInfoDescriptors,
}

/// Information about a vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListVaultsEntry {
    #[serde(
        serialize_with = "ser_amount",
        deserialize_with = "deser_amount_from_sats"
    )]
    pub amount: Amount,
    pub blockheight: Option<u32>,
    #[serde(serialize_with = "ser_to_string", deserialize_with = "deser_from_str")]
    pub status: VaultStatus,
    pub txid: Txid,
    pub vout: u32,
    pub derivation_index: bip32::ChildNumber,
    pub address: Address,
    pub funded_at: Option<u32>,
    pub secured_at: Option<u32>,
    pub delegated_at: Option<u32>,
    pub moved_at: Option<u32>,
}

/// Revocation transactions for a given vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationTransactions {
    pub cancel_tx: CancelTransaction,
    pub emergency_tx: EmergencyTransaction,
    // FIXME: consistent naming
    pub emergency_unvault_tx: UnvaultEmergencyTransaction,
}

/// A vault's presigned transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPresignedTransaction<T: RevaultTransaction> {
    pub psbt: T,
    // FIXME: is it really necessary?.. It's mostly contained in the PSBT already
    #[serde(rename(serialize = "hex"), serialize_with = "serialize_option_tx_hex")]
    pub transaction: Option<BitcoinTransaction>,
}

/// Information about a vault's presigned transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListPresignedTxEntry {
    pub vault_outpoint: OutPoint,
    pub unvault: VaultPresignedTransaction<UnvaultTransaction>,
    pub cancel: VaultPresignedTransaction<CancelTransaction>,
    /// Always None if not stakeholder
    pub emergency: Option<VaultPresignedTransaction<EmergencyTransaction>>,
    /// Always None if not stakeholder
    pub unvault_emergency: Option<VaultPresignedTransaction<UnvaultEmergencyTransaction>>,
}

/// Information about a vault's onchain transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListOnchainTxEntry {
    pub vault_outpoint: OutPoint,
    pub deposit: WalletTransaction,
    pub unvault: Option<WalletTransaction>,
    pub cancel: Option<WalletTransaction>,
    /// Always None if not stakeholder
    pub emergency: Option<WalletTransaction>,
    /// Always None if not stakeholder
    pub unvault_emergency: Option<WalletTransaction>,
    pub spend: Option<WalletTransaction>,
}

/// Status of a Spend transaction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ListSpendStatus {
    NonFinal,
    Pending,
    Broadcasted,
}

/// Information about a Spend transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSpendEntry {
    pub deposit_outpoints: Vec<OutPoint>,
    pub psbt: SpendTransaction,
    pub cpfp_index: usize,
    pub change_index: Option<usize>,
}

/// Information about the configured servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServersStatuses {
    pub coordinator: ServerStatus,
    pub cosigners: Vec<ServerStatus>,
    pub watchtowers: Vec<ServerStatus>,
}

/// The type of an accounting event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HistoryEventKind {
    #[serde(rename = "cancel")]
    Cancel,
    #[serde(rename = "deposit")]
    Deposit,
    #[serde(rename = "spend")]
    Spend,
}

impl fmt::Display for HistoryEventKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Cancel => write!(f, "Cancel"),
            Self::Deposit => write!(f, "Deposit"),
            Self::Spend => write!(f, "Spend"),
        }
    }
}

/// An accounting event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEvent {
    pub kind: HistoryEventKind,
    pub date: u32,
    pub blockheight: u32,
    pub amount: Option<u64>,
    pub fee: Option<u64>,
    pub txid: Txid,
    pub vaults: Vec<OutPoint>,
}
