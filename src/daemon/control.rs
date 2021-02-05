//! By itself, the daemon is not doing much: it basically just keeps its database updated with the
//! chain events in the bitcoind thread.
//! Any process is at first initiated by a manual interaction. This interaction is possible using the
//! JSONRPC api, which events are handled in the RPC thread.
//!
//! The main thread handles and coordinates all processes, which (for now) all originates from a
//! command sent to the RPC server. This control handling is what happens here.

use crate::{
    assert_tx_type,
    bitcoind::BitcoindError,
    database::{
        actions::db_store_revocation_txs,
        interface::{db_tip, db_transactions, db_vault_by_deposit, db_vaults},
        schema::RevaultTx,
        DatabaseError,
    },
    revaultd::{BlockchainTip, RevaultD, VaultStatus},
    threadmessages::*,
};
use common::{assume_ok, assume_some};

use revault_net::{
    message::server::{GetSigs, RevaultSignature, Sig, Sigs},
    transport::KKTransport,
};
use revault_tx::{
    bitcoin::{
        hashes::Hash,
        secp256k1::{self, Signature},
        Network, OutPoint, PublicKey as BitcoinPubKey, Script, SigHashType, Txid,
    },
    transactions::{
        transaction_chain, CancelTransaction, EmergencyTransaction, RevaultTransaction,
        UnvaultEmergencyTransaction, UnvaultTransaction,
    },
    txins::VaultTxIn,
    txouts::VaultTxOut,
};

use std::{
    collections::BTreeMap,
    fmt,
    path::PathBuf,
    process,
    sync::{
        mpsc::{self, Receiver, RecvError, SendError, Sender},
        Arc, RwLock,
    },
    thread::JoinHandle,
};

/// Any error that could arise during the process of executing the user's will.
/// Usually fatal.
#[derive(Debug)]
pub enum ControlError {
    ChannelCommunication(String),
    Database(String),
    Bitcoind(String),
    TransactionManagement(String),
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::ChannelCommunication(s) => write!(f, "Channel communication error: '{}'", s),
            Self::Database(s) => write!(f, "Database error: '{}'", s),
            Self::Bitcoind(s) => write!(f, "Bitcoind error: '{}'", s),
            Self::TransactionManagement(s) => write!(f, "Transaction management error: '{}'", s),
        }
    }
}

impl std::error::Error for ControlError {}

impl<T> From<SendError<T>> for ControlError {
    fn from(e: SendError<T>) -> Self {
        Self::ChannelCommunication(format!("Sending to channel: '{}'", e))
    }
}

impl From<RecvError> for ControlError {
    fn from(e: RecvError) -> Self {
        Self::ChannelCommunication(format!("Receiving from channel: '{}'", e))
    }
}

impl From<DatabaseError> for ControlError {
    fn from(e: DatabaseError) -> Self {
        Self::Database(format!("Database error: {}", e))
    }
}

impl From<BitcoindError> for ControlError {
    fn from(e: BitcoindError) -> Self {
        Self::Bitcoind(format!("Bitcoind error: {}", e))
    }
}

impl From<revault_tx::Error> for ControlError {
    fn from(e: revault_tx::Error) -> Self {
        Self::TransactionManagement(format!("Revault transaction error: {}", e))
    }
}

// Ask bitcoind for a wallet transaction
fn bitcoind_wallet_tx(
    bitcoind_tx: &Sender<BitcoindMessageOut>,
    txid: Txid,
) -> Result<Option<WalletTransaction>, ControlError> {
    log::trace!("Sending WalletTx to bitcoind thread for {}", txid);

    let (bitrep_tx, bitrep_rx) = mpsc::sync_channel(0);
    bitcoind_tx.send(BitcoindMessageOut::WalletTransaction(txid, bitrep_tx))?;
    bitrep_rx.recv().map_err(|e| e.into())
}

// List the vaults from DB, and filter out the info the RPC wants
// FIXME: we could make this more efficient with smarter SQL queries
fn listvaults_from_db(
    revaultd: &RevaultD,
    statuses: Option<Vec<VaultStatus>>,
    outpoints: Option<Vec<OutPoint>>,
) -> Result<Vec<ListVaultsEntry>, DatabaseError> {
    db_vaults(&revaultd.db_file()).map(|db_vaults| {
        db_vaults
            .into_iter()
            .filter_map(|db_vault| {
                if let Some(ref statuses) = statuses {
                    if !statuses.contains(&db_vault.status) {
                        return None;
                    }
                }

                if let Some(ref outpoints) = &outpoints {
                    if !outpoints.contains(&db_vault.deposit_outpoint) {
                        return None;
                    }
                }

                let address = revaultd.vault_address(db_vault.derivation_index);
                Some(ListVaultsEntry {
                    amount: db_vault.amount,
                    status: db_vault.status,
                    deposit_outpoint: db_vault.deposit_outpoint,
                    derivation_index: db_vault.derivation_index,
                    address,
                })
            })
            .collect()
    })
}

// List all the transactions of all the vaults which deposit outpoints we are passed. If we don't
// have the fully signed transaction in db, we create an unsigned one.
fn txlist_from_outpoints(
    revaultd: &RevaultD,
    bitcoind_tx: &Sender<BitcoindMessageOut>,
    outpoints: Option<Vec<OutPoint>>,
) -> Result<Vec<VaultTransactions>, ControlError> {
    let xpub_ctx = revaultd.xpub_ctx();
    let db_file = &revaultd.db_file();

    // If they didn't provide us with a list of outpoints, catch'em all!
    let db_vaults = if let Some(outpoints) = outpoints {
        // FIXME: we can probably make this more efficient with some SQL magic
        let mut vaults = Vec::with_capacity(outpoints.len());
        for outpoint in outpoints.iter() {
            if let Some(vault) = db_vault_by_deposit(db_file, &outpoint)? {
                vaults.push(vault);
            }
            // FIXME: Invalid outpoints are siltently ignored..
        }
        vaults
    } else {
        db_vaults(db_file)?
    };

    let mut tx_list = Vec::with_capacity(db_vaults.len());
    for db_vault in db_vaults {
        let outpoint = db_vault.deposit_outpoint;
        let deriv_index = db_vault.derivation_index;
        let mut txs = db_transactions(db_file, db_vault.id, &[])?.into_iter();

        let deposit = assume_some!(
            bitcoind_wallet_tx(&bitcoind_tx, outpoint.txid)?,
            "Vault without deposit tx in db for {}",
            &outpoint,
        );

        // Get the descriptors in case we need to derive the transactions (not signed
        // yet, ie not in DB).
        // One day, we could try to be smarter wrt free derivation but it's not
        // a priority atm.
        let deposit_descriptor = revaultd.vault_descriptor.derive(deriv_index);
        let vault_txin = VaultTxIn::new(
            db_vault.deposit_outpoint,
            VaultTxOut::new(db_vault.amount.as_sat(), &deposit_descriptor, xpub_ctx),
        );
        let unvault_descriptor = revaultd.unvault_descriptor.derive(deriv_index);
        let cpfp_descriptor = revaultd.cpfp_descriptor.derive(deriv_index);
        let emer_address = revaultd.emergency_address.clone();

        // We can always re-generate the Unvault out of the descriptor if it's
        // not in DB..
        let mut unvault_tx = txs
            .find(|db_tx| matches!(db_tx.psbt, RevaultTx::Unvault(_)))
            .map(|tx| assert_tx_type!(tx.psbt, Unvault, "We just found it"))
            .unwrap_or(UnvaultTransaction::new(
                vault_txin.clone(),
                &unvault_descriptor,
                &cpfp_descriptor,
                xpub_ctx,
                revaultd.lock_time,
            )?);
        let unvault_txin = unvault_tx
            .unvault_txin(&unvault_descriptor, xpub_ctx, revaultd.unvault_csv)
            .expect("Just created it");
        let wallet_tx = bitcoind_wallet_tx(
            &bitcoind_tx,
            unvault_tx.inner_tx().global.unsigned_tx.txid(),
        )?;
        // The transaction is signed if we did sign it, or if others did (eg
        // non-stakeholder managers) and we noticed it from broadcast.
        // TODO: maybe a is_finalizable upstream ? finalize() is pretty costy
        let is_signed = unvault_tx.finalize(&revaultd.secp_ctx).is_ok() || wallet_tx.is_some();
        let unvault = TransactionResource {
            wallet_tx,
            tx: unvault_tx,
            is_signed,
        };

        // .. But not the spend, as it's dynamically chosen by the managers and
        // could be anything!
        let spend = if let Some(mut tx) = txs
            .find(|db_tx| matches!(db_tx.psbt, RevaultTx::Spend(_)))
            .map(|tx| assert_tx_type!(tx.psbt, Spend, "We just found it"))
        {
            let wallet_tx =
                bitcoind_wallet_tx(&bitcoind_tx, tx.inner_tx().global.unsigned_tx.txid())?;
            // TODO: maybe a is_finalizable upstream ? finalize() is pretty costy
            let is_signed = tx.finalize(&revaultd.secp_ctx).is_ok() || wallet_tx.is_some();
            Some(TransactionResource {
                wallet_tx,
                tx,
                is_signed,
            })
        } else {
            None
        };

        // The cancel transaction is deterministic, so we can always return it.
        let mut cancel_tx = txs
            .find(|db_tx| matches!(db_tx.psbt, RevaultTx::Cancel(_)))
            .map(|tx| assert_tx_type!(tx.psbt, Cancel, "We just found it"))
            .unwrap_or_else(|| {
                CancelTransaction::new(
                    unvault_txin.clone(),
                    None,
                    &deposit_descriptor,
                    xpub_ctx,
                    revaultd.lock_time,
                )
            });
        let wallet_tx =
            bitcoind_wallet_tx(&bitcoind_tx, cancel_tx.inner_tx().global.unsigned_tx.txid())?;
        // TODO: maybe a is_finalizable upstream ? finalize() is pretty costy
        let is_signed = cancel_tx.finalize(&revaultd.secp_ctx).is_ok() || wallet_tx.is_some();
        let cancel = TransactionResource {
            wallet_tx,
            tx: cancel_tx,
            is_signed,
        };

        // The emergency transaction is deterministic, so we can always return it.
        let mut emergency_tx = txs
            .find(|db_tx| matches!(db_tx.psbt, RevaultTx::Emergency(_)))
            .map(|tx| assert_tx_type!(tx.psbt, Emergency, "We just found it"))
            .unwrap_or_else(|| {
                EmergencyTransaction::new(vault_txin, None, emer_address, revaultd.lock_time)
                    .unwrap() // FIXME
            });
        let wallet_tx = bitcoind_wallet_tx(
            &bitcoind_tx,
            emergency_tx.inner_tx().global.unsigned_tx.txid(),
        )?;
        // TODO: maybe a is_finalizable upstream ? finalize() is pretty costy
        let is_signed = emergency_tx.finalize(&revaultd.secp_ctx).is_ok() || wallet_tx.is_some();
        let emergency = TransactionResource {
            wallet_tx,
            tx: emergency_tx,
            is_signed,
        };

        // Same for the second emergency.
        let mut unvault_emergency_tx = txs
            .find(|db_tx| matches!(db_tx.psbt, RevaultTx::UnvaultEmergency(_)))
            .map(|tx| assert_tx_type!(tx.psbt, UnvaultEmergency, "We just found it"))
            .unwrap_or_else(|| {
                UnvaultEmergencyTransaction::new(
                    unvault_txin,
                    None,
                    revaultd.emergency_address.clone(),
                    revaultd.lock_time,
                )
            });
        let wallet_tx = bitcoind_wallet_tx(
            &bitcoind_tx,
            unvault_emergency_tx.inner_tx().global.unsigned_tx.txid(),
        )?;
        // TODO: maybe a is_finalizable upstream ? finalize() is pretty costy
        let is_signed =
            unvault_emergency_tx.finalize(&revaultd.secp_ctx).is_ok() || wallet_tx.is_some();
        let unvault_emergency = TransactionResource {
            wallet_tx,
            tx: unvault_emergency_tx,
            is_signed,
        };

        tx_list.push(VaultTransactions {
            outpoint,
            deposit,
            unvault,
            spend,
            cancel,
            emergency,
            unvault_emergency,
        });
    }

    Ok(tx_list)
}

// The signature hash of a revocation transaction (ie Cancel, Emergency, or UnvaultEmergency)
fn revocation_tx_sighash(tx: &impl RevaultTransaction, script_code: &Script) -> secp256k1::Message {
    // Revocation transactions (at this stage) only have one input.
    // If we were passed a >1 input transaction, something went really bad and it's better to
    // crash.
    assert!(tx.inner_tx().global.unsigned_tx.input.len() == 1);

    tx.signature_hash(0, script_code, SigHashType::AllPlusAnyoneCanPay)
        .map(|sighash| {
            secp256k1::Message::from_slice(&sighash.as_hash().into_inner())
                .expect("sighash is a 32 bytes hash")
        })
        .expect("Asserted above")
}

/// An error thrown when the verification of a ALL|ANYONECANPAY signature fails
#[derive(Debug)]
enum ACPSigError {
    InvalidLength,
    InvalidSighash,
    VerifError(secp256k1::Error),
}

impl std::fmt::Display for ACPSigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "Invalid length of signature"),
            Self::InvalidSighash => write!(f, "Invalid SIGHASH type"),
            Self::VerifError(e) => write!(f, "Signature verification error: '{}'", e),
        }
    }
}

impl std::error::Error for ACPSigError {}

impl From<secp256k1::Error> for ACPSigError {
    fn from(e: secp256k1::Error) -> Self {
        Self::VerifError(e)
    }
}

// Check all complete signatures for revocation transactions (ie Cancel, Emergency,
// or UnvaultEmergency)
fn check_revocation_signatures(
    secp: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    tx: &impl RevaultTransaction,
    script_code: &Script,
    sigs: &BTreeMap<BitcoinPubKey, Vec<u8>>,
) -> Result<(), ACPSigError> {
    let sighash = revocation_tx_sighash(tx, script_code);

    for (pubkey, sig) in sigs {
        let (sighash_type, sig) = sig.split_last().unwrap();
        if *sighash_type != SigHashType::AllPlusAnyoneCanPay as u8 {
            return Err(ACPSigError::InvalidSighash);
        }
        secp.verify(&sighash, &Signature::from_der(&sig)?, &pubkey.key)?;
    }

    Ok(())
}

// Check a raw (without SIGHASH type) revocation tx (ie Cancel, Emergency, or
// UnvaultEmergency) signature
fn check_revocation_signature(
    secp: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    tx: &impl RevaultTransaction,
    script_code: &Script,
    pubkey: BitcoinPubKey,
    sig: &Signature,
) -> Result<(), secp256k1::Error> {
    let sighash = revocation_tx_sighash(tx, script_code);

    secp.verify(&sighash, sig, &pubkey.key)?;

    Ok(())
}

// Send a `sig` (https://github.com/re-vault/practical-revault/blob/master/messages.md#sig-1)
// message to the server for all the sigs of this mapping.
// Note that we are looping, but most (if not all) will only have a single signature
// attached. We are called by the `revocationtxs` RPC, sent after a `getrevocationtxs`
// which generates fresh unsigned transactions.
//
// `sigs` MUST contain valid signatures (including the attached sighash type)
fn send_sig_msg(
    transport: &mut KKTransport,
    id: Txid,
    sigs: BTreeMap<BitcoinPubKey, Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // FIXME: use pop_last() once it's stable
    for (pubkey, sig) in sigs.into_iter() {
        let pubkey = pubkey.key;
        let (sigtype, sig) = sig
            .split_last()
            .expect("They must provide valid signatures");
        assert_eq!(*sigtype, SigHashType::AllPlusAnyoneCanPay as u8);

        let signature = RevaultSignature::PlaintextSig(
            Signature::from_der(&sig).expect("They must provide valid signatures"),
        );
        let sig_msg = Sig {
            pubkey,
            signature,
            id,
        };
        log::trace!(
            "Sending sig '{:?}' to sync server: '{}'",
            sig_msg,
            serde_json::to_string(&sig_msg)?,
        );
        // FIXME: here or upstream, we should retry until timeout
        transport.write(&serde_json::to_vec(&sig_msg)?)?;
    }

    Ok(())
}

// Send the signatures for the 3 revocation txs to the Coordinator
fn share_signatures(
    revaultd: &RevaultD,
    cancel: (&CancelTransaction, BTreeMap<BitcoinPubKey, Vec<u8>>),
    emer: (&EmergencyTransaction, BTreeMap<BitcoinPubKey, Vec<u8>>),
    unvault_emer: (
        &UnvaultEmergencyTransaction,
        BTreeMap<BitcoinPubKey, Vec<u8>>,
    ),
) -> Result<(), Box<dyn std::error::Error>> {
    let mut transport = KKTransport::connect(
        revaultd.coordinator_host,
        &revaultd.noise_secret,
        &revaultd.coordinator_noisekey,
    )?;

    let cancel_txid = cancel.0.inner_tx().global.unsigned_tx.txid();
    send_sig_msg(&mut transport, cancel_txid, cancel.1)?;
    let emer_txid = emer.0.inner_tx().global.unsigned_tx.txid();
    send_sig_msg(&mut transport, emer_txid, emer.1)?;
    let unvault_emer_txid = unvault_emer.0.inner_tx().global.unsigned_tx.txid();
    send_sig_msg(&mut transport, unvault_emer_txid, unvault_emer.1)?;

    Ok(())
}

// Get all signatures required to finalize the single-input revocation `tx`. This
// will finalize `tx` in place.
fn fetch_revocation_signatures(
    revaultd: &RevaultD,
    tx: &mut impl RevaultTransaction,
    script_code: &Script,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut transport = KKTransport::connect(
        revaultd.coordinator_host,
        &revaultd.noise_secret,
        &revaultd.coordinator_noisekey,
    )?;
    let secp_ctx = &revaultd.secp_ctx;
    let id = tx.inner_tx().global.unsigned_tx.txid();
    let getsigs_msg = GetSigs { id };

    // Revocation transactions (at this stage) only have one input. If we were
    // passed a >1 input transaction, we'd never get out of the loop.
    assert!(tx.inner_tx().global.unsigned_tx.input.len() == 1);

    loop {
        log::trace!(
            "Sending to sync server: '{}'",
            serde_json::to_string(&getsigs_msg)?,
        );
        transport.write(&serde_json::to_vec(&getsigs_msg)?)?;
        let recvd_raw = transport.read()?;
        log::trace!(
            "Receiving from sync server: '{}'",
            &String::from_utf8_lossy(&recvd_raw)
        );
        let Sigs { signatures } = serde_json::from_slice(&recvd_raw)?;

        for (key, sig) in signatures {
            let pubkey = BitcoinPubKey {
                compressed: true,
                key,
            };
            if !tx.inner_tx().inputs[0].partial_sigs.contains_key(&pubkey) {
                log::debug!(
                    "Adding signature '{:?}' for pubkey '{}' for tx '{}'",
                    sig,
                    pubkey,
                    id
                );
                match sig {
                    RevaultSignature::PlaintextSig(sig) => {
                        check_revocation_signature(secp_ctx, tx, script_code, pubkey, &sig)?;
                        // We just checked signature validity for ALL | ACP
                        tx.add_signature(0, pubkey, (sig, SigHashType::AllPlusAnyoneCanPay))?;
                    }
                    // We never share encrypted signatures. Of course it's broken as we don't
                    // trust the server.
                    // FIXME: either implement encrypted signatures or remove it from the types
                    // upstream. See https://github.com/re-vault/practical-revault/issues/72
                    RevaultSignature::EncryptedSig { .. } => unreachable!(),
                }
            }
        }

        let res = tx.finalize(&revaultd.secp_ctx);
        log::trace!("Finalization result: {:?}", res);
        if res.is_ok() {
            log::debug!("Got all signatures for '{}'", id);
            return Ok(());
        }

        log::debug!("Still waiting for signatures for '{}'", id);
        // We assume other signers are actively performing the routine signing.
        // FIXME: of course, it's bad..
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// Handle events incoming from the JSONRPC interface.
pub fn handle_rpc_messages(
    revaultd: Arc<RwLock<RevaultD>>,
    db_path: PathBuf,
    network: Network,
    rpc_rx: Receiver<RpcMessageIn>,
    bitcoind_tx: Sender<BitcoindMessageOut>,
    bitcoind_thread: JoinHandle<()>,
    jsonrpc_thread: JoinHandle<()>,
) -> Result<(), ControlError> {
    for msg in rpc_rx {
        match msg {
            RpcMessageIn::Shutdown => {
                log::info!("Stopping revaultd.");
                bitcoind_tx.send(BitcoindMessageOut::Shutdown)?;

                assume_ok!(jsonrpc_thread.join(), "Joining RPC server thread");
                assume_ok!(bitcoind_thread.join(), "Joining bitcoind thread");
                process::exit(0);
            }
            RpcMessageIn::GetInfo(response_tx) => {
                log::trace!("Got getinfo from RPC thread");

                let (bitrep_tx, bitrep_rx) = mpsc::sync_channel(0);
                bitcoind_tx.send(BitcoindMessageOut::SyncProgress(bitrep_tx))?;
                let progress = bitrep_rx.recv()?;

                // This means blockheight == 0 for IBD.
                let BlockchainTip {
                    height: blockheight,
                    ..
                } = db_tip(&db_path)?;

                response_tx.send((network.to_string(), blockheight, progress))?;
            }
            RpcMessageIn::ListVaults((statuses, outpoints), response_tx) => {
                log::trace!("Got listvaults from RPC thread");
                response_tx.send(listvaults_from_db(
                    &revaultd.read().unwrap(),
                    statuses,
                    outpoints,
                )?)?;
            }
            RpcMessageIn::DepositAddr(response_tx) => {
                log::trace!("Got 'depositaddr' request from RPC thread");
                response_tx.send(revaultd.read().unwrap().deposit_address())?;
            }
            RpcMessageIn::GetRevocationTxs(outpoint, response_tx) => {
                log::trace!("Got 'getrevocationtxs' request from RPC thread");
                let revaultd = revaultd.read().unwrap();
                let xpub_ctx = revaultd.xpub_ctx();
                let db_file = &revaultd.db_file();

                // First, make sure the vault exists and is confirmed.
                let vault = match db_vault_by_deposit(db_file, &outpoint)? {
                    None => None,
                    Some(vault) => match vault.status {
                        VaultStatus::Unconfirmed => None,
                        _ => Some(vault),
                    },
                };
                if let Some(vault) = vault {
                    // Second, derive the fully-specified deposit txout.
                    let deposit_descriptor =
                        revaultd.vault_descriptor.derive(vault.derivation_index);
                    let vault_txin = VaultTxIn::new(
                        outpoint,
                        VaultTxOut::new(vault.amount.as_sat(), &deposit_descriptor, xpub_ctx),
                    );

                    // Third, re-derive all the transactions out of it.
                    let unvault_descriptor =
                        revaultd.unvault_descriptor.derive(vault.derivation_index);
                    let cpfp_descriptor = revaultd.cpfp_descriptor.derive(vault.derivation_index);
                    let emer_address = revaultd.emergency_address.clone();

                    let (_, cancel, emergency, unvault_emer) = transaction_chain(
                        vault_txin,
                        &deposit_descriptor,
                        &unvault_descriptor,
                        &cpfp_descriptor,
                        emer_address,
                        xpub_ctx,
                        revaultd.lock_time,
                        revaultd.unvault_csv,
                    )?;

                    response_tx.send(Some((cancel, emergency, unvault_emer)))?;
                } else {
                    response_tx.send(None)?;
                }
            }
            RpcMessageIn::RevocationTxs(
                (outpoint, mut cancel_tx, mut emer_tx, mut unvault_emer_tx),
                response_tx,
            ) => {
                log::trace!("Got 'revocationtxs' from RPC thread");
                let revaultd = revaultd.read().unwrap();
                let secp_ctx = &revaultd.secp_ctx;

                // Checked by the RPC server
                assert!(revaultd.is_stakeholder());

                // They may only send revocation transactions for confirmed and not-yet-presigned
                // vaults.
                let db_vault = match db_vault_by_deposit(&revaultd.db_file(), &outpoint)? {
                    Some(v) => match v.status {
                        VaultStatus::Funded => v,
                        status => {
                            response_tx.send(Some(format!(
                                "Invalid vault status: expected {} but got {}",
                                VaultStatus::Funded,
                                status
                            )))?;
                            continue;
                        }
                    },
                    None => {
                        response_tx.send(Some(
                            "Outpoint does not correspond to an existing vault".to_string(),
                        ))?;
                        continue;
                    }
                };

                // Revocation transactions may only have an additional input for fee-bumping, which
                // is completely out of the scope of this call (pre-signing routine)
                if cancel_tx.inner_tx().global.unsigned_tx.input.len() != 1 {
                    response_tx.send(Some(format!(
                        "Invalid Cancel tx: expected a single input but got '{}'",
                        cancel_tx.inner_tx().inputs.len()
                    )))?;
                    continue;
                }
                if emer_tx.inner_tx().global.unsigned_tx.input.len() != 1 {
                    response_tx.send(Some(format!(
                        "Invalid Emergency tx: expected a single input but got '{}'",
                        emer_tx.inner_tx().inputs.len()
                    )))?;
                    continue;
                }
                if unvault_emer_tx.inner_tx().global.unsigned_tx.input.len() != 1 {
                    response_tx.send(Some(format!(
                        "Invalid Unvault Emergency tx: expected a single input but got '{}'",
                        emer_tx.inner_tx().inputs.len()
                    )))?;
                    continue;
                }

                let deriv_index = db_vault.derivation_index;
                let cancel_sigs = cancel_tx
                    .inner_tx()
                    .inputs
                    .get(0)
                    .expect("Cancel tx has a single input, inbefore fee bumping.")
                    .partial_sigs
                    .clone();
                let emer_sigs = emer_tx
                    .inner_tx()
                    .inputs
                    .get(0)
                    .expect("Emergency tx has a single input, inbefore fee bumping.")
                    .partial_sigs
                    .clone();
                let unvault_emer_sigs = unvault_emer_tx
                    .inner_tx()
                    .inputs
                    .get(0)
                    .expect("UnvaultEmergency tx has a single input, inbefore fee bumping.")
                    .partial_sigs
                    .clone();
                let deposit_script_code = revaultd
                    .vault_descriptor
                    .0
                    .derive(deriv_index)
                    .script_code(revaultd.xpub_ctx());
                let unvault_script_code = revaultd
                    .unvault_descriptor
                    .0
                    .derive(deriv_index)
                    .script_code(revaultd.xpub_ctx());

                // They must have included *at least* a signature for our pubkey
                let our_pubkey = revaultd
                    .our_stk_xpub
                    .expect("We are a stakeholder")
                    .derive_pub(secp_ctx, &[deriv_index])
                    .expect("The derivation index stored in the database is sane (unhardened)")
                    .public_key;
                if !cancel_sigs.contains_key(&our_pubkey) {
                    response_tx.send(Some(format!(
                        "No signature for ourselves ({}) in Cancel transaction",
                        our_pubkey
                    )))?;
                    continue;
                }
                // We use the same public key across the transaction chain, that's pretty
                // neat from an usability perspective.
                if !emer_sigs.contains_key(&our_pubkey) {
                    response_tx.send(Some(
                        "No signature for ourselves in Emergency transaction".to_string(),
                    ))?;
                    continue;
                }
                if !unvault_emer_sigs.contains_key(&our_pubkey) {
                    response_tx.send(Some(
                        "No signature for ourselves in UnvaultEmergency transaction".to_string(),
                    ))?;
                    continue;
                }

                // Don't share anything if we were given invalid signatures. This
                // checks for the presence of a SIGHASH type flag.
                if let Err(e) = check_revocation_signatures(
                    secp_ctx,
                    &cancel_tx,
                    &unvault_script_code,
                    &cancel_sigs,
                ) {
                    response_tx.send(Some(format!(
                        "Invalid signature in Cancel transaction: {}",
                        e
                    )))?;
                    continue;
                }
                if let Err(e) = check_revocation_signatures(
                    secp_ctx,
                    &emer_tx,
                    &deposit_script_code,
                    &emer_sigs,
                ) {
                    response_tx.send(Some(format!(
                        "Invalid signature in Emergency transaction: {}",
                        e
                    )))?;
                    continue;
                }
                if let Err(e) = check_revocation_signatures(
                    secp_ctx,
                    &unvault_emer_tx,
                    &unvault_script_code,
                    &unvault_emer_sigs,
                ) {
                    response_tx.send(Some(format!(
                        "Invalid signature in Unvault Emergency transaction: {}",
                        e
                    )))?;
                    continue;
                }

                // Ok, signatures look legit. Share them with our felow stakeholders.
                if let Err(e) = share_signatures(
                    &revaultd,
                    (&cancel_tx, cancel_sigs),
                    (&emer_tx, emer_sigs),
                    (&unvault_emer_tx, unvault_emer_sigs),
                ) {
                    response_tx.send(Some(format!("Error while sharing signatures: {}", e)))?;
                    continue;
                }

                // Now, fetch others' signatures
                // FIXME: do that in a background process.
                if let Err(e) =
                    fetch_revocation_signatures(&revaultd, &mut cancel_tx, &unvault_script_code)
                {
                    response_tx.send(Some(format!(
                        "Error while fetching Cancel signatures: {}",
                        e
                    )))?;
                    continue;
                }
                if let Err(e) =
                    fetch_revocation_signatures(&revaultd, &mut emer_tx, &deposit_script_code)
                {
                    response_tx.send(Some(format!(
                        "Error while fetching Emergency signatures: {}",
                        e
                    )))?;
                    continue;
                }
                if let Err(e) = fetch_revocation_signatures(
                    &revaultd,
                    &mut unvault_emer_tx,
                    &unvault_script_code,
                ) {
                    response_tx.send(Some(format!(
                        "Error while fetching UnvaultEmergency signatures: {}",
                        e
                    )))?;
                    continue;
                }

                // We are now all set, with valid revocation transactions, life is good, bitcoins
                // are safe.
                db_store_revocation_txs(
                    &revaultd.db_file(),
                    db_vault.id,
                    cancel_tx,
                    emer_tx,
                    unvault_emer_tx,
                )?;

                // Ok, RPC server, tell them that everything is fine.
                response_tx.send(None)?;
            }
            RpcMessageIn::ListTransactions(outpoints, response_tx) => {
                log::trace!("Got 'listtransactions' request from RPC thread");
                response_tx.send(txlist_from_outpoints(
                    &revaultd.read().unwrap(),
                    &bitcoind_tx,
                    outpoints,
                )?)?;
            }
        }
    }

    Ok(())
}
