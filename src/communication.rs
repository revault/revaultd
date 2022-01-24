use crate::{database::schema::DbTransaction, revaultd::RevaultD};

use revault_net::{
    message::{
        coordinator::{self, GetSigs, SetSpendResult, SetSpendTx, Sigs},
        cosigner::{SignRequest, SignResult},
        watchtower,
    },
    transport::KKTransport,
};
use revault_tx::{
    bitcoin::{
        consensus::encode, hashes::hex::ToHex, secp256k1, util::bip32::ChildNumber, OutPoint, Txid,
    },
    miniscript::DescriptorTrait,
    transactions::{RevaultTransaction, SpendTransaction},
};

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

/// The kind of signature the WT refused
#[derive(Debug)]
pub enum WtSigNackKind {
    Revocation,
    Unvault,
}

impl fmt::Display for WtSigNackKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WtSigNackKind::Revocation => write!(f, "revocation"),
            WtSigNackKind::Unvault => write!(f, "unvault"),
        }
    }
}

/// An error that occured when talking to a server
#[derive(Debug)]
pub enum CommunicationError {
    /// An error internal to revault_net, generally a transport error
    Net(revault_net::Error),
    /// The watchtower refused to store one of our signatures
    WatchtowerNack(OutPoint, WtSigNackKind),
    /// The Coordinator told us they could not store our signature
    SignatureStorage,
    /// The Coordinator told us they could not store our Spend transaction
    SpendTxStorage,
    /// The Cosigning Server returned null to our request!
    CosigAlreadySigned,
    /// The Cosigning Server tried to fool us!
    CosigInsanePsbt,
}

impl fmt::Display for CommunicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Net(e) => write!(f, "Network error: '{}'", e),
            Self::WatchtowerNack(op, kind) => write!(
                f,
                "Watchtower refused to store one of our {} signatures for vault '{}'",
                kind, op
            ),
            Self::SignatureStorage => {
                write!(f, "Coordinator error: it failed to store the signature")
            }
            Self::SpendTxStorage => write!(
                f,
                "Coordinator error: it failed to store the Spending transaction"
            ),
            Self::CosigAlreadySigned => write!(
                f,
                "Cosigning server error: one Cosigning Server already \
                    signed a Spend transaction spending one of these vaults."
            ),
            Self::CosigInsanePsbt => write!(f, "Cosigning server error: they sent an insane PSBT"),
        }
    }
}

impl std::error::Error for CommunicationError {}

impl From<revault_net::Error> for CommunicationError {
    fn from(e: revault_net::Error) -> Self {
        Self::Net(e)
    }
}

// Send a `sigs` (https://github.com/revault/practical-revault/blob/master/messages.md#sigs)
// message to a watchtower.
fn send_wt_sigs_msg(
    transport: &mut KKTransport,
    deposit_outpoint: OutPoint,
    derivation_index: ChildNumber,
    emer_tx: &DbTransaction,
    cancel_tx: &DbTransaction,
    unemer_tx: &DbTransaction,
) -> Result<(), CommunicationError> {
    let signatures = watchtower::Signatures {
        emergency: emer_tx.psbt.signatures(),
        cancel: cancel_tx.psbt.signatures(),
        unvault_emergency: unemer_tx.psbt.signatures(),
    };
    let sig_msg = watchtower::Sigs {
        signatures,
        deposit_outpoint,
        derivation_index,
    };

    log::debug!("Sending signatures to watchtower: '{:?}'", sig_msg);
    let sig_result: watchtower::SigsResult = transport.send_req(&sig_msg.into())?;
    log::debug!(
        "Got response to signatures for '{}' from watchtower: '{:?}'",
        deposit_outpoint,
        sig_result
    );
    if !sig_result.ack {
        return Err(CommunicationError::WatchtowerNack(
            deposit_outpoint,
            WtSigNackKind::Revocation,
        ));
    }

    Ok(())
}

// Send a `sig` (https://github.com/revault/practical-revault/blob/master/messages.md#sig-1)
// message to the server for all the sigs of this mapping.
// Note that we are looping, but most (if not all) will only have a single signature
// attached. We are called by the `revocationtxs` RPC, sent after a `getrevocationtxs`
// which generates fresh unsigned transactions.
//
// `sigs` MUST contain valid signatures (including the attached sighash type)
pub fn send_coord_sig_msg(
    transport: &mut KKTransport,
    id: Txid,
    sigs: BTreeMap<secp256k1::PublicKey, secp256k1::Signature>,
) -> Result<(), CommunicationError> {
    for (pubkey, signature) in sigs {
        let sig_msg = coordinator::Sig {
            pubkey,
            signature,
            id,
        };
        log::debug!("Sending sig '{:?}' to sync server", sig_msg,);
        let sig_result: coordinator::SigResult = transport.send_req(&sig_msg.into())?;
        log::debug!("Got from coordinator: '{:?}'", sig_result);
        if !sig_result.ack {
            return Err(CommunicationError::SignatureStorage);
        }
    }

    Ok(())
}

/// Share the revocation transactions' signatures with all our watchtowers.
pub fn wts_share_rev_signatures(
    noise_secret: &revault_net::noise::SecretKey,
    watchtowers: &[(std::net::SocketAddr, revault_net::noise::PublicKey)],
    deposit_outpoint: OutPoint,
    derivation_index: ChildNumber,
    emer_tx: &DbTransaction,
    cancel_tx: &DbTransaction,
    unemer_tx: &DbTransaction,
) -> Result<(), CommunicationError> {
    for (wt_host, wt_noisekey) in watchtowers {
        let mut transport = KKTransport::connect(*wt_host, noise_secret, wt_noisekey)?;

        send_wt_sigs_msg(
            &mut transport,
            deposit_outpoint,
            derivation_index,
            emer_tx,
            cancel_tx,
            unemer_tx,
        )?;
    }

    Ok(())
}

/// Send the signatures for the 3 revocation txs to the Coordinator
pub fn coord_share_rev_signatures(
    coordinator_host: std::net::SocketAddr,
    noise_secret: &revault_net::noise::SecretKey,
    coordinator_noisekey: &revault_net::noise::PublicKey,
    rev_txs: &[DbTransaction],
) -> Result<(), CommunicationError> {
    let mut transport = KKTransport::connect(coordinator_host, noise_secret, coordinator_noisekey)?;

    for tx in rev_txs {
        send_coord_sig_msg(&mut transport, tx.psbt.txid(), tx.psbt.signatures())?;
    }

    Ok(())
}

/// Send the unvault signature to the Coordinator
pub fn share_unvault_signatures(
    coordinator_host: std::net::SocketAddr,
    noise_secret: &revault_net::noise::SecretKey,
    coordinator_noisekey: &revault_net::noise::PublicKey,
    unvault_tx: &DbTransaction,
) -> Result<(), CommunicationError> {
    let mut transport = KKTransport::connect(coordinator_host, noise_secret, coordinator_noisekey)?;

    send_coord_sig_msg(
        &mut transport,
        unvault_tx.psbt.txid(),
        unvault_tx.psbt.signatures(),
    )
}

// A hack to workaround the immutability of the SpendTransaction.
// FIXME: should probably have a helper in revault_tx instead?
fn strip_signatures(spend_tx: SpendTransaction) -> SpendTransaction {
    let mut psbt = spend_tx.into_psbt();
    for psbtin in psbt.inputs.iter_mut() {
        psbtin.partial_sigs.clear();
    }
    SpendTransaction::from_raw_psbt(&encode::serialize(&psbt)).expect("We just deserialized it")
}

/// Make the cosigning servers sign this Spend transaction.
/// This method checks that the signatures are valid, but it doesn't
/// check that the cosigners are returning signatures in the first place.
pub fn fetch_cosigs_signatures<C: secp256k1::Verification>(
    secp: &secp256k1::Secp256k1<C>,
    noise_secret: &revault_net::noise::SecretKey,
    spend_tx: &mut SpendTransaction,
    cosigs: &[(std::net::SocketAddr, revault_net::noise::PublicKey)],
) -> Result<(), CommunicationError> {
    // Strip the signatures before polling the Cosigning Server. It does not check them
    // anyways, and it makes us hit the Noise message size limit fairly quickly.
    let tx = strip_signatures(spend_tx.clone());
    let msg = SignRequest { tx };
    log::trace!(
        "Prepared msg to fetch cosigning servers signatures: '{:?}'",
        msg
    );

    for (host, noise_key) in cosigs {
        // FIXME: connect should take a reference... This copy is useless
        let mut transport = KKTransport::connect(*host, noise_secret, noise_key)?;
        log::debug!(
            "Polling cosigning server at '{}' (key: '{}') for spend '{}'",
            host,
            noise_key.0.to_hex(),
            spend_tx.txid(),
        );

        let sign_res: SignResult = transport.send_req(&msg.clone().into())?;
        let signed_tx = sign_res.tx.ok_or(CommunicationError::CosigAlreadySigned)?;
        log::debug!("Cosigning server returned: '{}'", &signed_tx,);

        for (i, psbtin) in signed_tx.into_psbt().inputs.into_iter().enumerate() {
            for (key, sig) in psbtin.partial_sigs {
                let (_, rawsig) = sig
                    .split_last()
                    .ok_or(CommunicationError::CosigInsanePsbt)?;
                let sig = secp256k1::Signature::from_der(rawsig)
                    .map_err(|_| CommunicationError::CosigInsanePsbt)?;
                spend_tx
                    .add_signature(i, key.key, sig, secp)
                    .map_err(|_| CommunicationError::CosigInsanePsbt)?;
            }
        }
    }

    Ok(())
}

/// Sends the spend transaction for a certain outpoint to the coordinator
pub fn announce_spend_transaction(
    coordinator_host: std::net::SocketAddr,
    noise_secret: &revault_net::noise::SecretKey,
    coordinator_noisekey: &revault_net::noise::PublicKey,
    spend_tx: SpendTransaction,
    deposit_outpoints: Vec<OutPoint>,
) -> Result<(), CommunicationError> {
    let mut transport = KKTransport::connect(coordinator_host, noise_secret, coordinator_noisekey)?;

    let msg = SetSpendTx::from_spend_tx(deposit_outpoints, spend_tx);
    log::debug!("Sending Spend tx to Coordinator: '{:?}'", msg);
    let resp: SetSpendResult = transport.send_req(&msg.into())?;
    log::debug!("Got from Coordinator: '{:?}'", resp);
    if !resp.ack {
        return Err(CommunicationError::SpendTxStorage);
    }

    Ok(())
}

/// Get the signatures for this presigned transaction from the Coordinator.
pub fn get_presigs(
    transport: &mut KKTransport,
    txid: Txid,
) -> Result<BTreeMap<secp256k1::PublicKey, secp256k1::Signature>, CommunicationError> {
    let getsigs_msg = GetSigs { id: txid };

    log::debug!("Sending to sync server: '{:?}'", getsigs_msg,);
    let resp: Sigs = transport.send_req(&getsigs_msg.into())?;
    log::debug!("Got sigs {:?} from coordinator.", resp);

    Ok(resp.signatures)
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerStatus {
    pub host: String,
    pub reachable: bool,
}

/// Make a dummy connection to the coordinator to check whether it's up
pub fn coordinator_status(revaultd: &RevaultD) -> ServerStatus {
    let reachable = KKTransport::connect(
        revaultd.coordinator_host,
        &revaultd.noise_secret,
        &revaultd.coordinator_noisekey,
    )
    .is_ok();

    ServerStatus {
        host: revaultd.coordinator_host.to_string(),
        reachable,
    }
}

/// Make a dummy connection to the cosigning servers to check whether they're up
pub fn cosigners_status(revaultd: &RevaultD) -> Vec<ServerStatus> {
    let mut cosigners = Vec::new();
    if let Some(c) = &revaultd.cosigs {
        for (host, key) in c {
            let reachable = KKTransport::connect(*host, &revaultd.noise_secret, key).is_ok();

            cosigners.push(ServerStatus {
                host: host.to_string(),
                reachable,
            });
        }
    }
    cosigners
}

/// Make a dummy connection to the watchtowers to check whether they're up
pub fn watchtowers_status(revaultd: &RevaultD) -> Vec<ServerStatus> {
    let mut watchtowers = Vec::new();
    if let Some(w) = &revaultd.watchtowers {
        for (host, key) in w {
            let reachable = KKTransport::connect(*host, &revaultd.noise_secret, key).is_ok();

            watchtowers.push(ServerStatus {
                host: host.to_string(),
                reachable,
            });
        }
    }

    watchtowers
}

/// This function estimates (conservatively) the size of the message
/// for sending the fully-signed tx to the coordinator, returning
/// if the size is smaller than NOISE_PLAINTEXT_MAX_SIZE
pub fn check_spend_transaction_size(revaultd: &RevaultD, spend_tx: SpendTransaction) -> bool {
    let tx_finalized = spend_tx.is_finalized();
    let mut tx = spend_tx.into_psbt().extract_tx();

    if !tx_finalized {
        let max_satisfaction_weight = revaultd
            .unvault_descriptor
            .inner()
            .max_satisfaction_weight()
            .expect("Script must be satisfiable");
        for input in tx.input.iter_mut() {
            // It's not exact, but close enough
            input.witness.push(vec![0; max_satisfaction_weight]);
        }
    }

    let deposit_outpoints: Vec<OutPoint> = tx.input.iter().map(|i| i.previous_output).collect();
    let tx = base64::encode(encode::serialize(&tx));
    let msg = serde_json::to_string(&serde_json::json!( {
        "deposit_outpoints": deposit_outpoints,
        "transaction": tx,
    }))
    .expect("JSON created inline");
    msg.len() <= revault_net::noise::NOISE_PLAINTEXT_MAX_SIZE
}

#[cfg(test)]
mod tests {
    use crate::{
        communication::*,
        database::{
            bitcointx::{RevaultTx, TransactionType},
            schema::DbTransaction,
        },
        utils::test_utils::{dummy_revaultd, test_datadir, UserRole},
    };
    use revault_net::{
        message, sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::gen_keypair,
        transport::KKTransport,
    };
    use revault_tx::{
        bitcoin::{
            blockdata::transaction::OutPoint, hash_types::Txid, hashes::hex::FromHex,
            network::constants::Network, secp256k1, PrivateKey as BitcoinPrivKey,
            PublicKey as BitcoinPubKey, SigHashType,
        },
        transactions::{
            CancelTransaction, EmergencyTransaction, RevaultTransaction, SpendTransaction,
            UnvaultEmergencyTransaction, UnvaultTransaction,
        },
    };
    use std::{collections::BTreeMap, fs, net::TcpListener, str::FromStr, thread};

    fn create_keys(
        ctx: &secp256k1::Secp256k1<secp256k1::All>,
        secret_slice: &[u8],
    ) -> (BitcoinPrivKey, BitcoinPubKey) {
        let secret_key = secp256k1::SecretKey::from_slice(secret_slice).unwrap();
        let private_key = BitcoinPrivKey {
            compressed: true,
            network: Network::Regtest,
            key: secret_key,
        };
        let public_key = BitcoinPubKey::from_private_key(&ctx, &private_key);
        (private_key, public_key)
    }

    // This time the coordinator won't ack our signatures :(
    #[test]
    fn test_send_coord_sig_msg_not_acked() {
        let txid =
            Txid::from_str("fcb6ab963b654c773de786f4ac92c132b3d2e816ccea37af9592aa0b4aaec04b")
                .unwrap();
        let ctx = secp256k1::Secp256k1::new();
        let (_, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let mut sigs = BTreeMap::new();
        let signature = secp256k1::Signature::from_str("304402201a3109a4a6445c1e56416bc39520aada5c8ad089e69ee4f1a40a0901de1a435302204b281ba97da2ab2e40eb65943ae414cc4307406c5eb177b1c646606839a2e99d").unwrap();
        sigs.insert(public_key.key, signature.clone());

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            let mut cli_transport = KKTransport::connect(addr, &client_privkey, &server_pubkey)
                .expect("Client channel connecting");
            assert!(
                send_coord_sig_msg(&mut cli_transport, txid.clone(), sigs.clone())
                    .unwrap_err()
                    .to_string()
                    .contains(&CommunicationError::SignatureStorage.to_string())
            );
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(coordinator::Sig {
                        pubkey: public_key.key,
                        signature,
                        id: txid
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: false },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    // This time the server likes our signatures! :tada:
    #[test]
    fn test_send_coord_sig_msg() {
        let txid =
            Txid::from_str("fcb6ab963b654c773de786f4ac92c132b3d2e816ccea37af9592aa0b4aaec04b")
                .unwrap();
        let ctx = secp256k1::Secp256k1::new();
        let (_, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let mut sigs = BTreeMap::new();
        let signature = secp256k1::Signature::from_str("304402201a3109a4a6445c1e56416bc39520aada5c8ad089e69ee4f1a40a0901de1a435302204b281ba97da2ab2e40eb65943ae414cc4307406c5eb177b1c646606839a2e99d").unwrap();
        sigs.insert(public_key.key, signature.clone());

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            let mut cli_transport = KKTransport::connect(addr, &client_privkey, &server_pubkey)
                .expect("Client channel connecting");
            send_coord_sig_msg(&mut cli_transport, txid.clone(), sigs.clone()).unwrap();
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(coordinator::Sig {
                        pubkey: public_key.key,
                        signature,
                        id: txid
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: true },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_share_rev_signatures_not_acked() {
        let ctx = secp256k1::Secp256k1::new();
        let (private_key, public_key) =
            create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let mut cancel =
                CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAASDOvhSZlTSEcEoUq/CT7Cg3ILtc6sqt5qJKvAMq+LbIAAAAAAD9////AXYfpDUAAAAAIgAg9AncsIZc8g7mJdfT9infAeWlqjtxBs93ireDGnQn/DYAAAAAAAEBK7hhpDUAAAAAIgAgFZlOQkpDkFSsLUfyeMGVAOT3T88jZM7L/XlVZoJ2jnABAwSBAAAAAQWpIQMVlEoh50lasMhcdwnrmnCp2ROlGY5CrH+HtxQmfZDZ06xRh2R2qRS/INUX1CaP7Pbn5GmtGYu2wgqjnIisa3apFO/kceq8yo9w69g4VVtlFAf739qTiKxsk1KHZ1IhAnddfXi3N38A+aEQ74sUdeuV7sg+2L3ijTjMHMEAfq3cIQLWP96FqjfC5qKQkC2WhYbbLJx1FbNSAjsnMfwDnK0jD1KvARKyaCIGAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBR1IhA47+JRqdt+oloFosla9hWUYVf5YQKDbuq4KO13JS45KgIQMKcLWzABxb/9YBQe+bJRW3v3om8S2LNMGUKSp5K+PQ+1KuIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap();
        let signature_hash = secp256k1::Message::from_slice(
            &cancel
                .signature_hash(0, SigHashType::AllPlusAnyoneCanPay)
                .unwrap(),
        )
        .unwrap();
        let signature = ctx.sign(&signature_hash, &private_key.key);
        cancel
            .add_cancel_sig(public_key.key, signature, &ctx)
            .unwrap();
        let other_cancel = cancel.clone();
        let db_tx = DbTransaction {
            id: 0,
            vault_id: 0,
            tx_type: TransactionType::Cancel,
            psbt: RevaultTx::Cancel(cancel),
            is_fully_signed: false,
        };

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            assert!(
                coord_share_rev_signatures(addr, &client_privkey, &server_pubkey, &[db_tx])
                    .unwrap_err()
                    .to_string()
                    .contains(&CommunicationError::SignatureStorage.to_string())
            );
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(coordinator::Sig {
                        pubkey: public_key.key,
                        signature,
                        id: other_cancel.txid(),
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: false },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_share_rev_signatures() {
        let ctx = secp256k1::Secp256k1::new();
        let (privkey, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let mut cancel =
                CancelTransaction::from_psbt_str("cHNidP8BAF4CAAAAASDOvhSZlTSEcEoUq/CT7Cg3ILtc6sqt5qJKvAMq+LbIAAAAAAD9////AXYfpDUAAAAAIgAg9AncsIZc8g7mJdfT9infAeWlqjtxBs93ireDGnQn/DYAAAAAAAEBK7hhpDUAAAAAIgAgFZlOQkpDkFSsLUfyeMGVAOT3T88jZM7L/XlVZoJ2jnABAwSBAAAAAQWpIQMVlEoh50lasMhcdwnrmnCp2ROlGY5CrH+HtxQmfZDZ06xRh2R2qRS/INUX1CaP7Pbn5GmtGYu2wgqjnIisa3apFO/kceq8yo9w69g4VVtlFAf739qTiKxsk1KHZ1IhAnddfXi3N38A+aEQ74sUdeuV7sg+2L3ijTjMHMEAfq3cIQLWP96FqjfC5qKQkC2WhYbbLJx1FbNSAjsnMfwDnK0jD1KvARKyaCIGAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBR1IhA47+JRqdt+oloFosla9hWUYVf5YQKDbuq4KO13JS45KgIQMKcLWzABxb/9YBQe+bJRW3v3om8S2LNMGUKSp5K+PQ+1KuIgICEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAA").unwrap();
        let signature_hash = secp256k1::Message::from_slice(
            &cancel
                .signature_hash(0, SigHashType::AllPlusAnyoneCanPay)
                .unwrap(),
        )
        .unwrap();
        let signature_cancel = ctx.sign(&signature_hash, &privkey.key);
        cancel
            .add_cancel_sig(public_key.key, signature_cancel, &ctx)
            .unwrap();
        let mut emer =
                EmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAajRZE5yVgzG9McmOyy/WdcYdrGrK15bB5N/Hg8zhKOkAQAAAAD9////AXC1pDUAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBKwDppDUAAAAAIgAg9AncsIZc8g7mJdfT9infAeWlqjtxBs93ireDGnQn/DYBAwSBAAAAAQVHUiEDjv4lGp236iWgWiyVr2FZRhV/lhAoNu6rgo7XclLjkqAhAwpwtbMAHFv/1gFB75slFbe/eibxLYs0wZQpKnkr49D7Uq4iBgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAAiAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap();
        let signature_hash = secp256k1::Message::from_slice(
            &emer
                .signature_hash(0, SigHashType::AllPlusAnyoneCanPay)
                .unwrap(),
        )
        .unwrap();
        let signature_emer = ctx.sign(&signature_hash, &privkey.key);
        emer.add_emer_sig(public_key.key, signature_emer, &ctx)
            .unwrap();
        let mut unvault_emer =
                UnvaultEmergencyTransaction::from_psbt_str("cHNidP8BAF4CAAAAAbmw9RR44LLNO5aKs0SOdUDW4aJgM9indHt2KSEVkRNBAAAAAAD9////AaQvhEcAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK9BxhEcAAAAAIgAgMJBZ5AwbSGM9P3Q44qxIeXv5J4UXLnhwdfblfBLn2voBAwSBAAAAAQWoIQL5vFDdmMV/P4SpzIWhDMbHKHMGlMwntZxaWtwUXd9KvKxRh2R2qRTtnZLjf14tI1q08+ZyoIEpuuMqWYisa3apFJKFWLx/I+YKyIXcNmwC0yw69uN9iKxsk1KHZ1IhAw9kuSKu4v1ZfxBLxss7Zw8cosbEmxBxoabAEFddlP5aIQKr5HWxmew9YvpXb67hajNP24b/sm3Odb7Ouq7fMorD/lKvU7JoIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAA==").unwrap();
        let signature_hash = secp256k1::Message::from_slice(
            &unvault_emer
                .signature_hash(0, SigHashType::AllPlusAnyoneCanPay)
                .unwrap(),
        )
        .unwrap();
        let signature_unemer = ctx.sign(&signature_hash, &privkey.key);
        unvault_emer
            .add_emer_sig(public_key.key, signature_unemer, &ctx)
            .unwrap();
        let other_cancel = cancel.clone();
        let other_emer = emer.clone();
        let other_unvault_emer = unvault_emer.clone();
        let db_cancel = DbTransaction {
            id: 0,
            vault_id: 0,
            tx_type: TransactionType::Cancel,
            psbt: RevaultTx::Cancel(cancel),
            is_fully_signed: false,
        };
        let db_emer = DbTransaction {
            id: 0,
            vault_id: 0,
            tx_type: TransactionType::Emergency,
            psbt: RevaultTx::Emergency(emer),
            is_fully_signed: false,
        };
        let db_unemer = DbTransaction {
            id: 0,
            vault_id: 0,
            tx_type: TransactionType::UnvaultEmergency,
            psbt: RevaultTx::UnvaultEmergency(unvault_emer),
            is_fully_signed: false,
        };

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            coord_share_rev_signatures(
                addr,
                &client_privkey,
                &server_pubkey,
                &[db_cancel, db_emer, db_unemer],
            )
            .unwrap();
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(coordinator::Sig {
                        pubkey: public_key.key,
                        signature: signature_cancel,
                        id: other_cancel.txid(),
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: true },
                ))
            })
            .unwrap();

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(coordinator::Sig {
                        pubkey: public_key.key,
                        signature: signature_emer,
                        id: other_emer.txid(),
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: true },
                ))
            })
            .unwrap();

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(coordinator::Sig {
                        pubkey: public_key.key,
                        signature: signature_unemer,
                        id: other_unvault_emer.txid(),
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: true },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_share_unvault_signatures() {
        let mut unvault =
                UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAajRZE5yVgzG9McmOyy/WdcYdrGrK15bB5N/Hg8zhKOkAQAAAAD9////ArhhpDUAAAAAIgAgFZlOQkpDkFSsLUfyeMGVAOT3T88jZM7L/XlVZoJ2jnAwdQAAAAAAACIAILKCCA/RbV3QMPMrwwQmk4Ark4w1WyElM27WtBgftq6ZAAAAAAABASsA6aQ1AAAAACIAIPQJ3LCGXPIO5iXX0/Yp3wHlpao7cQbPd4q3gxp0J/w2AQMEAQAAAAEFR1IhA47+JRqdt+oloFosla9hWUYVf5YQKDbuq4KO13JS45KgIQMKcLWzABxb/9YBQe+bJRW3v3om8S2LNMGUKSp5K+PQ+1KuIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQGpIQMVlEoh50lasMhcdwnrmnCp2ROlGY5CrH+HtxQmfZDZ06xRh2R2qRS/INUX1CaP7Pbn5GmtGYu2wgqjnIisa3apFO/kceq8yo9w69g4VVtlFAf739qTiKxsk1KHZ1IhAnddfXi3N38A+aEQ74sUdeuV7sg+2L3ijTjMHMEAfq3cIQLWP96FqjfC5qKQkC2WhYbbLJx1FbNSAjsnMfwDnK0jD1KvARKyaCICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBJSEDjv4lGp236iWgWiyVr2FZRhV/lhAoNu6rgo7XclLjkqCsUYciAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap();
        let ctx = secp256k1::Secp256k1::new();
        let (privkey, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let signature_hash =
            secp256k1::Message::from_slice(&unvault.signature_hash(0, SigHashType::All).unwrap())
                .unwrap();
        let signature = ctx.sign(&signature_hash, &privkey.key);
        unvault
            .add_signature(0, public_key.key, signature.clone(), &ctx)
            .unwrap();
        let other_unvault = unvault.clone();
        let db_unvault = DbTransaction {
            id: 0,
            vault_id: 0,
            tx_type: TransactionType::Unvault,
            psbt: RevaultTx::Unvault(unvault),
            is_fully_signed: false,
        };

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            share_unvault_signatures(addr, &client_privkey, &server_pubkey, &db_unvault).unwrap();
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(coordinator::Sig {
                        pubkey: public_key.key,
                        signature,
                        id: other_unvault.txid(),
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: true },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_share_unvault_signatures_not_acked() {
        let mut unvault =
                UnvaultTransaction::from_psbt_str("cHNidP8BAIkCAAAAAajRZE5yVgzG9McmOyy/WdcYdrGrK15bB5N/Hg8zhKOkAQAAAAD9////ArhhpDUAAAAAIgAgFZlOQkpDkFSsLUfyeMGVAOT3T88jZM7L/XlVZoJ2jnAwdQAAAAAAACIAILKCCA/RbV3QMPMrwwQmk4Ark4w1WyElM27WtBgftq6ZAAAAAAABASsA6aQ1AAAAACIAIPQJ3LCGXPIO5iXX0/Yp3wHlpao7cQbPd4q3gxp0J/w2AQMEAQAAAAEFR1IhA47+JRqdt+oloFosla9hWUYVf5YQKDbuq4KO13JS45KgIQMKcLWzABxb/9YBQe+bJRW3v3om8S2LNMGUKSp5K+PQ+1KuIgYCEnb0lxeNI9466wDX+tqlq23zYNacTlLVLLLxtcVobG0INaO2mQoAAAAAAQGpIQMVlEoh50lasMhcdwnrmnCp2ROlGY5CrH+HtxQmfZDZ06xRh2R2qRS/INUX1CaP7Pbn5GmtGYu2wgqjnIisa3apFO/kceq8yo9w69g4VVtlFAf739qTiKxsk1KHZ1IhAnddfXi3N38A+aEQ74sUdeuV7sg+2L3ijTjMHMEAfq3cIQLWP96FqjfC5qKQkC2WhYbbLJx1FbNSAjsnMfwDnK0jD1KvARKyaCICAhJ29JcXjSPeOusA1/rapatt82DWnE5S1Syy8bXFaGxtCDWjtpkKAAAAAAEBJSEDjv4lGp236iWgWiyVr2FZRhV/lhAoNu6rgo7XclLjkqCsUYciAgISdvSXF40j3jrrANf62qWrbfNg1pxOUtUssvG1xWhsbQg1o7aZCgAAAAA=").unwrap();
        let ctx = secp256k1::Secp256k1::new();
        let (privkey, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let signature_hash =
            secp256k1::Message::from_slice(&unvault.signature_hash(0, SigHashType::All).unwrap())
                .unwrap();
        let signature = ctx.sign(&signature_hash, &privkey.key);
        unvault
            .add_signature(0, public_key.key, signature.clone(), &ctx)
            .unwrap();
        let other_unvault = unvault.clone();
        let db_unvault = DbTransaction {
            id: 0,
            vault_id: 0,
            tx_type: TransactionType::Unvault,
            psbt: RevaultTx::Unvault(unvault),
            is_fully_signed: false,
        };

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            assert!(
                share_unvault_signatures(addr, &client_privkey, &server_pubkey, &db_unvault,)
                    .unwrap_err()
                    .to_string()
                    .contains(&CommunicationError::SignatureStorage.to_string())
            );
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::CoordSig(coordinator::Sig {
                        pubkey: public_key.key,
                        signature,
                        id: other_unvault.txid(),
                    }),
                );
                Some(message::ResponseResult::Sig(
                    message::coordinator::SigResult { ack: false },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_fetch_cosigs_signatures() {
        let mut spend = SpendTransaction::from_psbt_str("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").unwrap();
        let ctx = secp256k1::Secp256k1::new();
        let (privkey, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let signature_hash =
            secp256k1::Message::from_slice(&spend.signature_hash(0, SigHashType::All).unwrap())
                .unwrap();
        let signature = ctx.sign(&signature_hash, &privkey.key);
        let mut other_spend = spend.clone();

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cosigs = vec![(addr, server_pubkey)];

        // client thread
        let cli_thread = thread::spawn(move || {
            // Our spend has no partial sigs...
            assert_eq!(spend.psbt().inputs.get(0).unwrap().partial_sigs.len(), 0);
            fetch_cosigs_signatures(&ctx, &client_privkey, &mut spend, &cosigs).unwrap();
            // Now our spend has one :)
            assert_eq!(spend.psbt().inputs.get(0).unwrap().partial_sigs.len(), 1);
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::Sign(SignRequest {
                        tx: other_spend.clone(),
                    }),
                );
                let ctx = secp256k1::Secp256k1::verification_only();
                other_spend
                    .add_signature(0, public_key.key, signature.clone(), &ctx)
                    .unwrap();
                Some(message::ResponseResult::SignResult(
                    message::cosigner::SignResult {
                        tx: Some(other_spend),
                    },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_fetch_cosigs_signatures_cosigner_already_signed() {
        let secp = secp256k1::Secp256k1::verification_only();
        let mut spend = SpendTransaction::from_psbt_str("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").unwrap();
        // Rust newbie: I need the spend but it's moved inside the closure, so I'm cloning
        // it now
        let other_spend = spend.clone();
        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cosigs = vec![(addr, server_pubkey)];

        // client thread
        let cli_thread = thread::spawn(move || {
            assert!(
                fetch_cosigs_signatures(&secp, &client_privkey, &mut spend, &cosigs)
                    .unwrap_err()
                    .to_string()
                    .contains(&CommunicationError::CosigAlreadySigned.to_string())
            );
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::Sign(SignRequest {
                        tx: other_spend.clone(),
                    }),
                );
                Some(message::ResponseResult::SignResult(
                    message::cosigner::SignResult { tx: None },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    /// The cosigner will send us the psbt with an invalid signature
    #[test]
    fn test_fetch_cosigs_signatures_invalid_signature() {
        let ctx = secp256k1::Secp256k1::new();
        let mut spend = SpendTransaction::from_psbt_str("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").unwrap();
        let mut psbt = spend.clone().into_psbt();
        let (_, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        // Not a DER signature
        let invalid_signature = Vec::<u8>::from_hex("1234").unwrap();
        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cosigs = vec![(addr, server_pubkey)];

        psbt.inputs[0]
            .partial_sigs
            .insert(public_key, invalid_signature);
        // FIXME: revault_tx should prevent us from doing this
        let other_spend = SpendTransaction::from_raw_psbt(&encode::serialize(&psbt)).unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            assert!(
                fetch_cosigs_signatures(&ctx, &client_privkey, &mut spend, &cosigs)
                    .unwrap_err()
                    .to_string()
                    .contains(&CommunicationError::CosigInsanePsbt.to_string())
            );
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|_| {
                Some(message::ResponseResult::SignResult(
                    message::cosigner::SignResult {
                        tx: Some(other_spend),
                    },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    #[should_panic(expected = "assertion failed: tx.is_finalized()")]
    fn test_announce_spend_transaction_not_finalized() {
        let spend = SpendTransaction::from_psbt_str("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").unwrap();

        let outpoints = vec![
            OutPoint::new(
                Txid::from_str("fcb6ab963b654c773de786f4ac92c132b3d2e816ccea37af9592aa0b4aaec04b")
                    .unwrap(),
                0,
            ),
            OutPoint::new(
                Txid::from_str("617eab1fc0b03ee7f82ba70166725291783461f1a0e7975eaf8b5f8f674234f2")
                    .unwrap(),
                1,
            ),
            OutPoint::new(
                Txid::from_str("a9735f42110ce529386f612194a1e137a2a2679ac0e789ad7f470cd70c3c2c24")
                    .unwrap(),
                2,
            ),
            OutPoint::new(
                Txid::from_str("cafa9f92be48ba41f9ee67e775b6c4afebd1bdbde5758792e9f30f6dea41e7fb")
                    .unwrap(),
                3,
            ),
        ];

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_thread = thread::spawn(move || {
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");
        });

        announce_spend_transaction(addr, &client_privkey, &server_pubkey, spend, outpoints)
            .unwrap();

        server_thread.join().unwrap();
    }

    #[test]
    fn test_announce_spend_transaction_not_acked() {
        let mut spend = SpendTransaction::from_psbt_str("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").unwrap();
        let ctx = secp256k1::Secp256k1::new();
        spend.finalize(&ctx).unwrap();

        let outpoints = vec![
            OutPoint::new(
                Txid::from_str("fcb6ab963b654c773de786f4ac92c132b3d2e816ccea37af9592aa0b4aaec04b")
                    .unwrap(),
                0,
            ),
            OutPoint::new(
                Txid::from_str("617eab1fc0b03ee7f82ba70166725291783461f1a0e7975eaf8b5f8f674234f2")
                    .unwrap(),
                1,
            ),
            OutPoint::new(
                Txid::from_str("a9735f42110ce529386f612194a1e137a2a2679ac0e789ad7f470cd70c3c2c24")
                    .unwrap(),
                2,
            ),
            OutPoint::new(
                Txid::from_str("cafa9f92be48ba41f9ee67e775b6c4afebd1bdbde5758792e9f30f6dea41e7fb")
                    .unwrap(),
                3,
            ),
        ];

        let other_spend = spend.clone();
        let other_outpoints = outpoints.clone();

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            assert!(announce_spend_transaction(
                addr,
                &client_privkey,
                &server_pubkey,
                spend,
                outpoints,
            )
            .unwrap_err()
            .to_string()
            .contains(&CommunicationError::SpendTxStorage.to_string()));
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::SetSpendTx(SetSpendTx::from_spend_tx(
                        other_outpoints,
                        other_spend,
                    ))
                );
                Some(message::ResponseResult::SetSpend(
                    message::coordinator::SetSpendResult { ack: false },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_announce_spend_transaction() {
        let mut spend = SpendTransaction::from_psbt_str("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").unwrap();
        let ctx = secp256k1::Secp256k1::new();
        spend.finalize(&ctx).unwrap();

        let outpoints = vec![
            OutPoint::new(
                Txid::from_str("fcb6ab963b654c773de786f4ac92c132b3d2e816ccea37af9592aa0b4aaec04b")
                    .unwrap(),
                0,
            ),
            OutPoint::new(
                Txid::from_str("617eab1fc0b03ee7f82ba70166725291783461f1a0e7975eaf8b5f8f674234f2")
                    .unwrap(),
                1,
            ),
            OutPoint::new(
                Txid::from_str("a9735f42110ce529386f612194a1e137a2a2679ac0e789ad7f470cd70c3c2c24")
                    .unwrap(),
                2,
            ),
            OutPoint::new(
                Txid::from_str("cafa9f92be48ba41f9ee67e775b6c4afebd1bdbde5758792e9f30f6dea41e7fb")
                    .unwrap(),
                3,
            ),
        ];

        let other_spend = spend.clone();
        let other_outpoints = outpoints.clone();

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            announce_spend_transaction(addr, &client_privkey, &server_pubkey, spend, outpoints)
                .unwrap();
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::SetSpendTx(SetSpendTx::from_spend_tx(
                        other_outpoints,
                        other_spend,
                    ))
                );
                Some(message::ResponseResult::SetSpend(
                    message::coordinator::SetSpendResult { ack: true },
                ))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_get_presigs() {
        let ctx = secp256k1::Secp256k1::new();
        let (_, public_key) = create_keys(&ctx, &[1; secp256k1::constants::SECRET_KEY_SIZE]);
        let signature = secp256k1::Signature::from_str("304402201a3109a4a6445c1e56416bc39520aada5c8ad089e69ee4f1a40a0901de1a435302204b281ba97da2ab2e40eb65943ae414cc4307406c5eb177b1c646606839a2e99d").unwrap();
        let mut sigs = BTreeMap::new();
        sigs.insert(public_key.key, signature);
        let other_sigs = sigs.clone();

        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let txid =
            Txid::from_str("cafa9f92be48ba41f9ee67e775b6c4afebd1bdbde5758792e9f30f6dea41e7fb")
                .unwrap();
        let same_txid = txid.clone();

        let cli_thread = thread::spawn(move || {
            let mut transport =
                KKTransport::connect(addr, &client_privkey, &server_pubkey).unwrap();
            let signatures = get_presigs(&mut transport, txid).unwrap();
            assert_eq!(signatures, sigs);
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        server_transport
            .read_req(|params| {
                assert_eq!(
                    &params,
                    &message::RequestParams::GetSigs(GetSigs { id: same_txid })
                );
                Some(message::ResponseResult::Sigs(message::coordinator::Sigs {
                    signatures: other_sigs,
                }))
            })
            .unwrap();
        cli_thread.join().unwrap();
    }

    #[test]
    fn test_check_spend_transaction_size() {
        let datadir = test_datadir();
        let revaultd = dummy_revaultd(datadir.clone(), UserRole::ManagerStakeholder);
        // 3 inputs, 4 outputs, 3 stakeholders and 3 manager psbt. No problem.
        let tx = SpendTransaction::from_psbt_str("cHNidP8BAP0ZAQIAAAADSe9QbkOAlLapVzhNT2J2sCWXMqe2x7g7klEr3N6+p8AAAAAAAAYAAABwwCBKiamcBn5fj0oQ3WcAU+twE4XemcK4G2nlprqBKAAAAAAABgAAAAwCYIUh0y2bkIH8BVZ/evuFulOCxOyGr/rvZnR2k/9aAAAAAAAGAAAABFCoAAAAAAAAIgAgvXwvxBU2X03+pufsytFJ2dS4BKVXIKMQmyxUXTbPJPmA8PoCAAAAABYAFCMDXGnefAb487YxeNjnpbUzH+pEQEtMAAAAAAAWABT+rq2LTo+bnAo3ZQoeUg0F6xVZbIx3EwIAAAAAIgAgfAYV/vqzwEWHS6kVMjA1yQRbIQqq//o7m4ik0eSSlasAAAAAAAEBKzb0VQMAAAAAIgAgEyIAQqFnv+D0rMmVvusK3TC6fPyFk7aU1PZ8+Ttm23IBAwQBAAAAAQXBUiEDNWoO4CCloCul5eCLd1+XLPxP4LMIsUy+XM01wlm59wIhAqQ3tGeAeMBPPR26fn0kuL0CS0AybrDlu8NwIzFOOukzIQJoBBIwDWTXwjMse2MiB8/kIcFOZACiADcmZltiEl85N1OuZHapFIe9/DRONZOp5OAQ6RCrIDclCDEjiKxrdqkUJs2E27SQYhbh4yxNkO+lDnFqCCaIrGyTa3apFBtcD9uL3TRJt1uCIj2J8Ub4YjvgiKxsk1OHZ1ayaCIGAmgEEjANZNfCMyx7YyIHz+QhwU5kAKIANyZmW2ISXzk3CO9FHBcBAAAAIgYCpDe0Z4B4wE89Hbp+fSS4vQJLQDJusOW7w3AjMU466TMIW+FtfgEAAAAiBgM1ag7gIKWgK6Xl4It3X5cs/E/gswixTL5czTXCWbn3AgjDFaC/AQAAAAABASs2rG0BAAAAACIAIICUwlAfLlUkhU44Hpkj/LEDNAdwME4fm3jtWfXwMwL7AQMEAQAAAAEFwVIhAgSNQIWSNnYSrfEl8juzTKw9o3BjYQ+DgbyizShqKzIcIQN+tRtybpIxVK9IdwxsTxFgy2YsiQqtnGvnowXelPblJiEC25bXunBKDpmrAvXiBbJ/+x9Oo5pL+8FhKgAqXSesn0VTrmR2qRTWWGTXm1UxE4rqqD2FkiKS94r8YYisa3apFCBven2wd5QCFoHAl/iRHg+9SJkgiKxsk2t2qRRP/mE3OesTO6kSJOgsBAoyLTfO8oisbJNTh2dWsmgiBgIEjUCFkjZ2Eq3xJfI7s0ysPaNwY2EPg4G8os0oaisyHAjDFaC/AAAAACIGAtuW17pwSg6ZqwL14gWyf/sfTqOaS/vBYSoAKl0nrJ9FCO9FHBcAAAAAIgYDfrUbcm6SMVSvSHcMbE8RYMtmLIkKrZxr56MF3pT25SYIW+FtfgAAAAAAAQErtgyYAAAAAAAiACCAlMJQHy5VJIVOOB6ZI/yxAzQHcDBOH5t47Vn18DMC+wEDBAEAAAABBcFSIQIEjUCFkjZ2Eq3xJfI7s0ysPaNwY2EPg4G8os0oaisyHCEDfrUbcm6SMVSvSHcMbE8RYMtmLIkKrZxr56MF3pT25SYhAtuW17pwSg6ZqwL14gWyf/sfTqOaS/vBYSoAKl0nrJ9FU65kdqkU1lhk15tVMROK6qg9hZIikveK/GGIrGt2qRQgb3p9sHeUAhaBwJf4kR4PvUiZIIisbJNrdqkUT/5hNznrEzupEiToLAQKMi03zvKIrGyTU4dnVrJoIgYCBI1AhZI2dhKt8SXyO7NMrD2jcGNhD4OBvKLNKGorMhwIwxWgvwAAAAAiBgLblte6cEoOmasC9eIFsn/7H06jmkv7wWEqACpdJ6yfRQjvRRwXAAAAACIGA361G3JukjFUr0h3DGxPEWDLZiyJCq2ca+ejBd6U9uUmCFvhbX4AAAAAACICArFlfWaPsqMsvdC+/3Hise+ubUHtj4n5Uz7qaI0bCfCWCBhRVloBAAAAIgICtg6ewcvt4XnF35qT+j9KoCYt4+vS8hXmOn1NsO/QppUIgryGbgEAAAAiAgOJmnB0i/XOb8ITGRA3itrYfvWx6/B8PGMiu2SYfOACFQhTR/BbAQAAAAAAACICAr+BTfGuO1VRPxE1DJoFIsH1Vu5Dk5lSullVQjCXjVlICEPuDksBAAAAIgIC+G7/TA9DNgnMf4Nup2Py3XAF8UCLmziV3Vw4Z2KsJcwIpbzhFQEAAAAiAgOpos5KhVRQaTPJTi3mk12g5sApoQNVGdOpMcMmn7C7gwieIH0+AQAAAAA=").unwrap();
        assert!(check_spend_transaction_size(&revaultd, tx));
        let tx = SpendTransaction::from_psbt_str("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").unwrap();
        assert!(!check_spend_transaction_size(&revaultd, tx));

        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
    }
}
