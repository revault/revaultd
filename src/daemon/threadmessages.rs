use crate::{bitcoind::BitcoindError, revaultd::VaultStatus};
use revault_tx::{
    bitcoin::{
        consensus::encode, util::bip32::ChildNumber, Address, Amount, OutPoint,
        Transaction as BitcoinTransaction, Txid,
    },
    transactions::{
        CancelTransaction, EmergencyTransaction, RevaultTransaction, SpendTransaction,
        UnvaultEmergencyTransaction, UnvaultTransaction,
    },
};

use std::sync::mpsc::SyncSender;

use serde::{Serialize, Serializer};

/// Outgoing to the bitcoind poller thread
#[derive(Debug)]
pub enum BitcoindMessageOut {
    Shutdown,
    SyncProgress(SyncSender<f64>),
    WalletTransaction(Txid, SyncSender<Option<WalletTransaction>>),
    BroadcastTransaction(BitcoinTransaction, SyncSender<Result<(), BitcoindError>>),
}

/// Outgoing to the signature fetcher thread
#[derive(Debug)]
pub enum SigFetcherMessageOut {
    Shutdown,
}

#[derive(Debug)]
pub struct WalletTransaction {
    pub hex: String,
    // None if unconfirmed
    pub blockheight: Option<u32>,
    pub received_time: u32,
}

#[derive(Debug, Serialize)]
pub struct VaultPresignedTransaction<T: RevaultTransaction> {
    pub psbt: T,
    #[serde(rename(serialize = "hex"), serialize_with = "serialize_option_tx_hex")]
    pub transaction: Option<BitcoinTransaction>,
}

#[derive(Debug)]
pub struct VaultPresignedTransactions {
    pub outpoint: OutPoint,
    pub unvault: VaultPresignedTransaction<UnvaultTransaction>,
    pub cancel: VaultPresignedTransaction<CancelTransaction>,
    // None if not stakeholder
    pub emergency: Option<VaultPresignedTransaction<EmergencyTransaction>>,
    pub unvault_emergency: Option<VaultPresignedTransaction<UnvaultEmergencyTransaction>>,
}

#[derive(Debug)]
pub struct VaultOnchainTransactions {
    pub outpoint: OutPoint,
    pub deposit: WalletTransaction,
    pub unvault: Option<WalletTransaction>,
    pub cancel: Option<WalletTransaction>,
    // Always None if not stakeholder
    pub emergency: Option<WalletTransaction>,
    pub unvault_emergency: Option<WalletTransaction>,
    pub spend: Option<WalletTransaction>,
}

#[derive(Debug, Serialize)]
pub struct ListSpendEntry {
    pub deposit_outpoints: Vec<OutPoint>,
    pub psbt: SpendTransaction,
}

#[derive(Debug)]
pub struct ListVaultsEntry {
    pub amount: Amount,
    pub blockheight: u32,
    pub status: VaultStatus,
    pub deposit_outpoint: OutPoint,
    pub derivation_index: ChildNumber,
    pub address: Address,
    pub received_at: u32,
    pub updated_at: u32,
}

fn serialize_tx_hex<S>(tx: &BitcoinTransaction, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let tx_hex = encode::serialize_hex(&tx);
    s.serialize_str(&tx_hex)
}

fn serialize_option_tx_hex<S>(tx: &Option<BitcoinTransaction>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Some(ref tx) = tx {
        serialize_tx_hex(tx, s)
    } else {
        s.serialize_none()
    }
}
