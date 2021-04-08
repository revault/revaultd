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

use std::{collections::BTreeMap, sync::mpsc::SyncSender};

use serde::{Serialize, Serializer};

/// Incoming from RPC server thread
#[derive(Debug)]
pub enum RpcMessageIn {
    Shutdown,
    // Network, blockheight, sync progress, number of vaults
    GetInfo(SyncSender<(String, u32, f64, usize)>),
    ListVaults(
        (Option<Vec<VaultStatus>>, Option<Vec<OutPoint>>),
        SyncSender<Vec<ListVaultsEntry>>,
    ),
    DepositAddr(Option<ChildNumber>, SyncSender<Address>),
    GetRevocationTxs(
        OutPoint,
        // None if the deposit does not exist
        // FIXME: use a Result with RpcControlError!
        SyncSender<
            Option<(
                CancelTransaction,
                EmergencyTransaction,
                UnvaultEmergencyTransaction,
            )>,
        >,
    ),
    // Returns None if the transactions could all be stored succesfully
    // FIXME: use a Result with RpcControlError!
    RevocationTxs(
        (
            OutPoint,
            CancelTransaction,
            EmergencyTransaction,
            UnvaultEmergencyTransaction,
        ),
        SyncSender<Option<String>>,
    ),
    GetUnvaultTx(
        OutPoint,
        SyncSender<Result<UnvaultTransaction, RpcControlError>>,
    ),
    UnvaultTx(
        (OutPoint, UnvaultTransaction),
        SyncSender<Result<(), RpcControlError>>,
    ),
    ListPresignedTransactions(
        Option<Vec<OutPoint>>,
        SyncSender<Result<Vec<VaultPresignedTransactions>, RpcControlError>>,
    ),
    ListOnchainTransactions(
        Option<Vec<OutPoint>>,
        SyncSender<Result<Vec<VaultOnchainTransactions>, RpcControlError>>,
    ),
    GetSpendTx(
        Vec<OutPoint>,
        BTreeMap<Address, u64>,
        u64,
        SyncSender<Result<SpendTransaction, RpcControlError>>,
    ),
    UpdateSpendTx(SpendTransaction, SyncSender<Result<(), RpcControlError>>),
    DelSpendTx(Txid, SyncSender<Result<(), RpcControlError>>),
    ListSpendTxs(SyncSender<Result<Vec<ListSpendEntry>, RpcControlError>>),
    SetSpendTx(Txid, SyncSender<Result<(), RpcControlError>>),
    Revault(OutPoint, SyncSender<Result<(), RpcControlError>>),
}

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

/// An error that occured during RPC message handling
#[derive(Debug)]
pub enum RpcControlError {
    UnknownOutpoint(OutPoint),
    // .0 is current status, .1 is required status
    InvalidStatus((VaultStatus, VaultStatus)),
    InvalidPsbt(String),
    Communication(String),
    Transaction(revault_tx::Error),
    SpendLowFeerate(u64, u64),
    SpendUnknownUnvault(Txid),
    UnknownSpend,
    AlreadySpentVault,
    // FIXME: these String are only temporary, until we remove the JSONRPC thread.
    SpendSignature(String),
    CosigningServer(String),
    UnvaultBroadcast(String),
    CancelBroadcast(String),
}

impl std::fmt::Display for RpcControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownOutpoint(ref o) => write!(f, "No vault at '{}'", o),
            Self::InvalidStatus((current, required)) => write!(
                f,
                "Invalid vault status: '{}'. Need '{}'",
                current, required
            ),
            Self::InvalidPsbt(reason) => write!(f, "Invalid PSBT: '{}'", reason),
            Self::Communication(reason) => write!(f, "Communication error: '{}'", reason),
            Self::Transaction(e) => write!(f, "Transaction management error: '{}'", e),
            Self::SpendLowFeerate(required, actual) => write!(
                f,
                "Required feerate ('{}') is significantly higher than actual feerate ('{}')",
                required, actual
            ),
            Self::SpendUnknownUnvault(txid) => {
                write!(f, "Spend transaction refers an unknown Unvault: '{}'", txid)
            }
            Self::UnknownSpend => write!(f, "Unknown Spend transaction"),
            Self::AlreadySpentVault => {
                write!(f, "Spend transaction refers to an already spent vault")
            }
            Self::SpendSignature(e) => {
                write!(f, "Error checking Spend transaction signature: '{}'", e)
            }
            Self::CosigningServer(e) => write!(f, "Error with the Cosigning Server: '{}'", e),
            Self::UnvaultBroadcast(e) => write!(f, "Broadcasting Unvault transaction(s): '{}'", e),
            Self::CancelBroadcast(e) => write!(f, "Broadcasting Cancel transaction: '{}'", e),
        }
    }
}

impl std::error::Error for RpcControlError {}

impl From<revault_tx::Error> for RpcControlError {
    fn from(e: revault_tx::Error) -> Self {
        Self::Transaction(e)
    }
}
