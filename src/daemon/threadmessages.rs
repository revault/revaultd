use crate::daemon::bitcoind::BitcoindError;
use revault_tx::bitcoin::{Transaction as BitcoinTransaction, Txid};

use std::sync::mpsc::{sync_channel, RecvError, SendError, Sender, SyncSender};

/// Outgoing to the bitcoind poller thread
#[derive(Debug)]
pub enum BitcoindMessageOut {
    Shutdown,
    SyncProgress(SyncSender<f64>),
    WalletTransaction(Txid, SyncSender<Option<WalletTransaction>>),
    BroadcastTransactions(
        Vec<BitcoinTransaction>,
        SyncSender<Result<(), BitcoindError>>,
    ),
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

/// BitcoindThread is the interface trait used to communicate with bitcoind client thread.
pub trait BitcoindThread {
    fn wallet_tx(&self, txid: Txid) -> Result<Option<WalletTransaction>, BitcoindThreadError>;
    fn broadcast(&self, transactions: Vec<BitcoinTransaction>) -> Result<(), BitcoindThreadError>;
    fn shutdown(&self) -> Result<(), BitcoindThreadError>;
    fn sync_progress(&self) -> Result<f64, BitcoindThreadError>;
}

/// BitcoindSender is a wrapper around a mpsc Sender
#[derive(Clone)]
pub struct BitcoindSender<'a>(&'a Sender<BitcoindMessageOut>);

impl<'a> BitcoindThread for BitcoindSender<'a> {
    fn wallet_tx(&self, txid: Txid) -> Result<Option<WalletTransaction>, BitcoindThreadError> {
        log::trace!("Sending WalletTx to bitcoind thread for {}", txid);

        let (bitrep_tx, bitrep_rx) = sync_channel(0);
        self.0
            .send(BitcoindMessageOut::WalletTransaction(txid, bitrep_tx))?;
        bitrep_rx.recv().map_err(|e| e.into())
    }

    fn broadcast(&self, transactions: Vec<BitcoinTransaction>) -> Result<(), BitcoindThreadError> {
        let (bitrep_tx, bitrep_rx) = sync_channel(0);

        if !transactions.is_empty() {
            // Note: this is a batched call to bitcoind's RPC, any failure will
            // override all the results.
            self.0.send(BitcoindMessageOut::BroadcastTransactions(
                transactions,
                bitrep_tx.clone(),
            ))?;
            bitrep_rx.recv()??;
        }

        Ok(())
    }

    fn shutdown(&self) -> Result<(), BitcoindThreadError> {
        self.0
            .send(BitcoindMessageOut::Shutdown)
            .map_err(|e| e.into())
    }

    fn sync_progress(&self) -> Result<f64, BitcoindThreadError> {
        let (bitrep_tx, bitrep_rx) = sync_channel(0);
        self.0
            .send(BitcoindMessageOut::SyncProgress(bitrep_tx))
            .map_err(|e| BitcoindThreadError::from(e))?;

        bitrep_rx.recv().map_err(|e| e.into())
    }
}

impl<'a> From<&'a Sender<BitcoindMessageOut>> for BitcoindSender<'a> {
    fn from(s: &'a Sender<BitcoindMessageOut>) -> Self {
        BitcoindSender(s)
    }
}

pub enum BitcoindThreadError {
    Bitcoind(BitcoindError),
    ThreadCommunication(String),
}

impl std::fmt::Display for BitcoindThreadError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Bitcoind(ref e) => write!(f, "Bitcoind error: '{}'", e),
            Self::ThreadCommunication(ref e) => write!(f, "Thread communication error: '{}'", e),
        }
    }
}

impl From<BitcoindError> for BitcoindThreadError {
    fn from(e: BitcoindError) -> Self {
        Self::Bitcoind(e)
    }
}

impl<T> From<SendError<T>> for BitcoindThreadError {
    fn from(e: SendError<T>) -> Self {
        Self::ThreadCommunication(format!("Sending to thread: '{}'", e))
    }
}

impl From<RecvError> for BitcoindThreadError {
    fn from(e: RecvError) -> Self {
        Self::ThreadCommunication(format!("Receiving from thread: '{}'", e))
    }
}
