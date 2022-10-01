use crate::bitcoind::{interface::WalletTransaction, BitcoindError};
use revault_tx::bitcoin::{Transaction as BitcoinTransaction, Txid};

use std::sync::mpsc::{sync_channel, Sender, SyncSender};

/// Outgoing to the signature fetcher thread
#[derive(Debug)]
pub enum SigFetcherMessageOut {
    Shutdown,
}

pub trait SigFetcherThread {
    fn shutdown(&self);
}

/// Interface to the sigfetcher thread using synchronous MPSCs.
#[derive(Debug, Clone)]
pub struct SigFetcherSender(Sender<SigFetcherMessageOut>);

impl SigFetcherThread for SigFetcherSender {
    fn shutdown(&self) {
        self.0
            .send(SigFetcherMessageOut::Shutdown)
            .expect("Sending shutdown to sigfetcher thread")
    }
}

impl From<Sender<SigFetcherMessageOut>> for SigFetcherSender {
    fn from(s: Sender<SigFetcherMessageOut>) -> Self {
        SigFetcherSender(s)
    }
}

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
    CPFPTransaction(Vec<Txid>, f64, SyncSender<Result<(), BitcoindError>>),
}

/// Interface to communicate with bitcoind client thread.
pub trait BitcoindThread {
    fn wallet_tx(&self, txid: Txid) -> Result<Option<WalletTransaction>, BitcoindError>;
    fn broadcast(&self, transactions: Vec<BitcoinTransaction>) -> Result<(), BitcoindError>;
    fn shutdown(&self);
    fn sync_progress(&self) -> f64;
    fn cpfp_tx(&self, txids: Vec<Txid>, feerate: f64) -> Result<(), BitcoindError>;
}

/// Interface to the bitcoind thread using synchronous MPSCs
#[derive(Clone)]
pub struct BitcoindSender(Sender<BitcoindMessageOut>);

impl<'a> BitcoindThread for BitcoindSender {
    fn wallet_tx(&self, txid: Txid) -> Result<Option<WalletTransaction>, BitcoindError> {
        log::trace!("Sending WalletTx to bitcoind thread for {}", txid);

        let (bitrep_tx, bitrep_rx) = sync_channel(0);
        self.0
            .send(BitcoindMessageOut::WalletTransaction(txid, bitrep_tx))
            .expect("Sending to bitcoind thread");
        Ok(bitrep_rx.recv().expect("Receiving from bitcoind thread"))
    }

    fn broadcast(&self, transactions: Vec<BitcoinTransaction>) -> Result<(), BitcoindError> {
        let (bitrep_tx, bitrep_rx) = sync_channel(0);

        if !transactions.is_empty() {
            // Note: this is a batched call to bitcoind's RPC, any failure will
            // override all the results.
            self.0
                .send(BitcoindMessageOut::BroadcastTransactions(
                    transactions,
                    bitrep_tx,
                ))
                .expect("Sending to bitcoind thread");
            bitrep_rx.recv().expect("Receiving from bitcoind thread")?;
        }

        Ok(())
    }

    fn shutdown(&self) {
        self.0
            .send(BitcoindMessageOut::Shutdown)
            .expect("Sending to bitcoind thread")
    }

    fn sync_progress(&self) -> f64 {
        let (bitrep_tx, bitrep_rx) = sync_channel(0);
        self.0
            .send(BitcoindMessageOut::SyncProgress(bitrep_tx))
            .expect("Sending to bitcoind thread");

        bitrep_rx.recv().expect("Receiving from bitcoind thread")
    }

    fn cpfp_tx(&self, txids: Vec<Txid>, feerate: f64) -> Result<(), BitcoindError> {
        let (bitrep_tx, bitrep_rx) = sync_channel(0);
        self.0
            .send(BitcoindMessageOut::CPFPTransaction(
                txids, feerate, bitrep_tx,
            ))
            .expect("Sending to bitcoind thread");
        bitrep_rx.recv().expect("Receiving from bitcoind thread")?;

        Ok(())
    }
}

impl From<Sender<BitcoindMessageOut>> for BitcoindSender {
    fn from(s: Sender<BitcoindMessageOut>) -> Self {
        BitcoindSender(s)
    }
}
