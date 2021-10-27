use crate::daemon::bitcoind::BitcoindError;
use revault_tx::bitcoin::{Transaction as BitcoinTransaction, Txid};

use std::sync::mpsc::{sync_channel, Sender, SyncSender};

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

/// Interface to communicate with bitcoind client thread.
pub trait BitcoindThread {
    fn wallet_tx(&self, txid: Txid) -> Result<Option<WalletTransaction>, BitcoindError>;
    fn broadcast(&self, transactions: Vec<BitcoinTransaction>) -> Result<(), BitcoindError>;
    fn shutdown(&self);
    fn sync_progress(&self) -> f64;
}

/// Interface to the bitcoind thread using synchronous MPSCs
#[derive(Clone)]
pub struct BitcoindSender<'a>(&'a Sender<BitcoindMessageOut>);

impl<'a> BitcoindThread for BitcoindSender<'a> {
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
                    bitrep_tx.clone(),
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

        bitrep_rx
            .recv()
            .expect("Receiving from bitcoind thread")
    }
}

impl<'a> From<&'a Sender<BitcoindMessageOut>> for BitcoindSender<'a> {
    fn from(s: &'a Sender<BitcoindMessageOut>) -> Self {
        BitcoindSender(s)
    }
}
