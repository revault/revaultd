pub mod interface;
pub mod poller;
pub mod utils;

use crate::config::BitcoindConfig;
use crate::{database::DatabaseError, revaultd::RevaultD, threadmessages::BitcoindMessageOut};
use interface::{BitcoinD, WalletTransaction};
use poller::poller_main;
use revault_tx::bitcoin::{Network, Txid};

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Receiver,
        Arc, RwLock,
    },
    thread,
    time::Duration,
};

use jsonrpc::{
    error::{Error, RpcError},
    simple_http,
};

/// An error happened in the bitcoind-manager thread
#[derive(Debug)]
pub enum BitcoindError {
    /// It can be related to us..
    Custom(String),
    /// Or directly to bitcoind's RPC server
    Server(Error),
    /// They replied to a batch request omitting some responses
    BatchMissingResponse,
    RevaultTx(revault_tx::Error),
}

impl BitcoindError {
    /// Is bitcoind just starting ?
    pub fn is_warming_up(&self) -> bool {
        match self {
            // https://github.com/bitcoin/bitcoin/blob/dca80ffb45fcc8e6eedb6dc481d500dedab4248b/src/rpc/protocol.h#L49
            BitcoindError::Server(Error::Rpc(RpcError { code, .. })) => *code == -28,
            _ => false,
        }
    }
}

impl std::fmt::Display for BitcoindError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BitcoindError::Custom(ref s) => write!(f, "Bitcoind manager error: {}", s),
            BitcoindError::Server(ref e) => write!(f, "Bitcoind server error: {}", e),
            BitcoindError::BatchMissingResponse => write!(
                f,
                "Bitcoind server replied without enough responses to our batched request"
            ),
            BitcoindError::RevaultTx(ref s) => write!(f, "Bitcoind manager error: {}", s),
        }
    }
}

impl std::error::Error for BitcoindError {}

impl From<DatabaseError> for BitcoindError {
    fn from(e: DatabaseError) -> Self {
        Self::Custom(format!("Database error in bitcoind thread: {}", e))
    }
}

impl From<simple_http::Error> for BitcoindError {
    fn from(e: simple_http::Error) -> Self {
        Self::Server(Error::Transport(Box::new(e)))
    }
}

impl From<revault_tx::Error> for BitcoindError {
    fn from(e: revault_tx::Error) -> Self {
        Self::RevaultTx(e)
    }
}

fn check_bitcoind_network(
    bitcoind: &BitcoinD,
    config_network: &Network,
) -> Result<(), BitcoindError> {
    let chaininfo = bitcoind.getblockchaininfo()?;
    let chain = chaininfo
        .get("chain")
        .and_then(|c| c.as_str())
        .ok_or_else(|| {
            BitcoindError::Custom("No valid 'chain' in getblockchaininfo response?".to_owned())
        })?;
    let bip70_net = match config_network {
        Network::Bitcoin => "main",
        Network::Testnet => "test",
        Network::Regtest => "regtest",
        Network::Signet => "signet",
    };

    if !bip70_net.eq(chain) {
        return Err(BitcoindError::Custom(format!(
            "Wrong network, bitcoind is on '{}' but our config says '{}' ({})",
            chain, bip70_net, config_network
        )));
    }

    Ok(())
}

/// Some sanity checks to be done at startup to make sure our bitcoind isn't going to fail under
/// our feet for a legitimate reason.
fn bitcoind_sanity_checks(
    bitcoind: &BitcoinD,
    bitcoind_config: &BitcoindConfig,
) -> Result<(), BitcoindError> {
    check_bitcoind_network(bitcoind, &bitcoind_config.network)
}

/// Connects to and sanity checks bitcoind.
pub fn start_bitcoind(revaultd: &mut RevaultD) -> Result<BitcoinD, BitcoindError> {
    let bitcoind = BitcoinD::new(
        &revaultd.bitcoind_config,
        revaultd
            .watchonly_wallet_file()
            .expect("Wallet id is set at startup in setup_db()"),
        revaultd
            .cpfp_wallet_file()
            .expect("Wallet id is set at startup in setup_db()"),
    )
    .map_err(|e| {
        BitcoindError::Custom(format!("Could not connect to bitcoind: {}", e.to_string()))
    })?;

    while let Err(e) = bitcoind_sanity_checks(&bitcoind, &revaultd.bitcoind_config) {
        if e.is_warming_up() {
            log::info!("Bitcoind is warming up. Waiting for it to be back up.");
            thread::sleep(Duration::from_secs(3))
        } else {
            return Err(e);
        }
    }

    Ok(bitcoind)
}

/// Check bitcoind version at startup
pub fn bitcoind_version_check() -> Result< i32 , &'static str> {
    // Set minimum supported bitcoind version here:
    let min_supported_bitcoind = "220000";
    // Extracts output of "bitcoin-cli getnetworkinfo" from user's cli and stores in value.
    use std::process::Command;
    let value = Command::new("bitcoin-cli").arg("getnetworkinfo").output();
    let getnetworkinfo_data = value.unwrap();
    let list_length = getnetworkinfo_data.stdout.len();
    let mut version_ascii : Vec<u8> = Vec::new(); 
    let mut version_flag = 0;
    // Extracts and stores version from getnetworkinfo output and stores in bitcoin_version as a string.
    for i in 0..list_length {
        let colon_ascii = 58;
        if getnetworkinfo_data.stdout[i] == colon_ascii {
            version_flag=1;
        }
        let comma_ascii = 44;
        if getnetworkinfo_data.stdout[i] == comma_ascii {
            break;
        }
        if version_flag == 1 {
           version_ascii.push(getnetworkinfo_data.stdout[i]);
        }
    }
    let mut bitcoind_version = String::new();
    let mut pos = 0;
  
    for i in version_ascii {
      if pos>=2 {
          let ival:u8 = i;
          let str_ival = (ival-48).to_string();
          bitcoind_version.push_str(&str_ival);
      }
      pos+=1; 
    }
  
    let bitcoind_version_i32 = bitcoind_version.trim().parse::<i32>();
    let min_supported_bitcoind_i32 = min_supported_bitcoind.trim().parse::<i32>();
  
    // We are checking if bitcoind's version is greater than or equal to the minimum supported version of revaultd
    match (bitcoind_version_i32, min_supported_bitcoind_i32) {
      (Ok(bitcoind_version_i32), Ok(min_supported_bitcoind_i32)) if bitcoind_version_i32 >= min_supported_bitcoind_i32 => Ok(bitcoind_version_i32),
      _ => Err("Your bitcoind version is not compatible with revaultd! Please upgrade to the latest version of bitcoind."),
  }
  }

fn wallet_transaction(bitcoind: &BitcoinD, txid: Txid) -> Option<WalletTransaction> {
    bitcoind
        .get_wallet_transaction(&txid)
        .map_err(|res| {
            log::trace!(
                "Got '{:?}' from bitcoind when requesting wallet transaction '{}'",
                res,
                txid
            );
            res
        })
        .ok()
}

/// The bitcoind event loop.
/// Listens for bitcoind requests (wallet / chain) and poll bitcoind every 30 seconds,
/// updating our state accordingly.
pub fn bitcoind_main_loop(
    rx: Receiver<BitcoindMessageOut>,
    revaultd: Arc<RwLock<RevaultD>>,
    bitcoind: BitcoinD,
) -> Result<(), BitcoindError> {
    let bitcoind = Arc::new(RwLock::new(bitcoind));
    // The verification progress announced by bitcoind *at startup* thus won't be updated
    // after startup check. Should be *exactly* 1.0 when synced, but hey, floats so we are
    // careful.
    let sync_progress = Arc::new(RwLock::new(0.0f64));
    // Used to shutdown the poller thread
    let shutdown = Arc::new(AtomicBool::new(false));

    // We use a thread to 1) wait for bitcoind to be synced 2) poll listunspent
    let poller_thread = std::thread::spawn({
        let _bitcoind = bitcoind.clone();
        let _sync_progress = sync_progress.clone();
        let _shutdown = shutdown.clone();
        move || poller_main(revaultd, _bitcoind, _sync_progress, _shutdown)
    });

    for msg in rx {
        match msg {
            BitcoindMessageOut::Shutdown => {
                log::info!("Bitcoind received shutdown from main. Exiting.");
                shutdown.store(true, Ordering::Relaxed);
                poller_thread
                    .join()
                    .expect("Joining bitcoind poller thread")
                    .expect("Failed to join bitcoind poller thread");
                return Ok(());
            }
            BitcoindMessageOut::SyncProgress(resp_tx) => {
                resp_tx.send(*sync_progress.read().unwrap()).map_err(|e| {
                    BitcoindError::Custom(format!(
                        "Sending synchronization progress to main thread: {}",
                        e
                    ))
                })?;
            }
            BitcoindMessageOut::WalletTransaction(txid, resp_tx) => {
                log::trace!("Received 'wallettransaction' from main thread");
                // FIXME: what if bitcoind isn't synced?
                resp_tx
                    .send(wallet_transaction(&bitcoind.read().unwrap(), txid))
                    .map_err(|e| {
                        BitcoindError::Custom(format!(
                            "Sending wallet transaction to main thread: {}",
                            e
                        ))
                    })?;
            }
            BitcoindMessageOut::BroadcastTransactions(txs, resp_tx) => {
                log::trace!("Received 'broadcastransactions' from main thread");
                resp_tx
                    .send(bitcoind.read().unwrap().broadcast_transactions(&txs))
                    .map_err(|e| {
                        BitcoindError::Custom(format!(
                            "Sending transactions broadcast result to main thread: {}",
                            e
                        ))
                    })?;
            }
        }
    }

    Ok(())
}
