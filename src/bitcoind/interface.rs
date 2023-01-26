use crate::config::BitcoindConfig;
use crate::{bitcoind::BitcoindError, revaultd::BlockchainTip};
use revault_tx::bitcoin::{
    consensus::encode, util::bip32::ChildNumber, util::psbt::PartiallySignedTransaction as Psbt,
    Address, Amount, BlockHash, OutPoint, Script, Transaction, TxOut, Txid,
};

use std::{
    collections::{HashMap, HashSet},
    fs,
    str::FromStr,
    time::Duration,
};

use jsonrpc::{
    arg,
    client::Client,
    simple_http::{Error as HttpError, SimpleHttpTransport},
};

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

// If bitcoind takes more than 3 minutes to answer one of our queries, fail.
const RPC_SOCKET_TIMEOUT: u64 = 180;

pub struct BitcoinD {
    node_client: Client,
    watchonly_client: Client,
    cpfp_client: Client,

    /// How many times the client will try again to send a request to bitcoind upon failure
    retries: usize,
}

macro_rules! params {
    ($($param:expr),* $(,)?) => {
        [
            $(
                arg($param),
            )*
        ]
    };
}

impl BitcoinD {
    pub fn new(
        config: &BitcoindConfig,
        watchonly_wallet_path: String,
        cpfp_wallet_path: String,
    ) -> Result<BitcoinD, BitcoindError> {
        let cookie_string = fs::read_to_string(&config.cookie_path).map_err(|e| {
            BitcoindError::Custom(format!("Reading cookie file: {}", e.to_string()))
        })?;

        let node_client = Client::with_transport(
            SimpleHttpTransport::builder()
                .url(&config.addr.to_string())
                .map_err(BitcoindError::from)?
                .timeout(Duration::from_secs(RPC_SOCKET_TIMEOUT))
                .cookie_auth(cookie_string.clone())
                .build(),
        );

        let watchonly_url = format!("http://{}/wallet/{}", config.addr, watchonly_wallet_path);
        let watchonly_client = Client::with_transport(
            SimpleHttpTransport::builder()
                .url(&watchonly_url)
                .map_err(BitcoindError::from)?
                .timeout(Duration::from_secs(RPC_SOCKET_TIMEOUT))
                .cookie_auth(cookie_string.clone())
                .build(),
        );

        let cpfp_url = format!("http://{}/wallet/{}", config.addr, cpfp_wallet_path);
        let cpfp_client = Client::with_transport(
            SimpleHttpTransport::builder()
                .url(&cpfp_url)
                .map_err(BitcoindError::from)?
                .timeout(Duration::from_secs(RPC_SOCKET_TIMEOUT))
                .cookie_auth(cookie_string)
                .build(),
        );

        Ok(BitcoinD {
            node_client,
            watchonly_client,
            cpfp_client,
            retries: 0,
        })
    }

    /// Set the retry limit (number of times we'll retry a request to bitcoind upon specific failures).
    pub fn with_retry_limit(mut self, retry_limit: usize) -> Self {
        self.retries = retry_limit;
        self
    }

    /// Wrapper to retry a request sent to bitcoind upon IO failure
    /// according to the configured number of retries.
    fn retry<T, R: Fn() -> Result<T, BitcoindError>>(
        &self,
        request: R,
    ) -> Result<T, BitcoindError> {
        let mut error: Option<BitcoindError> = None;
        for i in 0..self.retries + 1 {
            match request() {
                Ok(res) => return Ok(res),
                Err(e) => {
                    if e.is_warming_up() {
                        error = Some(e)
                    } else if let BitcoindError::Server(jsonrpc::Error::Transport(ref err)) = e {
                        match err.downcast_ref::<HttpError>() {
                            Some(HttpError::Timeout)
                            | Some(HttpError::SocketError(_))
                            | Some(HttpError::HttpErrorCode(503)) => {
                                std::thread::sleep(Duration::from_secs(1));
                                log::debug!("Retrying RPC request to bitcoind: attempt #{}", i);
                                error = Some(e);
                            }
                            _ => return Err(e),
                        }
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Err(BitcoindError::Custom(format!(
            "Retry limit reached: {:?}",
            error
        )))
    }

    fn make_request<'a, 'b>(
        &self,
        client: &Client,
        method: &'a str,
        params: &'b [Box<serde_json::value::RawValue>],
    ) -> Result<Json, BitcoindError> {
        self.retry(|| {
            let req = client.build_request(method, params);
            log::trace!("Sending to bitcoind: {:#?}", req);
            match client.send_request(req) {
                Ok(resp) => {
                    let res = resp.result().map_err(BitcoindError::Server)?;
                    log::trace!("Got from bitcoind: {:#?}", res);

                    return Ok(res);
                }
                Err(e) => Err(BitcoindError::Server(e)),
            }
        })
    }

    fn make_requests(
        &self,
        client: &Client,
        reqs: &[jsonrpc::Request],
    ) -> Result<Vec<Json>, BitcoindError> {
        self.retry(|| {
            log::trace!("Sending to bitcoind: {:#?}", reqs);
            match client.send_batch(reqs) {
                Ok(resp) => {
                    let res = resp
                        .into_iter()
                        .flatten()
                        .map(|resp| resp.result())
                        .collect::<Result<Vec<Json>, jsonrpc::Error>>()
                        .map_err(BitcoindError::Server)?;
                    log::trace!("Got from bitcoind: {:#?}", res);

                    // FIXME: why is rust-jsonrpc even returning a Vec of Option in the first
                    // place??
                    if res.len() != reqs.len() {
                        return Err(BitcoindError::BatchMissingResponse);
                    }

                    return Ok(res);
                }
                Err(e) => Err(BitcoindError::Server(e)),
            }
        })
    }

    fn make_node_request(
        &self,
        method: &str,
        params: &[Box<serde_json::value::RawValue>],
    ) -> Result<Json, BitcoindError> {
        self.make_request(&self.node_client, method, params)
    }

    fn make_watchonly_request(
        &self,
        method: &str,
        params: &[Box<serde_json::value::RawValue>],
    ) -> Result<Json, BitcoindError> {
        self.make_request(&self.watchonly_client, method, params)
    }

    fn make_node_requests(
        &self,
        requests: &[jsonrpc::Request],
    ) -> Result<Vec<Json>, BitcoindError> {
        self.make_requests(&self.node_client, requests)
    }

    fn make_cpfp_request(
        &self,
        method: &str,
        params: &[Box<serde_json::value::RawValue>],
    ) -> Result<Json, BitcoindError> {
        self.make_request(&self.cpfp_client, method, params)
    }

    pub fn getnetworkinfo(&self) -> Result<Json, BitcoindError> {
        self.make_node_request("getnetworkinfo", &[])
    }

    pub fn getblockchaininfo(&self) -> Result<Json, BitcoindError> {
        self.make_node_request("getblockchaininfo", &[])
    }

    pub fn getblockhash(&self, height: u32) -> Result<BlockHash, BitcoindError> {
        Ok(BlockHash::from_str(
            self.make_node_request("getblockhash", &params!(height))?
                .as_str()
                .expect("API break, 'getblockhash' didn't return a string."),
        )
        .expect("Invalid blockhash given by 'getblockhash'"))
    }

    pub fn get_tip(&self) -> Result<BlockchainTip, BitcoindError> {
        let json_height = self.make_node_request("getblockcount", &[])?;
        let height = json_height
            .as_u64()
            .expect("API break, 'getblockcount' didn't return an u64.") as u32;
        let hash = self.getblockhash(height)?;

        Ok(BlockchainTip { height, hash })
    }

    pub fn synchronization_info(&self) -> Result<SyncInfo, BitcoindError> {
        let chaininfo = self.make_node_request("getblockchaininfo", &[])?;
        Ok(SyncInfo {
            headers: chaininfo
                .get("headers")
                .and_then(|h| h.as_u64())
                .expect("No valid 'headers' in getblockchaininfo response?"),
            blocks: chaininfo
                .get("blocks")
                .and_then(|b| b.as_u64())
                .expect("No valid 'blocks' in getblockchaininfo response?"),
            ibd: chaininfo
                .get("initialblockdownload")
                .and_then(|i| i.as_bool())
                .expect("No valid 'initialblockdownload' in getblockchaininfo response?"),
            progress: chaininfo
                .get("verificationprogress")
                .and_then(|i| i.as_f64())
                .expect("No valid 'initialblockdownload' in getblockchaininfo response?"),
        })
    }

    pub fn createwallet_startup(
        &self,
        wallet_path: String,
        watchonly: bool,
    ) -> Result<(), BitcoindError> {
        let res = self.make_node_request(
            "createwallet",
            &params!(
                Json::String(wallet_path),
                Json::Bool(watchonly),        // watchonly
                Json::Bool(true),             // blank
                Json::String("".to_string()), // passphrase,
                Json::Bool(false),            // avoid_reuse
                Json::Bool(true),             // descriptors
                Json::Bool(true),             // load_on_startup
            ),
        )?;

        if res.get("name").is_some() {
            return Ok(());
        }

        Err(BitcoindError::Custom(format!(
            "Error creating wallet: '{:?}'",
            res.get("warning")
        )))
    }

    pub fn listwallets(&self) -> Result<Vec<String>, BitcoindError> {
        Ok(self
            .make_node_request("listwallets", &[])?
            .as_array()
            .expect("API break, 'listwallets' didn't return an array.")
            .iter()
            .map(|json_str| {
                json_str
                    .as_str()
                    .expect("API break: 'listwallets' contains a non-string value")
                    .to_string()
            })
            .collect())
    }

    pub fn loadwallet_startup(&self, wallet_path: String) -> Result<(), BitcoindError> {
        let res = self.make_node_request(
            "loadwallet",
            &params!(
                Json::String(wallet_path),
                Json::Bool(true), // load_on_startup
            ),
        )?;

        if res.get("name").is_some() {
            return Ok(());
        }

        Err(BitcoindError::Custom(format!(
            "Error loading wallet: '{:?}'",
            res.get("warning")
        )))
    }

    pub fn unloadwallet(&self, wallet_path: String) -> Result<(), BitcoindError> {
        let res = self.make_node_request("unloadwallet", &params!(Json::String(wallet_path),))?;

        let warning = res
            .get("warning")
            .map(|w| w.as_str())
            .flatten()
            .ok_or_else(|| {
                BitcoindError::Custom(
                    "No or invalid 'warning' in 'unloadwallet' result".to_string(),
                )
            })?;
        if !warning.is_empty() {
            Err(BitcoindError::Custom(warning.to_string()))
        } else {
            Ok(())
        }
    }

    fn import_descriptors(
        &self,
        client: &Client,
        descriptors: Vec<String>,
        timestamp: Option<u32>,
        active: bool,
    ) -> Result<(), BitcoindError> {
        if timestamp.is_some() {
            log::debug!("Not a fresh wallet, rescan *may* take some time.");
        }

        let all_descriptors: Vec<Json> = descriptors
            .into_iter()
            .map(|desc| {
                let mut desc_map = serde_json::Map::with_capacity(3);
                desc_map.insert("desc".to_string(), Json::String(desc));
                // We set to "now" the timestamp for fresh wallet, as otherwise bitcoind
                // will rescan the last few blocks for each of them.
                desc_map.insert(
                    "timestamp".to_string(),
                    timestamp
                        .map(serde_json::Number::from)
                        .map(Json::Number)
                        .unwrap_or_else(|| Json::String("now".to_string())),
                );
                desc_map.insert("active".to_string(), Json::Bool(active));

                Json::Object(desc_map)
            })
            .collect();

        let res = self.make_request(
            client,
            "importdescriptors",
            &params!(Json::Array(all_descriptors)),
        )?;
        let all_succeeded = res
            .as_array()
            .map(|results| {
                results
                    .iter()
                    .all(|res| res.get("success") == Some(&Json::Bool(true)))
            })
            .unwrap_or(false);
        if all_succeeded {
            return Ok(());
        }

        Err(BitcoindError::Custom(format!(
            "Error returned from 'importdescriptor': {:?}",
            res
        )))
    }

    /// Import the deposit and Unvault descriptors, when at startup.
    pub fn startup_import_descriptors(
        &self,
        descriptors: [String; 2],
        timestamp: Option<u32>,
    ) -> Result<(), BitcoindError> {
        self.import_descriptors(
            &self.watchonly_client,
            descriptors.to_vec(),
            timestamp,
            false,
        )
    }

    pub fn import_cpfp_descriptor(
        &self,
        descriptor: String,
        timestamp: Option<u32>,
    ) -> Result<(), BitcoindError> {
        self.import_descriptors(&self.cpfp_client, vec![descriptor], timestamp, true)
    }

    pub fn list_unspent_cpfp(&self) -> Result<Vec<ListUnspentEntry>, BitcoindError> {
        // For some weird reason, listunspent with the cpfp wallet doesn't return the label
        // (maybe because we only have one descriptor anyways?), so we pass `None` as a label
        self.list_unspent(&self.cpfp_client, None, None)
    }

    fn list_unspent(
        &self,
        client: &Client,
        min_amount: Option<u64>,
        label: Option<&'static str>,
    ) -> Result<Vec<ListUnspentEntry>, BitcoindError> {
        let req = if let Some(min_amount) = min_amount {
            self.make_request(
                client,
                "listunspent",
                &params!(
                    Json::Number(0.into()),       // minconf
                    Json::Number(9999999.into()), // maxconf (default)
                    Json::Array(vec![]),          // addresses (default)
                    Json::Bool(true),             // include_unsafe (default)
                    serde_json::json!({
                        "minimumAmount": min_amount,
                    }), // query_options
                ),
            )
        } else {
            self.make_request(
                client,
                "listunspent",
                &params!(
                    Json::Number(0.into()), // minconf
                ),
            )
        };

        req.map(|r| {
            r.as_array()
                .expect("API break, 'listunspent' didn't return an array.")
                .iter()
                .filter_map(|utxo| {
                    let utxo = ListUnspentEntry::from(utxo);
                    if label.or_else(|| utxo.label.as_deref()) == utxo.label.as_deref() {
                        Some(utxo)
                    } else {
                        None
                    }
                })
                .collect()
        })
    }

    fn list_since_block(
        &self,
        tip: &BlockchainTip,
        descriptor: Option<String>,
    ) -> Result<Vec<ListSinceBlockTransaction>, BitcoindError> {
        let req = if tip.height == 0 {
            self.make_request(&self.watchonly_client, "listsinceblock", &params!())?
        } else {
            self.make_request(
                &self.watchonly_client,
                "listsinceblock",
                &params!(
                    Json::String(tip.hash.to_string()),
                    Json::Number(1.into()),
                    Json::Bool(true),
                    Json::Bool(true),
                    Json::Bool(true)
                ),
            )?
        };
        Ok(req
            .get("transactions")
            .expect("API break, listsinceblock doesn't have a transaction field")
            .as_array()
            .expect("API break, listsinceblock transactions is not an array")
            .iter()
            .filter_map(|t| {
                let t = ListSinceBlockTransaction::from(t);
                match descriptor {
                    None => Some(t),
                    Some(ref desc) => {
                        if t.wallet_descs.contains(desc) {
                            Some(t)
                        } else {
                            None
                        }
                    }
                }
            })
            .collect())
    }

    fn list_deposits_since_block(
        &self,
        tip: &BlockchainTip,
        deposit_desc: String,
    ) -> Result<Vec<ListSinceBlockTransaction>, BitcoindError> {
        self.list_since_block(tip, Some(deposit_desc))
    }

    /// Repeatedly called by our main loop to stay in sync with bitcoind.
    /// We take the currently known deposit utxos, and return the new, confirmed and spent ones.
    pub fn sync_deposits(
        &self,
        deposits_utxos: &HashMap<OutPoint, UtxoInfo>,
        db_tip: &BlockchainTip,
        min_conf: u32,
        deposit_desc: String,
    ) -> Result<DepositsState, BitcoindError> {
        let (mut new_unconf, mut new_conf, mut new_spent) =
            (HashMap::new(), HashMap::new(), HashMap::new());

        // First, we check the existing deposits to see whether the unconfirmed got confirmed or if
        // any was spent.
        // FIXME: batch those calls to gettxout
        for (outpoint, info) in deposits_utxos {
            let confirmations = self.get_unspent_outpoint_confirmations(&outpoint)?;
            if let Some(confirmations) = confirmations {
                if !info.is_confirmed && confirmations >= min_conf as i32 {
                    new_conf.insert(
                        *outpoint,
                        UtxoInfo {
                            txo: info.txo.clone(),
                            is_confirmed: true,
                        },
                    );
                }
            } else {
                // Only a 'funded' vault can get to 'unvaulting'.
                if info.is_confirmed {
                    // We've seen it unspent and now it's not here anymore: it's spent.
                    new_spent.insert(*outpoint, info.clone());
                } else {
                    let confs = self
                        .get_wallet_transaction(&outpoint.txid)?
                        .blockheight
                        .map(|bh| db_tip.height.checked_add(1).unwrap().checked_sub(bh))
                        .flatten();
                    if confs >= Some(min_conf) {
                        new_conf.insert(
                            *outpoint,
                            UtxoInfo {
                                txo: info.txo.clone(),
                                is_confirmed: true,
                            },
                        );
                    }
                }
            }
        }

        // Second, we scan for new ones.
        let utxos = self.list_deposits_since_block(db_tip, deposit_desc)?;
        for utxo in utxos {
            if utxo.is_receive && deposits_utxos.get(&utxo.outpoint).is_none() {
                new_unconf.insert(
                    utxo.outpoint,
                    UtxoInfo {
                        txo: utxo.txo,
                        // All new utxos are first marked as unconfirmed. This allows for a
                        // proper state transition.
                        is_confirmed: false,
                    },
                );
            }
        }

        Ok(DepositsState {
            new_unconf,
            new_conf,
            new_spent,
        })
    }

    /// Repeatedly called by our main loop to stay in sync with bitcoind.
    /// We take the currently known unvault utxos, and return both the confirmed and spent ones.
    pub fn sync_unvaults(
        &self,
        unvault_utxos: &HashMap<OutPoint, UtxoInfo>,
    ) -> Result<UnvaultsState, BitcoindError> {
        let (mut new_conf, mut new_spent) = (Vec::new(), Vec::new());

        // NOTE: if rescanning, and an Unvault was created, confirmed and then spent while we were
        // not actively watching, it will be marked as 'spent' immediately. It is necessary to keep
        // the smooth 'unvaulting' -> 'canceling'/'spending' flow, and we'll check for it when
        // marking as 'canceled'/'spent' (which implies the Unvault was confirmed, too).
        // FIXME: batch those calls to gettxout
        for (outpoint, utxo) in unvault_utxos {
            if let Some(conf) = self.get_unspent_outpoint_confirmations(&outpoint)? {
                if conf > 0 && !utxo.is_confirmed {
                    new_conf.push(*outpoint);
                }
            } else {
                new_spent.push(*outpoint);
            }
        }

        Ok(UnvaultsState {
            new_conf,
            new_spent,
        })
    }

    /// Get the raw transaction as hex, the blockheight it was included in if
    /// it's confirmed, as well as the reception time.
    pub fn get_wallet_transaction(&self, txid: &Txid) -> Result<WalletTransaction, BitcoindError> {
        let res = self
            .make_watchonly_request("gettransaction", &params!(Json::String(txid.to_string())))?;
        let tx_hex = res
            .get("hex")
            .expect(&format!(
                "API break: no 'hex' in 'gettransaction' result (txid: {})",
                txid
            ))
            .as_str()
            .expect("API break: 'hex' is not a string ????")
            .to_string();
        let blockheight = res.get("blockheight").map(|bh| bh.as_u64().unwrap() as u32);
        let blocktime = res.get("blocktime").map(|bh| bh.as_u64().unwrap() as u32);
        let received_time = res
            .get("timereceived")
            .expect(&format!(
                "API break: no 'time_received' in 'gettransaction' result (txid: {})",
                txid
            ))
            .as_u64()
            .expect(&format!(
                "API break: invalid 'time_received' in 'gettransaction' result (txid: {})",
                txid
            )) as u32;

        Ok(WalletTransaction {
            hex: tx_hex,
            blockheight,
            blocktime,
            received_time,
        })
    }

    /// Make bitcoind:
    /// 1. Add information to the PSBT inputs
    /// 2. Sign the PSBT inputs it can
    /// 3. Finalize the PSBT if it is complete
    pub fn sign_psbt(&self, psbt: &Psbt) -> Result<(bool, Psbt), BitcoindError> {
        let res = self.make_cpfp_request(
            "walletprocesspsbt",
            &params!(
                Json::String(base64::encode(&encode::serialize(psbt))),
                Json::Bool(true),
                Json::String("ALL".to_string()),
            ),
        )?;
        let complete = res
            .get("complete")
            .expect("API break: no 'complete' in 'walletprocesspsbt' result")
            .as_bool()
            .expect("API break: invalid 'complete' in 'walletprocesspsbt' result");
        let psbt = res
            .get("psbt")
            .expect("API break: no 'psbt' in 'walletprocesspsbt' result")
            .as_str()
            .expect("API break: invalid 'psbt' in 'walletprocesspsbt' result")
            .to_string();
        let psbt =
            encode::deserialize(&base64::decode(psbt).expect("bitcoind returned invalid base64"))
                .expect("bitcoind returned an invalid PSBT.");
        Ok((complete, psbt))
    }

    /// Broadcast a transaction with 'sendrawtransaction', discarding the returned txid
    pub fn broadcast_transaction(&self, tx: &Transaction) -> Result<(), BitcoindError> {
        let tx_hex = encode::serialize_hex(tx);
        log::debug!("Broadcasting '{}'", tx_hex);
        self.make_watchonly_request("sendrawtransaction", &params!(Json::String(tx_hex)))
            .map(|_| ())
    }

    /// Broadcast a batch of transactions with 'sendrawtransaction'
    pub fn broadcast_transactions(&self, txs: &[Transaction]) -> Result<(), BitcoindError> {
        let txs_hex: Vec<[Box<serde_json::value::RawValue>; 1]> = txs
            .iter()
            .map(|tx| params!(Json::String(encode::serialize_hex(tx))))
            .collect();
        log::debug!("Batch-broadcasting {:?}", txs_hex);
        let reqs: Vec<jsonrpc::Request> = txs_hex
            .iter()
            .map(|hex| {
                self.node_client
                    .build_request("sendrawtransaction", hex.as_ref())
            })
            .collect();
        self.make_node_requests(&reqs).map(|_| ())
    }

    /// Broadcast a transaction that is already part of the wallet
    pub fn rebroadcast_wallet_tx(&self, txid: &Txid) -> Result<(), BitcoindError> {
        let tx = self.get_wallet_transaction(txid)?;
        log::debug!("Re-broadcasting '{}'", tx.hex);
        self.make_watchonly_request("sendrawtransaction", &params!(Json::String(tx.hex)))
            .map(|_| ())
    }

    /// So, bitcoind has no API for getting the transaction spending a wallet UTXO. Instead we are
    /// therefore using a rather convoluted way to get it the other way around, since the spending
    /// transaction is actually *part of the wallet transactions*.
    /// So, what we do there is listing all outgoing transactions of the wallet since the last poll
    /// and iterating through each of those to check if it spends the transaction we are interested
    /// in (requiring an other RPC call for each!!).
    pub fn get_spender_txid(
        &self,
        spent_outpoint: &OutPoint,
    ) -> Result<Option<Txid>, BitcoindError> {
        // FIXME: The Unvault blockhash might be pretty deep and result in large responses to
        // `listsinceblock`.
        let req = self.make_watchonly_request(
            "gettransaction",
            &params!(Json::String(spent_outpoint.txid.to_string().into())),
        )?;
        let spent_tx_height = match req.get("blockheight").and_then(|h| h.as_i64()) {
            Some(h) => h,
            None => return Ok(None),
        };
        let block_hash = if let Ok(res) = self.make_watchonly_request(
            "getblockhash",
            &params!(Json::Number((spent_tx_height - 1).into())),
        ) {
            res.as_str()
                .expect("'getblockhash' result isn't a string")
                .to_string()
        } else {
            // Possibly a race.
            return Ok(None);
        };

        let lsb_res = self.make_watchonly_request(
            "listsinceblock",
            &params!(Json::String(block_hash.to_string())),
        )?;
        let transactions = lsb_res
            .get("transactions")
            .map(|t| t.as_array())
            .flatten()
            .expect(&format!(
            "API break: no or invalid 'transactions' in 'listsinceblock' result (blockhash: {})",
            block_hash
        ));

        // Get the spent txid to ignore the entries about this transaction
        let spent_txid = spent_outpoint.txid.to_string();
        // We use a cache to avoid needless iterations, since listsinceblock returns an entry
        // per transaction output, not per transaction.
        let mut visited_txs = HashSet::new();
        for transaction in transactions {
            if transaction.get("category").map(|c| c.as_str()).flatten() != Some("send") {
                continue;
            }

            let spending_txid = transaction
                .get("txid")
                .map(|t| t.as_str())
                .flatten()
                .expect(&format!(
                    "API break: no or invalid 'txid' in 'listsinceblock' entry (blockhash: {})",
                    block_hash
                ));

            if visited_txs.contains(&spending_txid) || &spent_txid == spending_txid {
                continue;
            } else {
                visited_txs.insert(spending_txid);
            }

            let gettx_res = self.make_watchonly_request(
                "gettransaction",
                &params!(
                    Json::String(spending_txid.to_string()),
                    Json::Bool(true), // watchonly
                    Json::Bool(true)  // verbose
                ),
            )?;
            let vin = gettx_res
                .get("decoded")
                .map(|d| d.get("vin").map(|vin| vin.as_array()))
                .flatten()
                .flatten()
                .expect(&format!(
                    "API break: getting '.decoded.vin' from 'gettransaction' (blockhash: {})",
                    block_hash
                ));

            for input in vin {
                let txid = input
                    .get("txid")
                    .map(|t| t.as_str().map(|t| Txid::from_str(t).ok()))
                    .flatten()
                    .flatten()
                    .expect(
                        &format!(
                            "API break: Invalid or no txid in 'vin' entry in 'gettransaction' (blockhash: {})",
                            block_hash
                    ));
                let vout = input.get("vout").map(|v| v.as_u64()).flatten().expect(
                    &format!(
                        "API break: Invalid or no vout in 'vin' entry in 'gettransaction' (blockhash: {})",
                        block_hash
                    ))
                as u32;
                let input_outpoint = OutPoint { txid, vout };

                if spent_outpoint == &input_outpoint {
                    return Ok(Txid::from_str(spending_txid)
                        .map(Some)
                        .expect("bitcoind gave an invalid txid in 'listsinceblock'"));
                }
            }
        }

        Ok(None)
    }

    pub fn is_in_mempool(&self, txid: &Txid) -> Result<bool, BitcoindError> {
        match self.make_node_request("getmempoolentry", &params!(Json::String(txid.to_string()))) {
            Ok(_) => Ok(true),
            Err(BitcoindError::Server(jsonrpc::Error::Rpc(jsonrpc::error::RpcError {
                code: -5,
                ..
            }))) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Check whether a transaction is part of the wallet, and not stuck (as in is confirmed or
    /// part of the mempool).
    pub fn is_current(&self, txid: &Txid) -> Result<bool, BitcoindError> {
        match self.get_wallet_transaction(txid) {
            // Non wallet transaction?
            Err(_) => Ok(false),
            Ok(tx) => {
                // Confirmed wallet transaction
                if tx.blockheight.is_some() {
                    Ok(true)
                // Not confirmed wallet transaction
                } else {
                    self.is_in_mempool(txid)
                }
            }
        }
    }

    /// Estimates the feerate needed for a tx to make it in the
    /// next block. Uses estimatesmartfee and, in case it returns an
    /// error, a default value.
    /// The value returned is in sats/kWU
    pub fn estimate_feerate(&self) -> Result<Option<u64>, BitcoindError> {
        if let Ok(json) = self.make_node_request(
            "estimatesmartfee",
            &params!(Json::Number(serde_json::Number::from(2))),
        ) {
            if let Some(n) = json.get("feerate") {
                let btc_kvb = n.as_f64().expect("feerate is f64");
                // Math is hard
                // btc/kvbyte -> sats/kbyte
                let sats_kvb = btc_kvb * Amount::ONE_BTC.as_sat() as f64;
                // sats/kbyte -> sats/vbyte
                let sats_vb = sats_kvb / 1000.0;
                // sats/vbyte -> sats/WU
                let sats_wu = sats_vb / 4.0;
                // sats/WU -> msats/WU
                return Ok(Some((sats_wu * 1000.0) as u64));
            }
        }
        // TODO: Calculate the fallback feerate using the blockchain!
        Ok(None)
    }

    /// Returns the number of confirmations of an unspent tx. Returns `None` if given a spent or
    /// non-existent tx
    pub fn get_unspent_outpoint_confirmations(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<i32>, BitcoindError> {
        // gettxout should be used for UTXOs, but this API is about txs,
        // so we always ask txid:0
        let res = self.make_watchonly_request(
            "gettxout",
            &params!(
                Json::String(outpoint.txid.to_string()),
                Json::Number(serde_json::Number::from(outpoint.vout))
            ),
        )?;
        Ok(res.get("confirmations").map(|a| {
            a.as_i64()
                .expect("Invalid confirmations in `gettxout` response: not an i64")
                as i32
        }))
    }

    pub fn get_block_stats(&self, blockhash: BlockHash) -> Result<BlockStats, BitcoindError> {
        let res = self.make_watchonly_request(
            "getblockheader",
            &params!(Json::String(blockhash.to_string()),),
        )?;
        let confirmations = res
            .get("confirmations")
            .map(|a| a.as_i64())
            .flatten()
            .expect("Invalid confirmations in `getblockheader` response: not an i64")
            as i32;
        let previous_block_str = res
            .get("previousblockhash")
            .map(|a| a.as_str())
            .flatten()
            .expect("Invalid previousblockhash in `getblockheader` response: not a string");
        let previous_blockhash = BlockHash::from_str(previous_block_str)
            .expect("Invalid previousblockhash hex in `getblockheader` response");
        let height = res
            .get("height")
            .map(|a| a.as_u64())
            .flatten()
            .expect("Invalid height in `getblockheader` response: not an u32")
            as u32;
        Ok(BlockStats {
            confirmations,
            previous_blockhash,
            height,
            blockhash,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTransaction {
    pub hex: String,
    #[serde(rename = "received_at")]
    pub received_time: u32,
    // None if unconfirmed
    pub blockheight: Option<u32>,
    // None if unconfirmed
    pub blocktime: Option<u32>,
}

/// Information about an utxo one of our descriptors points to.
#[derive(Debug, Clone)]
pub struct UtxoInfo {
    pub txo: TxOut,
    pub is_confirmed: bool,
}

#[derive(Debug, Clone)]
pub struct BlockStats {
    pub confirmations: i32,
    pub previous_blockhash: BlockHash,
    pub blockhash: BlockHash,
    pub height: u32,
}

#[derive(Debug, Clone)]
/// Onchain state of the deposit UTxOs
pub struct DepositsState {
    /// The set of newly "received" deposit utxos
    pub new_unconf: HashMap<OutPoint, UtxoInfo>,
    /// The set of newly confirmed deposit utxos
    pub new_conf: HashMap<OutPoint, UtxoInfo>,
    /// The set of newly spent deposit utxos
    pub new_spent: HashMap<OutPoint, UtxoInfo>,
}

/// Onchain state of the Unvault UTxOs
pub struct UnvaultsState {
    /// The set of newly confirmed unvault utxos
    pub new_conf: Vec<OutPoint>,
    /// The set of newly spent unvault utxos
    pub new_spent: Vec<OutPoint>,
}

pub struct SyncInfo {
    pub headers: u64,
    pub blocks: u64,
    pub ibd: bool,
    pub progress: f64,
}

#[derive(Clone, Debug)]
pub struct ListUnspentEntry {
    pub outpoint: OutPoint,
    pub txo: TxOut,
    pub label: Option<String>,
    pub confirmations: i32,
    pub derivation_index: Option<ChildNumber>,
}

impl From<&Json> for ListUnspentEntry {
    fn from(utxo: &Json) -> Self {
        let txid = utxo
            .get("txid")
            .map(|a| a.as_str())
            .flatten()
            .expect("API break, 'listunspent' entry didn't contain a string 'txid'.");
        let txid = Txid::from_str(txid).expect("Converting txid from str in 'listunspent': {}.");
        let vout = utxo
            .get("vout")
            .map(|a| a.as_u64())
            .flatten()
            .expect("API break, 'listunspent' entry didn't contain a valid 'vout'.");
        let script_pubkey = utxo
            .get("scriptPubKey")
            .map(|s| s.as_str())
            .flatten()
            .map(|s| {
                Script::from_str(s)
                    .expect("API break, 'listunspent' entry didn't contain a valid script_pubkey")
            })
            .expect("API break, 'listunspent' entry didn't contain a string script_pubkey.");
        let amount = utxo
            .get("amount")
            .map(|a| a.as_f64())
            .flatten()
            .expect("API break, 'listunspent' entry didn't contain a valid 'amount'.");
        let value = Amount::from_btc(amount)
            .expect("Could not convert 'listunspent' entry's 'amount' to an Amount")
            .as_sat();
        let confirmations = utxo
            .get("confirmations")
            .map(|a| a.as_i64())
            .flatten()
            .expect("API break, 'listunspent' entry didn't contain a valid 'confirmations'.")
            as i32;
        let label = utxo
            .get("label")
            .map(|l| l.as_str())
            .flatten()
            .map(|l| l.to_string());
        let mut derivation_index = None;
        if let Some(d) = utxo.get("desc").map(|d| {
            d.as_str()
                .expect("API break, 'listunspent` entry contains a non-string desc")
        }) {
            // If we have a descriptor, we derive only once, so the derivation index must be
            // between `/` and `]`
            let derivation_index_start = d.find('/');
            let derivation_index_end = d.find(']');
            if let Some(s) = derivation_index_start {
                if let Some(e) = derivation_index_end {
                    // Also we always use normal derivation
                    derivation_index = d[s + 1..e]
                        .parse()
                        .map(|d| ChildNumber::Normal { index: d })
                        .ok();
                }
            }
        }

        ListUnspentEntry {
            outpoint: OutPoint {
                txid,
                vout: vout as u32, // Bitcoin makes this safe
            },
            txo: TxOut {
                value,
                script_pubkey,
            },
            confirmations,
            label,
            derivation_index,
        }
    }
}

#[derive(Debug)]
pub struct ListSinceBlockTransaction {
    pub outpoint: OutPoint,
    pub txo: TxOut,
    pub is_receive: bool,
    pub wallet_descs: Vec<String>,
    pub confirmations: i32,
    pub blockheight: Option<u32>,
}

impl From<&Json> for ListSinceBlockTransaction {
    fn from(j: &Json) -> Self {
        let category = j
            .get("category")
            .map(|c| c.as_str())
            .flatten()
            .expect("API break, 'listsinceblock' didn't cointain a valid category")
            .to_string();
        let is_receive = category == "receive" || category == "generate";
        let txid = j
            .get("txid")
            .map(|a| a.as_str())
            .flatten()
            .expect("API break, 'listsinceblock' entry didn't contain a string 'txid'.");
        let txid = Txid::from_str(txid).expect("Converting txid from str in 'listsinceblock': {}.");
        let vout = j
            .get("vout")
            .map(|a| a.as_u64())
            .flatten()
            .expect("API break, 'listsinceblock' entry didn't contain a valid 'vout'.");
        let script_pubkey =
            j.get("address")
                .map(|s| s.as_str())
                .flatten()
                .map(|s| {
                    Address::from_str(s).expect(
                    "API break, 'listsinceblock' entry didn't contain a valid script_pubkey",
                ).script_pubkey()
                })
                .expect("API break, 'listsinceblock' entry didn't contain a string script_pubkey.");
        let amount_negative = !is_receive;
        let amount = j
            .get("amount")
            .map(|a| a.as_f64())
            .flatten()
            .map(|a| if amount_negative { -a } else { a })
            .expect("API break, 'listsinceblock' entry didn't contain a valid 'amount'.");
        let value = Amount::from_btc(amount)
            .expect("Could not convert 'listsinceblock' entry's 'amount' to an Amount")
            .as_sat();
        let confirmations = j
            .get("confirmations")
            .map(|a| a.as_i64())
            .flatten()
            .expect("API break, 'listsinceblock' entry didn't contain a valid 'confirmations'.")
            as i32;
        let blockheight = j
            .get("blockheight")
            .map(|a| a.as_u64())
            .flatten()
            .map(|b| b as u32);
        // FIXME: allocs
        let wallet_descs = j
            .get("wallet_descs")
            .map(|l| {
                l.as_array()
                    .expect(
                        "API break, 'listsinceblock' entry didn't contain a valid 'wallet_descs'.",
                    )
                    .iter()
                    .map(|desc| {
                        desc.as_str()
                            .expect("Invalid desc string in 'listsinceblock'.")
                            .to_string()
                    })
                    .collect()
            })
            .unwrap_or_else(|| Vec::new());

        ListSinceBlockTransaction {
            outpoint: OutPoint {
                txid,
                vout: vout as u32, // Bitcoin makes this safe
            },
            is_receive,
            wallet_descs,
            txo: TxOut {
                value,
                script_pubkey,
            },
            confirmations,
            blockheight,
        }
    }
}
