use crate::common::config::BitcoindConfig;
use crate::daemon::{bitcoind::BitcoindError, revaultd::BlockchainTip};
use revault_tx::{
    bitcoin::{
        blockdata::constants::COIN_VALUE, consensus::encode, Address, Amount, BlockHash, OutPoint,
        Transaction, TxOut, Txid,
    },
    transactions::{DUST_LIMIT, UNVAULT_CPFP_VALUE},
};

use std::{
    any::Any,
    collections::HashMap,
    fs,
    str::FromStr,
    time::{Duration, Instant},
};

use jsonrpc::{
    arg,
    client::Client,
    simple_http::{Error as HttpError, SimpleHttpTransport},
};
use serde_json::Value as Json;

// The minimum deposit value according to revault_tx depends also on the unvault's
// transaction fee. To have a one-value-fits-all, just take a 5% leeway.
const MIN_DEPOSIT_VALUE: u64 = (DUST_LIMIT + UNVAULT_CPFP_VALUE) * 105 / 100;

// If bitcoind takes more than 3 minutes to answer one of our queries, fail.
const RPC_SOCKET_TIMEOUT: u64 = 180;

// Labels used to tag utxos in the watchonly wallet
const DEPOSIT_UTXOS_LABEL: &str = "revault-deposit";
const UNVAULT_UTXOS_LABEL: &str = "revault-unvault";

pub struct BitcoinD {
    node_client: Client,
    watchonly_client: Client,
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

        let url = format!("http://{}/wallet/{}", config.addr, watchonly_wallet_path);
        let watchonly_client = Client::with_transport(
            SimpleHttpTransport::builder()
                .url(&url)
                .map_err(BitcoindError::from)?
                .timeout(Duration::from_secs(RPC_SOCKET_TIMEOUT))
                .cookie_auth(cookie_string)
                .build(),
        );

        Ok(BitcoinD {
            node_client,
            watchonly_client,
        })
    }

    // Reasonably try to be robust to possible spurious communication error.
    fn handle_error(&self, e: jsonrpc::Error, start: Instant) -> Result<(), BitcoindError> {
        let now = Instant::now();

        match e {
            jsonrpc::Error::Transport(ref err) => {
                log::error!("Transport error when talking to bitcoind: '{}'", err);

                // This is *always* a simple_http::Error. Rule out the error that can
                // not occur after startup (ie if we encounter them it must be startup
                // and we better be failing quickly).
                let any_err = err as &dyn Any;
                if let Some(http_err) = any_err.downcast_ref::<HttpError>() {
                    match http_err {
                        HttpError::InvalidUrl { .. } => return Err(BitcoindError::Server(e)),
                        // FIXME: allow it to be unreachable for a handful of seconds,
                        // but not at startup!
                        HttpError::SocketError(_) => return Err(BitcoindError::Server(e)),
                        HttpError::HttpParseError => {
                            // Weird. Try again once, just in case.
                            if now.duration_since(start) > Duration::from_secs(1) {
                                return Err(BitcoindError::Server(e));
                            }
                            std::thread::sleep(Duration::from_secs(1));
                        }
                        _ => {}
                    }
                }

                // This one *may* happen. For a number of reasons, the obvious one may
                // be the RPC work queue being exceeded. In this case, and since we'll
                // usually fail if we err try again for a reasonable amount of time.
                if now.duration_since(start) > Duration::from_secs(45) {
                    return Err(BitcoindError::Server(e));
                }
                std::thread::sleep(Duration::from_secs(1));
                log::debug!("Retrying RPC request to bitcoind.");
            }
            jsonrpc::Error::Json(ref err) => {
                // Weird. A JSON serialization error? Just try again but
                // fail fast anyways as it should not happen.
                log::error!(
                    "JSON serialization error when talking to bitcoind: '{}'",
                    err
                );
                if now.duration_since(start) > Duration::from_secs(1) {
                    return Err(BitcoindError::Server(e));
                }
                std::thread::sleep(Duration::from_millis(500));
                log::debug!("Retrying RPC request to bitcoind.");
            }
            _ => return Err(BitcoindError::Server(e)),
        };

        Ok(())
    }

    fn make_request<'a, 'b>(
        &self,
        client: &Client,
        method: &'a str,
        params: &'b [Box<serde_json::value::RawValue>],
    ) -> Result<Json, BitcoindError> {
        let req = client.build_request(method, &params);
        log::trace!("Sending to bitcoind: {:#?}", req);

        // Trying to be robust on bitcoind's spurious failures. We try to support bitcoind failing
        // under our feet for a few dozens of seconds, while not delaying an early failure (for
        // example, if we got the RPC listening address or path to the cookie wrong).
        let start = Instant::now();
        loop {
            match client.send_request(req.clone()) {
                Ok(resp) => {
                    let res = resp.result().map_err(BitcoindError::Server)?;
                    log::trace!("Got from bitcoind: {:#?}", res);

                    return Ok(res);
                }
                Err(e) => {
                    // Decide wether we should error, or not yet
                    self.handle_error(e, start)?;
                }
            }
        }
    }

    fn make_requests<'a, 'b>(
        &self,
        client: &Client,
        reqs: &[jsonrpc::Request],
    ) -> Result<Vec<Json>, BitcoindError> {
        log::trace!("Sending to bitcoind: {:#?}", reqs);

        // Trying to be robust on bitcoind's spurious failures. We try to support bitcoind failing
        // under our feet for a few dozens of seconds, while not delaying an early failure (for
        // example, if we got the RPC listening address or path to the cookie wrong).
        let start = Instant::now();
        loop {
            match client.send_batch(&reqs.clone()) {
                Ok(resp) => {
                    let res = resp
                        .into_iter()
                        .filter_map(|r| r)
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
                Err(e) => {
                    // Decide wether we should error, or not yet
                    self.handle_error(e, start)?;
                }
            }
        }
    }

    fn make_node_request<'a, 'b>(
        &self,
        method: &'a str,
        params: &'b [Box<serde_json::value::RawValue>],
    ) -> Result<Json, BitcoindError> {
        self.make_request(&self.node_client, method, params)
    }

    fn make_watchonly_request<'a, 'b>(
        &self,
        method: &'a str,
        params: &'b [Box<serde_json::value::RawValue>],
    ) -> Result<Json, BitcoindError> {
        self.make_request(&self.watchonly_client, method, params)
    }

    fn make_node_requests<'a, 'b>(
        &self,
        requests: &[jsonrpc::Request],
    ) -> Result<Vec<Json>, BitcoindError> {
        self.make_requests(&self.node_client, requests)
    }

    pub fn getblockchaininfo(&self) -> Result<Json, BitcoindError> {
        self.make_node_request("getblockchaininfo", &[])
    }

    pub fn getblockhash(&self, height: u32) -> Result<BlockHash, BitcoindError> {
        BlockHash::from_str(
            self.make_node_request("getblockhash", &params!(height))?
                .as_str()
                .ok_or_else(|| {
                    BitcoindError::Custom(
                        "API break, 'getblockhash' didn't return a string.".to_string(),
                    )
                })?,
        )
        .map_err(|e| {
            BitcoindError::Custom(format!("Invalid blockhash given by 'getblockhash': {}", e))
        })
    }

    pub fn get_tip(&self) -> Result<BlockchainTip, BitcoindError> {
        let json_height = self.make_node_request("getblockcount", &[])?;
        let height = json_height.as_u64().ok_or_else(|| {
            BitcoindError::Custom("API break, 'getblockcount' didn't return an u64.".to_string())
        })? as u32;
        let hash = self.getblockhash(height)?;

        Ok(BlockchainTip { height, hash })
    }

    pub fn synchronization_info(&self) -> Result<SyncInfo, BitcoindError> {
        let chaininfo = self.make_node_request("getblockchaininfo", &[])?;
        Ok(SyncInfo {
            headers: chaininfo
                .get("headers")
                .and_then(|h| h.as_u64())
                .ok_or_else(|| {
                    BitcoindError::Custom(
                        "No valid 'headers' in getblockchaininfo response?".to_owned(),
                    )
                })?,
            blocks: chaininfo
                .get("blocks")
                .and_then(|b| b.as_u64())
                .ok_or_else(|| {
                    BitcoindError::Custom(
                        "No valid 'blocks' in getblockchaininfo response?".to_owned(),
                    )
                })?,
            ibd: chaininfo
                .get("initialblockdownload")
                .and_then(|i| i.as_bool())
                .ok_or_else(|| {
                    BitcoindError::Custom(
                        "No valid 'initialblockdownload' in getblockchaininfo response?".to_owned(),
                    )
                })?,
            progress: chaininfo
                .get("verificationprogress")
                .and_then(|i| i.as_f64())
                .ok_or_else(|| {
                    BitcoindError::Custom(
                        "No valid 'initialblockdownload' in getblockchaininfo response?".to_owned(),
                    )
                })?,
        })
    }

    pub fn createwallet_startup(&self, wallet_path: String) -> Result<(), BitcoindError> {
        let res = self.make_node_request(
            "createwallet",
            &params!(
                Json::String(wallet_path),
                Json::Bool(true),             // watchonly
                Json::Bool(false),            // blank
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
        self.make_node_request("listwallets", &[])?
            .as_array()
            .ok_or_else(|| {
                BitcoindError::Custom(
                    "API break, 'listwallets' didn't return an array.".to_string(),
                )
            })
            .map(|vec| {
                vec.iter()
                    .map(|json_str| {
                        json_str
                            .as_str()
                            .unwrap_or_else(|| {
                                log::error!("'listwallets' contain a non-string value. Aborting.");
                                panic!("API break: 'listwallets' contains a non-string value");
                            })
                            .to_string()
                    })
                    .collect()
            })
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
        if warning.len() > 0 {
            Err(BitcoindError::Custom(warning.to_string()))
        } else {
            Ok(())
        }
    }

    /// Constructs an `addr()` descriptor out of an address
    pub fn addr_descriptor(&self, address: &str) -> Result<String, BitcoindError> {
        let desc_wo_checksum = format!("addr({})", address);

        Ok(self
            .make_watchonly_request(
                "getdescriptorinfo",
                &params!(Json::String(desc_wo_checksum)),
            )?
            .get("descriptor")
            .ok_or_else(|| {
                BitcoindError::Custom("No 'descriptor' in 'getdescriptorinfo'".to_string())
            })?
            .as_str()
            .ok_or_else(|| {
                BitcoindError::Custom(
                    "'descriptor' in 'getdescriptorinfo' isn't a string anymore".to_string(),
                )
            })?
            .to_string())
    }

    fn bulk_import_descriptors(
        &self,
        descriptors: Vec<String>,
        timestamp: u32,
        label: String,
        fresh_wallet: bool,
    ) -> Result<(), BitcoindError> {
        let all_descriptors: Vec<Json> = descriptors
            .into_iter()
            .map(|desc| {
                let mut desc_map = serde_json::Map::with_capacity(3);
                desc_map.insert("desc".to_string(), Json::String(desc));
                // We set to "now" the timestamp for fresh wallet, as otherwise bitcoind
                // will rescan the last few blocks for each of them.
                desc_map.insert(
                    "timestamp".to_string(),
                    if fresh_wallet {
                        Json::String("now".to_string())
                    } else {
                        log::debug!("Not a fresh wallet, rescan *may* take some time.");
                        Json::Number(serde_json::Number::from(timestamp))
                    },
                );
                desc_map.insert("label".to_string(), Json::String(label.clone()));

                Json::Object(desc_map)
            })
            .collect();

        let res = self
            .make_watchonly_request("importdescriptors", &params!(Json::Array(all_descriptors)))?;
        if res.get(0).map(|x| x.get("success")) == Some(Some(&Json::Bool(true))) {
            return Ok(());
        }

        Err(BitcoindError::Custom(format!(
            "Error returned from 'importdescriptor': {:?}",
            res.get("error")
        )))
    }

    pub fn startup_import_deposit_descriptors(
        &self,
        descriptors: Vec<String>,
        timestamp: u32,
        fresh_wallet: bool,
    ) -> Result<(), BitcoindError> {
        self.bulk_import_descriptors(
            descriptors,
            timestamp,
            DEPOSIT_UTXOS_LABEL.to_string(),
            fresh_wallet,
        )
    }

    pub fn startup_import_unvault_descriptors(
        &self,
        descriptors: Vec<String>,
        timestamp: u32,
        fresh_wallet: bool,
    ) -> Result<(), BitcoindError> {
        self.bulk_import_descriptors(
            descriptors,
            timestamp,
            UNVAULT_UTXOS_LABEL.to_string(),
            fresh_wallet,
        )
    }

    fn import_fresh_descriptor(
        &self,
        descriptor: String,
        label: String,
    ) -> Result<(), BitcoindError> {
        let mut desc_map = serde_json::Map::with_capacity(3);
        desc_map.insert("desc".to_string(), Json::String(descriptor));
        desc_map.insert("timestamp".to_string(), Json::String("now".to_string()));
        desc_map.insert("label".to_string(), Json::String(label));

        let res = self.make_watchonly_request(
            "importdescriptors",
            &params!(Json::Array(vec![Json::Object(desc_map,)])),
        )?;
        if res.get(0).map(|x| x.get("success")).flatten() == Some(&Json::Bool(true)) {
            return Ok(());
        }

        Err(BitcoindError::Custom(format!(
            "In import_fresh descriptor, no success returned from 'importdescriptor': {:?}",
            res
        )))
    }

    pub fn import_fresh_deposit_descriptor(&self, descriptor: String) -> Result<(), BitcoindError> {
        self.import_fresh_descriptor(descriptor, DEPOSIT_UTXOS_LABEL.to_string())
    }

    pub fn import_fresh_unvault_descriptor(&self, descriptor: String) -> Result<(), BitcoindError> {
        self.import_fresh_descriptor(descriptor, UNVAULT_UTXOS_LABEL.to_string())
    }

    pub fn listunspent(
        &self,
        min_amount: Option<u64>,
    ) -> Result<Vec<ListUnspentResult>, BitcoindError> {
        let req = if let Some(min_amount) = min_amount {
            self.make_watchonly_request(
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
            self.make_watchonly_request(
                "listunspent",
                &params!(
                    Json::Number(0.into()), // minconf
                ),
            )
        };

        Ok(req?
            .as_array()
            .expect("API break, 'listunspent' didn't return an array.")
            .into_iter()
            .map(|utxo| self.parse_listunspent_output(&utxo))
            .collect())
    }

    // A routine for parsing a listunspent entry
    fn parse_listunspent_output(&self, utxo: &Json) -> ListUnspentResult {
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
        let address = utxo
            .get("address")
            .map(|a| a.as_str())
            .flatten()
            .expect("API break, 'listunspent' entry didn't contain a string 'address'.");
        let script_pubkey = Address::from_str(address)
            .expect("Could not parse 'address' from 'listunspent' entry")
            .script_pubkey();
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
            .map(|a| a.as_u64())
            .flatten()
            .expect("API break, 'listunspent' entry didn't contain a valid 'confirmations'.");
        let label = utxo
            .get("label")
            .map(|a| a.as_str())
            .flatten()
            .expect("API break, 'listunspent' entry didn't contain a valid 'label'.")
            .to_string();

        ListUnspentResult {
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
        }
    }

    /// Repeatedly called by our main loop to stay in sync with bitcoind.
    /// We take the currently known deposit utxos, and return the new, confirmed and spent ones.
    pub fn sync_deposits(
        &self,
        deposits_utxos: &HashMap<OutPoint, UtxoInfo>,
        min_conf: u32,
    ) -> Result<DepositsState, BitcoindError> {
        let (mut new_utxos, mut confirmed_utxos) = (HashMap::new(), HashMap::new());
        // All seen utxos, if an utxo remains unseen by listunspent then it's spent.
        let mut spent_utxos = deposits_utxos.clone();
        let utxos = self.listunspent(Some(MIN_DEPOSIT_VALUE / COIN_VALUE))?;
        let label = DEPOSIT_UTXOS_LABEL;

        for unspent in utxos {
            if unspent.label != label {
                continue;
            }

            // Not obvious at first sight:
            //  - spent_utxos == existing_utxos before the loop
            //  - listunspent won't send duplicated entries
            //  - remove() will return None if it was not present in the map
            // Therefore if there is an utxo at this outpoint, it's an already known deposit
            if let Some(map_utxo) = spent_utxos.remove(&unspent.outpoint) {
                // It may be known but still unconfirmed, though.
                if !map_utxo.is_confirmed && unspent.confirmations >= min_conf as u64 {
                    confirmed_utxos.insert(unspent.outpoint, map_utxo);
                }
                continue;
            }
            new_utxos.insert(
                unspent.outpoint,
                UtxoInfo {
                    txo: unspent.txo,
                    // All new utxos are marked as unconfirmed. This allows for a proper state
                    // transition.
                    is_confirmed: false,
                },
            );
        }

        Ok(DepositsState {
            new_unconf: new_utxos,
            new_conf: confirmed_utxos,
            new_spent: spent_utxos,
        })
    }

    /// Repeatedly called by our main loop to stay in sync with bitcoind.
    /// We take the currently known unvault utxos, and return both the confirmed and spent ones.
    pub fn sync_unvaults(
        &self,
        unvault_utxos: &HashMap<OutPoint, UtxoInfo>,
    ) -> Result<UnvaultsState, BitcoindError> {
        // Since we don't need to care about new utxos the logic here is more
        // straightforward than in sync_deposits.
        //
        // 1. Fetch the Unvault utxos from the watchonly wallet into a
        //    (outpoint, confirmed) mapping
        let unspent_list: HashMap<OutPoint, bool> = self
            .listunspent(None)?
            .iter()
            .filter_map(|utxo| {
                if utxo.label == UNVAULT_UTXOS_LABEL {
                    Some((utxo.outpoint, utxo.confirmations > 0))
                } else {
                    None
                }
            })
            .collect();

        // 2. Loop through all known Unvault utxos, check if some confirmed or
        //    are missing (ie were spent)
        let (mut new_conf, mut new_spent) = (HashMap::new(), HashMap::new());
        for (op, utxo_info) in unvault_utxos {
            if let Some(confirmed) = unspent_list.get(&op) {
                if *confirmed && !utxo_info.is_confirmed {
                    new_conf.insert(*op, utxo_info.clone());
                }
            } else {
                new_spent.insert(*op, utxo_info.clone());
            }
        }

        Ok(UnvaultsState {
            new_conf,
            new_spent,
        })
    }

    // FIXME: this should return a struct not a footguny tuple.
    /// Get the raw transaction as hex, the blockheight it was included in if
    /// it's confirmed, as well as the reception time.
    pub fn get_wallet_transaction(
        &self,
        txid: &Txid,
    ) -> Result<(String, Option<u32>, u32), BitcoindError> {
        let res = self
            .make_watchonly_request("gettransaction", &params!(Json::String(txid.to_string())))?;
        let tx_hex = res
            .get("hex")
            .ok_or_else(|| {
                BitcoindError::Custom(format!(
                    "API break: no 'hex' in 'gettransaction' result (txid: {})",
                    txid
                ))
            })?
            .as_str()
            .ok_or_else(|| {
                BitcoindError::Custom("API break: 'hex' is not a string ????".to_string())
            })?
            .to_string();
        let blockheight = res.get("blockheight").map(|bh| bh.as_u64().unwrap() as u32);
        let received = res
            .get("timereceived")
            .ok_or_else(|| {
                BitcoindError::Custom(format!(
                    "API break: no 'time_received' in 'gettransaction' result (txid: {})",
                    txid
                ))
            })?
            .as_u64()
            .ok_or_else(|| {
                BitcoindError::Custom(format!(
                    "API break: invalid 'time_received' in 'gettransaction' result (txid: {})",
                    txid
                ))
            })? as u32;

        Ok((tx_hex, blockheight, received))
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
        let (hex, _, _) = self.get_wallet_transaction(txid)?;
        log::debug!("Re-broadcasting '{}'", hex);
        self.make_watchonly_request("sendrawtransaction", &params!(Json::String(hex)))
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
        block_hash: &BlockHash,
    ) -> Result<Option<Txid>, BitcoindError> {
        let lsb_res = self.make_watchonly_request(
            "listsinceblock",
            &params!(Json::String(block_hash.to_string())),
        )?;
        let transactions = lsb_res
            .get("transactions")
            .map(|t| t.as_array())
            .flatten()
            .ok_or_else(|| {
                BitcoindError::Custom(format!(
                    "API break: no or invalid 'transactions' in 'listsinceblock' result (blockhash: {})",
                    block_hash
                ))
            })?;

        for transaction in transactions {
            if transaction.get("category").map(|c| c.as_str()).flatten() != Some("send") {
                continue;
            }

            // TODO: i think we can also filter out the entries *with* a "revault-somthing" label,
            // but we need to be sure.

            let spending_txid = transaction
                .get("txid")
                .map(|t| t.as_str())
                .flatten()
                .ok_or_else(|| {
                    BitcoindError::Custom(format!(
                        "API break: no or invalid 'txid' in 'listsinceblock' entry (blockhash: {})",
                        block_hash
                    ))
                })?;

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
                .ok_or_else(|| {
                    BitcoindError::Custom(format!(
                        "API break: getting '.decoded.vin' from 'gettransaction' (blockhash: {})",
                        block_hash
                    ))
                })?;

            for input in vin {
                let txid = input
                    .get("txid")
                    .map(|t| t.as_str().map(|t| Txid::from_str(t).ok()))
                    .flatten()
                    .flatten().ok_or_else(|| {
                    BitcoindError::Custom(format!(
                        "API break: Invalid or no txid in 'vin' entry in 'gettransaction' (blockhash: {})",
                        block_hash
                    ))
                })?;
                let vout = input.get("vout").map(|v| v.as_u64()).flatten().ok_or_else(|| {
                    BitcoindError::Custom(format!(
                        "API break: Invalid or no vout in 'vin' entry in 'gettransaction' (blockhash: {})",
                        block_hash
                    ))
                })? as u32;
                let input_outpoint = OutPoint { txid, vout };

                if spent_outpoint == &input_outpoint {
                    return Txid::from_str(spending_txid)
                        .map(|txid| Some(txid))
                        .map_err(|e| {
                            BitcoindError::Custom(format!(
                                "bitcoind gave an invalid txid in 'listsinceblock': '{}'",
                                e
                            ))
                        });
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
            // Confirmed wallet transaction
            Ok((_, Some(_), _)) => Ok(true),
            // Not confirmed wallet transaction
            Ok((_, None, _)) => self.is_in_mempool(txid),
        }
    }
}

/// Information about an utxo one of our descriptors points to.
#[derive(Debug, Clone)]
pub struct UtxoInfo {
    pub txo: TxOut,
    pub is_confirmed: bool,
}

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
    pub new_conf: HashMap<OutPoint, UtxoInfo>,
    /// The set of newly spent unvault utxos
    pub new_spent: HashMap<OutPoint, UtxoInfo>,
}

pub struct SyncInfo {
    pub headers: u64,
    pub blocks: u64,
    pub ibd: bool,
    pub progress: f64,
}

pub struct ListUnspentResult {
    pub outpoint: OutPoint,
    pub txo: TxOut,
    pub label: String,
    pub confirmations: u64,
}
