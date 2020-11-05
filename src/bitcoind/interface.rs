use crate::{
    bitcoind::BitcoindError,
    config::BitcoindConfig,
    revaultd::{CachedVault, VaultStatus},
};
use revault_tx::bitcoin::{Address, Amount, OutPoint, TxOut, Txid};

use std::{collections::HashMap, fs, str::FromStr};

use jsonrpc::{client::Client, simple_rtt::Tripper};

pub struct BitcoinD {
    client: Client<Tripper>,
}

impl BitcoinD {
    pub fn new(config: &BitcoindConfig) -> Result<BitcoinD, BitcoindError> {
        let cookie_string = fs::read_to_string(&config.cookie_path)
            .map_err(|e| BitcoindError(format!("Reading cookie file: {}", e.to_string())))?;
        // The cookie file content is "__cookie__:pass"
        let mut cookie_slices = cookie_string.split(":");
        let (user, pass) = (
            cookie_slices.next().map(|s| s.to_string()),
            cookie_slices.next().map(|s| s.to_string()),
        );
        let client = Client::new(format!("{}", config.addr), user, pass);

        Ok(BitcoinD { client })
    }

    fn deposit_utxos_label(&self) -> String {
        "revault-deposit".to_string()
    }

    fn unvault_utxos_label(&self) -> String {
        "revault-unvault".to_string()
    }

    fn make_request<'a, 'b>(
        &self,
        method: &'a str,
        params: &'b [serde_json::Value],
    ) -> Result<serde_json::Value, BitcoindError> {
        let req = self.client.build_request(method, params);
        log::trace!("Sending to bitcoind: {:#?}", req);
        let resp = self
            .client
            .send_request(&req)
            .map_err(|e| BitcoindError(format!("Sending request: {}", e.to_string())))?;
        let res = resp
            .into_result()
            .map_err(|e| BitcoindError(format!("Making request: {}", e.to_string())))?;
        log::trace!("Got from bitcoind: {:#?}", res);

        Ok(res)
    }

    pub fn getblockchaininfo(&self) -> Result<serde_json::Value, BitcoindError> {
        self.make_request("getblockchaininfo", &[])
    }

    pub fn createwallet_startup(&self, wallet_path: String) -> Result<(), BitcoindError> {
        let res = self.make_request(
            "createwallet",
            &[
                serde_json::Value::String(wallet_path),
                serde_json::Value::Bool(true),             // watchonly
                serde_json::Value::Bool(false),            // blank
                serde_json::Value::String("".to_string()), // passphrase,
                serde_json::Value::Bool(false),            // avoid_reuse
                serde_json::Value::Bool(true),             // descriptors
                serde_json::Value::Bool(true),             // load_on_startup
            ],
        )?;

        if res.get("name").is_some() {
            return Ok(());
        }

        Err(BitcoindError(format!(
            "Error creating wallet: '{:?}'",
            res.get("warning")
        )))
    }

    pub fn listwallets(&self) -> Result<Vec<String>, BitcoindError> {
        self.make_request("listwallets", &[])?
            .as_array()
            .ok_or_else(|| {
                BitcoindError("API break, 'listwallets' didn't return an array.".to_string())
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
        let res = self.make_request(
            "loadwallet",
            &[
                serde_json::Value::String(wallet_path),
                serde_json::Value::Bool(true), // load_on_startup
            ],
        )?;

        if res.get("name").is_some() {
            return Ok(());
        }

        Err(BitcoindError(format!(
            "Error loading wallet: '{:?}'",
            res.get("warning")
        )))
    }

    pub fn unloadwallet(&self, wallet_name: String) -> Result<(), BitcoindError> {
        let res = self.make_request(
            "unloadwallet",
            &[
                serde_json::Value::String(wallet_name),
                serde_json::Value::Bool(false), // load_on_startup
            ],
        )?;

        if let Some(warning) = res.get("warning") {
            log::debug!("Warning unloading wallet: {}", warning);
        }

        Ok(())
    }

    /// Constructs an `addr()` descriptor out of an address
    pub fn addr_descriptor(&self, address: &str) -> Result<String, BitcoindError> {
        let desc_wo_checksum = format!("addr({})", address);

        Ok(self
            .make_request(
                "getdescriptorinfo",
                &[serde_json::Value::String(desc_wo_checksum)],
            )?
            .get("descriptor")
            .ok_or_else(|| BitcoindError("No 'descriptor' in 'getdescriptorinfo'".to_string()))?
            .as_str()
            .ok_or_else(|| {
                BitcoindError(
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
    ) -> Result<(), BitcoindError> {
        let all_descriptors: Vec<serde_json::Value> = descriptors
            .into_iter()
            .map(|desc| {
                let mut desc_map = serde_json::Map::with_capacity(3);
                desc_map.insert("desc".to_string(), serde_json::Value::String(desc));
                // FIXME: set to "now" for first import!
                desc_map.insert(
                    "timestamp".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(timestamp)),
                );
                desc_map.insert(
                    "label".to_string(),
                    serde_json::Value::String(label.clone()),
                );

                serde_json::Value::Object(desc_map)
            })
            .collect();

        let res = self.make_request(
            "importdescriptors",
            &[serde_json::Value::Array(all_descriptors)],
        )?;
        if res.get(0).map(|x| x.get("success")) == Some(Some(&serde_json::Value::Bool(true))) {
            return Ok(());
        }

        Err(BitcoindError(format!(
            "Error returned from 'importdescriptor': {:?}",
            res.get("error")
        )))
    }

    pub fn startup_import_deposit_descriptors(
        &self,
        descriptors: Vec<String>,
        timestamp: u32,
    ) -> Result<(), BitcoindError> {
        self.bulk_import_descriptors(descriptors, timestamp, self.deposit_utxos_label())
    }

    pub fn startup_import_unvault_descriptors(
        &self,
        descriptors: Vec<String>,
        timestamp: u32,
    ) -> Result<(), BitcoindError> {
        self.bulk_import_descriptors(descriptors, timestamp, self.unvault_utxos_label())
    }

    fn import_fresh_descriptor(
        &self,
        descriptor: String,
        label: String,
    ) -> Result<(), BitcoindError> {
        let mut desc_map = serde_json::Map::with_capacity(3);
        desc_map.insert("desc".to_string(), serde_json::Value::String(descriptor));
        desc_map.insert(
            "timestamp".to_string(),
            serde_json::Value::String("now".to_string()),
        );
        desc_map.insert(
            "label".to_string(),
            serde_json::Value::String(label.clone()),
        );

        let res = self.make_request(
            "importdescriptors",
            &[serde_json::Value::Array(vec![serde_json::Value::Object(
                desc_map,
            )])],
        )?;
        if res.get(0).map(|x| x.get("success")) == Some(Some(&serde_json::Value::Bool(true))) {
            return Ok(());
        }

        Err(BitcoindError(format!(
            "In import_fresh descriptor, error returned from 'importdescriptor': {:?}",
            res.get("error")
        )))
    }

    pub fn import_fresh_deposit_descriptor(&self, descriptor: String) -> Result<(), BitcoindError> {
        self.import_fresh_descriptor(descriptor, self.deposit_utxos_label())
    }

    pub fn import_fresh_unvault_descriptor(&self, descriptor: String) -> Result<(), BitcoindError> {
        self.import_fresh_descriptor(descriptor, self.unvault_utxos_label())
    }

    // A routine to get the txid,vout pair out of a listunspent entry
    fn outpoint_from_utxo(&self, utxo: &serde_json::Value) -> Result<OutPoint, BitcoindError> {
        let txid = utxo
            .get("txid")
            .ok_or_else(|| {
                BitcoindError("API break, 'listunspent' entry didn't contain a 'txid'.".to_string())
            })?
            .as_str()
            .ok_or_else(|| {
                BitcoindError(
                    "API break, 'listunspent' entry didn't contain a string 'txid'.".to_string(),
                )
            })?;
        let txid = Txid::from_str(txid).map_err(|e| {
            BitcoindError(format!(
                "Converting txid from str in 'listunspent': {}.",
                e.to_string()
            ))
        })?;
        let vout = utxo
            .get("vout")
            .ok_or_else(|| {
                BitcoindError("API break, 'listunspent' entry didn't contain a 'vout'.".to_string())
            })?
            .as_u64()
            .ok_or_else(|| {
                BitcoindError(
                    "API break, 'listunspent' entry didn't contain a valid 'vout'.".to_string(),
                )
            })?;
        Ok(OutPoint {
            txid,
            vout: vout as u32, // Bitcoin makes this safe
        })
    }

    /// Repeatedly called by our main loop to stay in sync with bitcoind.
    /// We take the currently known utxos, and return both the new deposits and the spent deposits.
    pub fn sync_deposits(
        &self,
        existing_utxos: &HashMap<OutPoint, CachedVault>,
    ) -> Result<
        (
            HashMap<OutPoint, CachedVault>,
            HashMap<OutPoint, CachedVault>,
        ),
        BitcoindError,
    > {
        let mut new_utxos = HashMap::new();
        // All seen utxos, if an utxo remains unseen by listunspent then it's spent.
        let mut spent_utxos = existing_utxos.clone();

        for utxo in self
            .make_request("listunspent", &[])?
            .as_array()
            .ok_or_else(|| {
                BitcoindError("API break, 'listunspent' didn't return an array.".to_string())
            })?
        {
            if utxo.get("label") != Some(&serde_json::Value::String(self.deposit_utxos_label())) {
                continue;
            }

            let outpoint = self.outpoint_from_utxo(&utxo)?;
            // Not obvious at first sight:
            //  - spent_utxos == existing_utxos before the loop
            //  - listunspent won't send duplicated entries
            //  - remove() will return None if it was not present in the map, ie new deposit
            if spent_utxos.remove(&outpoint).is_some() {
                continue;
            }

            let address = utxo
                .get("address")
                .ok_or_else(|| {
                    BitcoindError(
                        "API break, 'listunspent' entry didn't contain an 'address'.".to_string(),
                    )
                })?
                .as_str()
                .ok_or_else(|| {
                    BitcoindError(
                        "API break, 'listunspent' entry didn't contain a string 'address'."
                            .to_string(),
                    )
                })?;
            let script_pubkey = Address::from_str(address)
                .map_err(|e| {
                    BitcoindError(format!(
                        "Could not parse 'address' from 'listunspent' entry: {}",
                        e.to_string()
                    ))
                })?
                .script_pubkey();
            let amount = utxo
                .get("amount")
                .ok_or_else(|| {
                    BitcoindError(
                        "API break, 'listunspent' entry didn't contain an 'amount'.".to_string(),
                    )
                })?
                .as_f64()
                .ok_or_else(|| {
                    BitcoindError(
                        "API break, 'listunspent' entry didn't contain a valid 'amount'."
                            .to_string(),
                    )
                })?;
            let value = Amount::from_btc(amount)
                .map_err(|e| {
                    BitcoindError(format!(
                        "Could not convert 'listunspent' entry's 'amount' to an Amount: {}",
                        e.to_string()
                    ))
                })?
                .as_sat();

            log::trace!(
                "Got a new deposit at {:#?} for address {} ({} sats)",
                &outpoint,
                &address,
                &value
            );
            new_utxos.insert(
                outpoint,
                CachedVault {
                    txo: TxOut {
                        value,
                        script_pubkey,
                    },
                    status: VaultStatus::Funded,
                },
            );
        }

        Ok((new_utxos, spent_utxos))
    }

    /// Get the raw transaction as hex, and the blockheight it was included in if
    /// it's confirmed.
    pub fn get_wallet_transaction(
        &self,
        txid: Txid,
    ) -> Result<(String, Option<u32>), BitcoindError> {
        let res = self.make_request(
            "gettransaction",
            &[serde_json::Value::String(txid.to_string())],
        )?;
        let tx_hex = res
            .get("hex")
            .ok_or_else(|| {
                BitcoindError(format!(
                    "API break: no 'hex' in 'gettransaction' result (txid: {})",
                    txid
                ))
            })?
            .as_str()
            .ok_or_else(|| BitcoindError("API break: 'hex' is not a string ????".to_string()))?
            .to_string();
        let blockheight = res.get("blockheight").map(|bh| bh.as_u64().unwrap() as u32);

        Ok((tx_hex, blockheight))
    }

    // This assumes wallet transactions, will error otherwise !
    fn previous_outpoints(&self, outpoint: &OutPoint) -> Result<Vec<OutPoint>, BitcoindError> {
        Ok(self
            .make_request(
                "gettransaction",
                &[
                    serde_json::Value::String(outpoint.txid.to_string()),
                    serde_json::Value::Bool(true), // include_watchonly
                    serde_json::Value::Bool(true), // verbose
                ],
            )?
            .get("decoded")
            .ok_or_else(|| {
                BitcoindError(
                    "API break: 'gettransaction' has no 'hex' in verbose mode?".to_string(),
                )
            })?
            .get("vin")
            .ok_or_else(|| BitcoindError("API break: 'gettransaction' has no 'vin' ?".to_string()))?
            .as_array()
            .ok_or_else(|| {
                BitcoindError("API break: 'gettransaction' 'vin' isn't an array?".to_string())
            })?
            .into_iter()
            .filter_map(|txin| {
                Some(OutPoint {
                    txid: Txid::from_str(txin.get("txid")?.as_str()?).ok()?,
                    vout: txin.get("vout")?.as_u64()? as u32,
                })
            })
            .collect())
    }

    /// There is no good way to get the "spending transaction" from an utxo in bitcoind.
    /// So here we workaround it leveraging the fact we know the unvault address. So we list
    /// the unvault address transactions and check if one spent this outpoint to this address.
    pub fn unvault_from_vault(
        &self,
        vault_outpoint: &OutPoint,
        unvault_address: String,
    ) -> Result<Option<OutPoint>, BitcoindError> {
        let res = self.make_request(
            "listunspent",
            &[
                serde_json::Value::Number(serde_json::Number::from(0)), // minconf
                serde_json::Value::Number(serde_json::Number::from(9999999)), // maxconf (default)
                serde_json::Value::Array(vec![serde_json::Value::String(unvault_address)]),
            ],
        )?;
        let utxos = res.as_array().ok_or_else(|| {
            BitcoindError("API break: 'listunspent' didn't return an array".to_string())
        })?;

        for utxo in utxos {
            let outpoint = self.outpoint_from_utxo(&utxo)?;
            for prev_outpoint in self.previous_outpoints(&outpoint)? {
                if &prev_outpoint == vault_outpoint {
                    return Ok(Some(outpoint));
                }
            }
        }

        Ok(None)
    }
}
