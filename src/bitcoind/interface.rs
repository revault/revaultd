use crate::{bitcoind::BitcoindError, config::BitcoindConfig};

use std::fs;

use jsonrpc::{client::Client, simple_rtt::Tripper};

pub struct BitcoinD {
    // FIXME: do we need to persist the config here ?
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

    pub fn importdescriptor(
        &self,
        desc: String,
        timestamp: u32,
        label: String,
    ) -> Result<(), BitcoindError> {
        let mut desc_map = serde_json::Map::with_capacity(3);
        desc_map.insert("desc".to_string(), serde_json::Value::String(desc));
        // FIXME: set to "now" for first import!
        desc_map.insert(
            "timestamp".to_string(),
            serde_json::Value::Number(serde_json::Number::from(timestamp)),
        );
        desc_map.insert("label".to_string(), serde_json::Value::String(label));

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
            "Error returned from 'importdescriptor': {:?}",
            res.get("error")
        )))
    }
}
