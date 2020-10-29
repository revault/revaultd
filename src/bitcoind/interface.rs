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
}
