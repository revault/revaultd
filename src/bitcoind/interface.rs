use crate::config::BitcoindConfig;

use std::fs;

use jsonrpc::{client::Client, simple_rtt::Tripper, Request, Response};

#[derive(PartialEq, Eq, Debug)]
pub struct BitcoindError(pub String);

impl std::fmt::Display for BitcoindError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Bitcoind error: {}", self.0)
    }
}

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
        let resp = self
            .client
            .send_request(&req)
            .map_err(|e| BitcoindError(format!("Sending request: {}", e.to_string())))?;
        let res = resp
            .into_result()
            .map_err(|e| BitcoindError(format!("Making request: {}", e.to_string())))?;

        Ok(res)
    }

    pub fn getblockchaininfo(&self) -> Result<serde_json::Value, BitcoindError> {
        self.make_request("getblockchaininfo", &[])
    }
}
