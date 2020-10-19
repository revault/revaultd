use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::vec::Vec;

use revault_tx::miniscript::descriptor::DescriptorPublicKey;
use serde::{de, Deserialize, Deserializer};

/// Everything we need to know for talking to bitcoind serenely
#[derive(Debug, Deserialize, Clone)]
pub struct BitcoindConfig {
    /// The network we are operating on, one of "mainnet", "testnet", "regtest"
    pub network: String,
    /// Path to bitcoind's cookie file, to authenticate the RPC connection
    // TODO: think more about our potential need for the datadir
    pub cookie_path: PathBuf,
    /// The IP:port bitcoind's RPC is listening on
    pub addr: SocketAddr,
}

/// A participant not taking part in day-to-day fund management, and who runs
/// a cosigning server to ensure that spending transactions are only signed once.
#[derive(Debug)]
pub struct NonManager {
    /// The master extended public key of this participant
    pub xpub: DescriptorPublicKey,
    /// The cosigning server's static public key
    pub cosigner_key: DescriptorPublicKey,
    // TODO: cosigner's address
}

impl<'de> Deserialize<'de> for NonManager {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map = HashMap::<String, String>::deserialize(deserializer)?;

        let (xpub_str, cosigner_key_str) = (map.get("xpub"), map.get("cosigner_key"));
        if xpub_str == None || cosigner_key_str == None {
            return Err(de::Error::custom(
                r#"Non-manager entries need both a "xpub" and a "cosigner_key""#,
            ));
        }

        let xpub = DescriptorPublicKey::from_str(&xpub_str.unwrap());
        if let Err(ref e) = xpub {
            return Err(de::Error::custom(e.to_owned()));
        }

        let cosigner_key = DescriptorPublicKey::from_str(&cosigner_key_str.unwrap());
        if let Err(ref e) = cosigner_key {
            return Err(de::Error::custom(e.to_owned()));
        }

        Ok(NonManager {
            xpub: xpub.unwrap(),
            cosigner_key: cosigner_key.unwrap(),
        })
    }
}

/// A participant taking part in day-to-day fund management.
#[derive(Debug)]
pub struct Manager {
    pub xpub: DescriptorPublicKey,
}

impl<'de> Deserialize<'de> for Manager {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map = HashMap::<String, String>::deserialize(deserializer)?;

        let xpub_str = map.get("xpub");
        if xpub_str == None {
            return Err(de::Error::custom(r#"No "xpub" for manager entry."#));
        }

        let xpub = DescriptorPublicKey::from_str(&xpub_str.unwrap());
        if let Err(ref e) = xpub {
            return Err(de::Error::custom(e.to_owned()));
        }

        Ok(Manager {
            xpub: xpub.unwrap(),
        })
    }
}

/// Our own informations
#[derive(Debug, Clone)]
pub struct OurSelves {
    /// Our own master extended key, used to retrieve for which keys we can sign
    xpub: DescriptorPublicKey,
    // TODO: our watchtower's address
}

impl<'de> Deserialize<'de> for OurSelves {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map = HashMap::<String, String>::deserialize(deserializer)?;

        let xpub_str = map.get("xpub");
        if xpub_str == None {
            return Err(de::Error::custom(r#"No "xpub" for "ourselves" entry."#));
        }

        let xpub = DescriptorPublicKey::from_str(&xpub_str.unwrap());
        if let Err(ref e) = xpub {
            return Err(de::Error::custom(e.to_owned()));
        }

        Ok(OurSelves {
            xpub: xpub.unwrap(),
        })
    }
}

/// Static informations we require to operate
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Everything we need to know to talk to bitcoind
    pub bitcoind_config: BitcoindConfig,
    /// Who am i, and where am i in all this mess ?
    pub ourselves: OurSelves,
    /// The managers' xpubs
    pub managers: Vec<Manager>,
    /// The non-managers' xpubs
    pub non_managers: Vec<NonManager>,
    /// The unvault output scripts relative timelock
    pub unvault_csv: u32,
    /// An optional custom data directory
    pub data_dir: Option<PathBuf>,
    // TODO: sync server address
}

#[derive(PartialEq, Eq, Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Configuration error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Get the absolute path to the revault configuration folder.
///
/// This a "revault" directory in the XDG standard configuration directory for all OSes but
/// Linux-based ones, for which it's `~/.revault`.
/// Rationale: we want to have the database, RPC socket, etc.. in the same folder as the
/// configuration file but for Linux the XDG specify a data directory (`~/.local/share/`) different
/// from the configuration one (`~/.config/`).
pub fn config_folder_path() -> Result<PathBuf, ConfigError> {
    #[cfg(target_os = "linux")]
    let configs_dir = dirs::home_dir();

    #[cfg(not(target_os = "linux"))]
    let configs_dir = dirs::config_dir();

    if let Some(mut path) = configs_dir {
        #[cfg(target_os = "linux")]
        path.push(".revault");

        #[cfg(not(target_os = "linux"))]
        path.push("Revault");

        return Ok(path);
    }

    Err(ConfigError(
        "Could not locate the configuration directory.".to_owned(),
    ))
}

fn config_file_path() -> Result<PathBuf, ConfigError> {
    config_folder_path().and_then(|mut path| {
        path.push("revault.toml");
        Ok(path)
    })
}

/// Get our static configuration out of a mandatory configuration file.
///
/// We require all settings to be set in the configuration file, and only in the configuration
/// file. We don't allow to set them via the command line or environment variables to avoid a
/// futile duplication.
pub fn parse_config(custom_path: Option<PathBuf>) -> Result<Config, ConfigError> {
    let config_file = custom_path.unwrap_or(config_file_path()?);

    std::fs::read(&config_file)
        .map_err(|e| ConfigError(format!("Reading configuration file: {}", e)))
        .and_then(|file_content| {
            toml::from_slice::<Config>(&file_content)
                .map_err(|e| ConfigError(format!("Parsing configuration file: {}", e)))
        })
}

#[cfg(test)]
mod tests {
    use super::{config_file_path, Config};

    // Test the format of the configuration file
    #[test]
    fn deserialize_toml_config() {
        // A valid config
        let toml_str = r#"
            unvault_csv = 42

            data_dir = "/home/wizardsardine/custom/folder/"

            [bitcoind_config]
            network = "bitcoin"
            cookie_path = "/home/user/.bitcoin/.cookie"
            addr = "127.0.0.1:8332"

            # Our own informations
            [ourselves]
            xpub = "xpub6A662oAj5Kjk53U7GjfCGKCT6jJsChstkxbbWBVyVUyzYcayw7PLjJQk9H9g2pryTqhGDTNo8DRNZm1zGzZ7ywzbMgRHRYyfydCd4yjepHs"

            [[managers]]
            xpub = "xpub6AtVcKWPpZ9t3Aa3VvzWid1dzJFeXPfNntPbkGsYjNrp7uhXpzSL5QVMCmaHqUzbVUGENEwbBbzF9E8emTxQeP3AzbMjfzvwSDkwUrxg2G4"
            [[managers]]
            xpub = "xpub6AMXQWzNN9GSrWk5SeKdEUK6Ntha87BBtprp95EGSsLiMkUedYcHh53P3J1frsnMqRSssARq6EdRnAJmizJMaBqxCrA3MVGjV7d9wNQAEtm"

            [[non_managers]]
            xpub = "xpub6BHATNyFVsBD8MRygTsv2q9WFTJzEB3o6CgJK7sjopcB286bmWFkNYm6kK5fzVe2gk4mJrSK5isFSFommNDST3RYJWSzrAe9V4bEzboHqnA"
            cosigner_key = "02644cf9e2b78feb0a751e50502f530a4cbd0bbda3020779605391e71654dd66c2"
            [[non_managers]]
            xpub = "xpub6AP3nZhB34Zoan3KCL9bAdnwNHdzMbskLudpbchwTfkHwnNDXYf1769gzozjgzDNUF7iwa5nCdhE5byrcx5PDKFCUDByeuqiHa382EKhcay"
            cosigner_key = "03ced55d1208bd8c6b42b11e29baa577711cae831b3a1296607c5e5d3ed365f49c"
            [[non_managers]]
            xpub = "xpub6AUkrYoAoySUXnEbspdqL7dJ5qE4n5wTDAXb22tzNaU9cKqpeE6Tjvh5gkXECrX8bGM2Ndgk3HYYVmD7m3NyHxS74NRi1cuq9ddxmhG8RxP"
            cosigner_key = "026237f655f3bf45fd6b7aa00e91c2603d6155f1cc001e40f5e47662d965c4c779"
            [[non_managers]]
            xpub = "xpub6AL6oiHLkP5bDMry27vH7uethb1g8iTysk5MZJvNe1yBv5fedvqqgiaPS2riWCiu4o3H8xinEVdQ5zz8pZKH1RtjTbdQyxHsMMCBrp2PP8S"
            cosigner_key = "030a3cbcfbfdf7122fe7fa830354c956ea6595f2dbde23286f03bc1ec0c1685ca3"
        "#;
        let _config: Config = toml::from_str(toml_str).expect("Deserializing toml_str");

        // Not enough parameters
        let toml_str = r#"
            network = "bitcoin"

            # Our master extended keys
            our_xpub = "xpub6A662oAj5Kjk53U7GjfCGKCT6jJsChstkxbbWBVyVUyzYcayw7PLjJQk9H9g2pryTqhGDTNo8DRNZm1zGzZ7ywzbMgRHRYyfydCd4yjepHs"

            [[managers]]
            xpub = "xpub6AtVcKWPpZ9t3Aa3VvzWid1dzJFeXPfNntPbkGsYjNrp7uhXpzSL5QVMCmaHqUzbVUGENEwbBbzF9E8emTxQeP3AzbMjfzvwSDkwUrxg2G4"
            [[managers]]
            xpub = "xpub6AMXQWzNN9GSrWk5SeKdEUK6Ntha87BBtprp95EGSsLiMkUedYcHh53P3J1frsnMqRSssARq6EdRnAJmizJMaBqxCrA3MVGjV7d9wNQAEtm"
        "#;
        let config_res: Result<Config, toml::de::Error> = toml::from_str(toml_str);
        config_res.expect_err("Deserializing an invalid toml_str");
    }

    #[test]
    fn config_directory() {
        let filepath = config_file_path().expect("Getting config file path");

        #[cfg(target_os = "linux")]
        {
            assert!(filepath.as_path().starts_with("/home/"));
            assert!(filepath.as_path().ends_with(".revault/revault.toml"));
        }

        #[cfg(target_os = "macos")]
        assert!(filepath
            .as_path()
            .ends_with("Library/Application Support/Revault/revault.toml"));

        #[cfg(target_os = "windows")]
        assert!(filepath
            .as_path()
            .ends_with(r#"AppData\Roaming\Revault\revault.toml"#));
    }
}
