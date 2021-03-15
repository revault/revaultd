use std::{net::SocketAddr, path::PathBuf, str::FromStr, time::Duration, vec::Vec};

use revault_net::noise::PublicKey as NoisePubkey;
use revault_tx::{
    bitcoin::{hashes::hex::FromHex, util::bip32, Network, PublicKey as BitcoinPubkey},
    miniscript::descriptor::{DescriptorPublicKey, DescriptorSinglePub, DescriptorXKey},
    scripts::EmergencyAddress,
};

use serde::{de, Deserialize, Deserializer};

fn xpub_to_desc_xpub(xkey: bip32::ExtendedPubKey) -> DescriptorPublicKey {
    DescriptorPublicKey::XPub(DescriptorXKey {
        origin: None,
        xkey,
        derivation_path: bip32::DerivationPath::from(vec![]),
        is_wildcard: true,
    })
}

fn deserialize_xpubs<'de, D>(deserializer: D) -> Result<Vec<DescriptorPublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let xpubs = Vec::<bip32::ExtendedPubKey>::deserialize(deserializer)?;
    Ok(xpubs.into_iter().map(xpub_to_desc_xpub).collect())
}

fn key_to_desc_key(key: BitcoinPubkey) -> DescriptorPublicKey {
    DescriptorPublicKey::SinglePub(DescriptorSinglePub { origin: None, key })
}

fn deserialize_single_keys<'de, D>(deserializer: D) -> Result<Vec<DescriptorPublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let xpubs = Vec::<BitcoinPubkey>::deserialize(deserializer)?;
    Ok(xpubs.into_iter().map(key_to_desc_key).collect())
}

fn deserialize_noisepubkey<'de, D>(deserializer: D) -> Result<NoisePubkey, D::Error>
where
    D: Deserializer<'de>,
{
    let data = String::deserialize(deserializer)?;
    FromHex::from_hex(&data)
        .map_err(|e| de::Error::custom(e))
        .map(NoisePubkey)
}

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    Ok(Duration::from_secs(secs))
}

fn deserialize_loglevel<'de, D>(deserializer: D) -> Result<log::LevelFilter, D::Error>
where
    D: Deserializer<'de>,
{
    let level_str = String::deserialize(deserializer)?;
    log::LevelFilter::from_str(&level_str).map_err(de::Error::custom)
}

fn default_loglevel() -> log::LevelFilter {
    log::LevelFilter::Info
}

fn default_poll_interval() -> Duration {
    Duration::from_secs(30)
}

fn default_sig_poll_interval() -> Duration {
    Duration::from_secs(60)
}

/// Everything we need to know for talking to bitcoind serenely
#[derive(Debug, Clone, Deserialize)]
pub struct BitcoindConfig {
    /// The network we are operating on, one of "bitcoin", "testnet", "regtest"
    pub network: Network,
    /// Path to bitcoind's cookie file, to authenticate the RPC connection
    pub cookie_path: PathBuf,
    /// The IP:port bitcoind's RPC is listening on
    pub addr: SocketAddr,
    /// The poll interval for bitcoind
    #[serde(
        deserialize_with = "deserialize_duration",
        default = "default_poll_interval"
    )]
    pub poll_interval_secs: Duration,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WatchtowerConfig {
    pub host: String,
    pub noise_key: String,
}

/// If we are a stakeholder, we need to connect to our watchtower(s)
#[derive(Debug, Clone, Deserialize)]
pub struct StakeholderConfig {
    pub xpub: bip32::ExtendedPubKey,
    pub watchtowers: Vec<WatchtowerConfig>,
    pub emergency_address: EmergencyAddress,
}

// Same fields as the WatchtowerConfig struct for now, but leave them separate.
#[derive(Debug, Clone, Deserialize)]
pub struct CosignerConfig {
    pub host: String,
    pub noise_key: String,
}

/// If we are a manager, we need to connect to cosigning servers
#[derive(Debug, Clone, Deserialize)]
pub struct ManagerConfig {
    pub xpub: bip32::ExtendedPubKey,
    pub cosigners: Vec<CosignerConfig>,
}

/// Static informations we require to operate
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Everything we need to know to talk to bitcoind
    pub bitcoind_config: BitcoindConfig,
    /// Some() if we are a stakeholder
    pub stakeholder_config: Option<StakeholderConfig>,
    /// Some() if we are a manager
    pub manager_config: Option<ManagerConfig>,
    /// The stakeholders' xpubs
    #[serde(deserialize_with = "deserialize_xpubs")]
    pub stakeholders_xpubs: Vec<DescriptorPublicKey>,
    /// The cosigners' static public keys (must be as many as stakeholders'
    /// xpubs)
    #[serde(deserialize_with = "deserialize_single_keys")]
    pub cosigners_keys: Vec<DescriptorPublicKey>,
    /// The managers' xpubs
    #[serde(deserialize_with = "deserialize_xpubs")]
    pub managers_xpubs: Vec<DescriptorPublicKey>,
    /// The unvault output scripts relative timelock
    pub unvault_csv: u32,
    /// The host of the sync server (may be an IP or a hidden service)
    pub coordinator_host: String,
    /// The Noise static public key of the sync server
    #[serde(deserialize_with = "deserialize_noisepubkey")]
    pub coordinator_noise_key: NoisePubkey,
    /// The poll intervals for signature fetching (default: 1min)
    #[serde(
        deserialize_with = "deserialize_duration",
        default = "default_sig_poll_interval"
    )]
    pub coordinator_poll_seconds: Duration,
    /// An optional custom data directory
    pub data_dir: Option<PathBuf>,
    /// Whether to daemonize the process
    pub daemon: Option<bool>,
    /// What messages to log
    #[serde(
        deserialize_with = "deserialize_loglevel",
        default = "default_loglevel"
    )]
    pub log_level: log::LevelFilter,
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
/// It's a "revault/<network>/" directory in the XDG standard configuration directory for
/// all OSes but Linux-based ones, for which it's `~/.revault/<network>/`.
/// There is only one config file at `revault/config.toml`, which specifies the network.
/// Rationale: we want to have the database, RPC socket, etc.. in the same folder as the
/// configuration file but for Linux the XDG specifoes a data directory (`~/.local/share/`)
/// different from the configuration one (`~/.config/`).
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
    config_folder_path().map(|mut path| {
        path.push("revault.toml");
        path
    })
}

impl Config {
    /// Get our static configuration out of a mandatory configuration file.
    ///
    /// We require all settings to be set in the configuration file, and only in the configuration
    /// file. We don't allow to set them via the command line or environment variables to avoid a
    /// futile duplication.
    pub fn from_file(custom_path: Option<PathBuf>) -> Result<Config, ConfigError> {
        let config_file = custom_path.unwrap_or(config_file_path()?);

        let config = std::fs::read(&config_file)
            .map_err(|e| ConfigError(format!("Reading configuration file: {}", e)))
            .and_then(|file_content| {
                toml::from_slice::<Config>(&file_content)
                    .map_err(|e| ConfigError(format!("Parsing configuration file: {}", e)))
            })?;

        if config.stakeholder_config.is_none() && config.manager_config.is_none() {
            return Err(ConfigError(format!(
                r#"At least one "stakeholder_config" or "manager_config" must be present"#
            )));
        }

        if config.stakeholders_xpubs.len() != config.cosigners_keys.len() {
            return Err(ConfigError(format!(
                r#"Not as much "stakeholders_xpubs" ({}) as "cosigners_keys" ({})"#,
                config.stakeholders_xpubs.len(),
                config.cosigners_keys.len()
            )));
        }

        if let Some(ref stk_config) = config.stakeholder_config {
            let our_desc_xpub = DescriptorPublicKey::XPub(DescriptorXKey {
                origin: None,
                xkey: stk_config.xpub.clone(),
                derivation_path: bip32::DerivationPath::from(vec![]),
                is_wildcard: true,
            });

            if !config
                .stakeholders_xpubs
                .iter()
                .any(|x| x == &our_desc_xpub)
            {
                return Err(ConfigError(format!(
                    r#"Our "stakeholder_config" xpub is not part of the given stakeholders' xpubs: {}"#,
                    stk_config.xpub
                )));
            }

            let emer_addr_net = stk_config.emergency_address.address().network;
            let bitcoind_net = config.bitcoind_config.network;
            if emer_addr_net != bitcoind_net {
                return Err(ConfigError(format!(
                    r#"Our "emergency_address" is for '{}' but bitcoind is on '{}'"#,
                    emer_addr_net, bitcoind_net
                )));
            }
        }

        if let Some(ref man_config) = config.manager_config {
            let our_desc_xpub = DescriptorPublicKey::XPub(DescriptorXKey {
                origin: None,
                xkey: man_config.xpub.clone(),
                derivation_path: bip32::DerivationPath::from(vec![]),
                is_wildcard: true,
            });

            if !config.managers_xpubs.iter().any(|x| x == &our_desc_xpub) {
                return Err(ConfigError(format!(
                    r#"Our "manager_config" xpub is not part of the given managers' xpubs: {}"#,
                    man_config.xpub
                )));
            }
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::{config_file_path, Config};

    // Test the format of the configuration file
    #[test]
    fn deserialize_toml_config() {
        // A valid stakeholder config
        let toml_str = r#"
            daemon = false
            log_level = "trace"
            data_dir = "/home/wizardsardine/custom/folder/"

            coordinator_host = "127.0.0.1:1"
            coordinator_noise_key = "d91563973102454a7830137e92d0548bc83b4ea2799f1df04622ca1307381402"

            stakeholders_xpubs = [
                    "xpub6BHATNyFVsBD8MRygTsv2q9WFTJzEB3o6CgJK7sjopcB286bmWFkNYm6kK5fzVe2gk4mJrSK5isFSFommNDST3RYJWSzrAe9V4bEzboHqnA",
                    "xpub6AP3nZhB34Zoan3KCL9bAdnwNHdzMbskLudpbchwTfkHwnNDXYf1769gzozjgzDNUF7iwa5nCdhE5byrcx5PDKFCUDByeuqiHa382EKhcay",
                    "xpub6AUkrYoAoySUXnEbspdqL7dJ5qE4n5wTDAXb22tzNaU9cKqpeE6Tjvh5gkXECrX8bGM2Ndgk3HYYVmD7m3NyHxS74NRi1cuq9ddxmhG8RxP",
                    "xpub6AL6oiHLkP5bDMry27vH7uethb1g8iTysk5MZJvNe1yBv5fedvqqgiaPS2riWCiu4o3H8xinEVdQ5zz8pZKH1RtjTbdQyxHsMMCBrp2PP8S"
            ]
            cosigners_keys = [
                    "02644cf9e2b78feb0a751e50502f530a4cbd0bbda3020779605391e71654dd66c2",
                    "03ced55d1208bd8c6b42b11e29baa577711cae831b3a1296607c5e5d3ed365f49c",
                    "026237f655f3bf45fd6b7aa00e91c2603d6155f1cc001e40f5e47662d965c4c779",
                    "030a3cbcfbfdf7122fe7fa830354c956ea6595f2dbde23286f03bc1ec0c1685ca3"
            ]
            managers_xpubs = [
                    "xpub6AtVcKWPpZ9t3Aa3VvzWid1dzJFeXPfNntPbkGsYjNrp7uhXpzSL5QVMCmaHqUzbVUGENEwbBbzF9E8emTxQeP3AzbMjfzvwSDkwUrxg2G4",
                    "xpub6AMXQWzNN9GSrWk5SeKdEUK6Ntha87BBtprp95EGSsLiMkUedYcHh53P3J1frsnMqRSssARq6EdRnAJmizJMaBqxCrA3MVGjV7d9wNQAEtm"
            ]
            unvault_csv = 42

            [bitcoind_config]
            network = "bitcoin"
            cookie_path = "/home/user/.bitcoin/.cookie"
            addr = "127.0.0.1:8332"
            poll_interval_secs = 18

            # We are one of the above stakeholders
            [stakeholder_config]
            xpub = "xpub6AP3nZhB34Zoan3KCL9bAdnwNHdzMbskLudpbchwTfkHwnNDXYf1769gzozjgzDNUF7iwa5nCdhE5byrcx5PDKFCUDByeuqiHa382EKhcay"
            watchtowers = [ { host = "127.0.0.1:1", noise_key = "46084f8a7da40ef7ffc38efa5af8a33a742b90f920885d17c533bb2a0b680cb3" } ]
            emergency_address = "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"
        "#;
        toml::from_str::<Config>(toml_str).expect("Deserializing stakeholder toml_str");

        // A valid manager config
        let toml_str = r#"
            daemon = false
            log_level = "trace"
            data_dir = "/home/wizardsardine/custom/folder/"

            coordinator_host = "127.0.0.1:1"
            coordinator_noise_key = "d91563973102454a7830137e92d0548bc83b4ea2799f1df04622ca1307381402"

            stakeholders_xpubs = [
                    "xpub6BHATNyFVsBD8MRygTsv2q9WFTJzEB3o6CgJK7sjopcB286bmWFkNYm6kK5fzVe2gk4mJrSK5isFSFommNDST3RYJWSzrAe9V4bEzboHqnA",
                    "xpub6AP3nZhB34Zoan3KCL9bAdnwNHdzMbskLudpbchwTfkHwnNDXYf1769gzozjgzDNUF7iwa5nCdhE5byrcx5PDKFCUDByeuqiHa382EKhcay",
                    "xpub6AUkrYoAoySUXnEbspdqL7dJ5qE4n5wTDAXb22tzNaU9cKqpeE6Tjvh5gkXECrX8bGM2Ndgk3HYYVmD7m3NyHxS74NRi1cuq9ddxmhG8RxP",
                    "xpub6AL6oiHLkP5bDMry27vH7uethb1g8iTysk5MZJvNe1yBv5fedvqqgiaPS2riWCiu4o3H8xinEVdQ5zz8pZKH1RtjTbdQyxHsMMCBrp2PP8S"
            ]
            cosigners_keys = [
                    "02644cf9e2b78feb0a751e50502f530a4cbd0bbda3020779605391e71654dd66c2",
                    "03ced55d1208bd8c6b42b11e29baa577711cae831b3a1296607c5e5d3ed365f49c",
                    "026237f655f3bf45fd6b7aa00e91c2603d6155f1cc001e40f5e47662d965c4c779",
                    "030a3cbcfbfdf7122fe7fa830354c956ea6595f2dbde23286f03bc1ec0c1685ca3"
            ]
            managers_xpubs = [
                    "xpub6AtVcKWPpZ9t3Aa3VvzWid1dzJFeXPfNntPbkGsYjNrp7uhXpzSL5QVMCmaHqUzbVUGENEwbBbzF9E8emTxQeP3AzbMjfzvwSDkwUrxg2G4",
                    "xpub6AMXQWzNN9GSrWk5SeKdEUK6Ntha87BBtprp95EGSsLiMkUedYcHh53P3J1frsnMqRSssARq6EdRnAJmizJMaBqxCrA3MVGjV7d9wNQAEtm"
            ]
            unvault_csv = 42

            [bitcoind_config]
            network = "bitcoin"
            cookie_path = "/home/user/.bitcoin/.cookie"
            addr = "127.0.0.1:8332"
            poll_interval_secs = 4

            # We are one of the above managers
            [manager_config]
            xpub = "xpub6AtVcKWPpZ9t3Aa3VvzWid1dzJFeXPfNntPbkGsYjNrp7uhXpzSL5QVMCmaHqUzbVUGENEwbBbzF9E8emTxQeP3AzbMjfzvwSDkwUrxg2G4"
            cosigners = [ { host = "127.0.0.1:1", noise_key = "087629614d227ff2b9ed5f2ce2eb7cd527d2d18f866b24009647251fce58de38" } ]
        "#;
        toml::from_str::<Config>(toml_str).expect("Deserializing manager toml_str");

        // A valid sakeholder-manager config
        let toml_str = r#"
            daemon = false
            log_level = "trace"
            data_dir = "/home/wizardsardine/custom/folder/"

            coordinator_host = "127.0.0.1:1"
            coordinator_noise_key = "d91563973102454a7830137e92d0548bc83b4ea2799f1df04622ca1307381402"

            stakeholders_xpubs = [
                    "xpub6BHATNyFVsBD8MRygTsv2q9WFTJzEB3o6CgJK7sjopcB286bmWFkNYm6kK5fzVe2gk4mJrSK5isFSFommNDST3RYJWSzrAe9V4bEzboHqnA",
                    "xpub6AP3nZhB34Zoan3KCL9bAdnwNHdzMbskLudpbchwTfkHwnNDXYf1769gzozjgzDNUF7iwa5nCdhE5byrcx5PDKFCUDByeuqiHa382EKhcay",
                    "xpub6AUkrYoAoySUXnEbspdqL7dJ5qE4n5wTDAXb22tzNaU9cKqpeE6Tjvh5gkXECrX8bGM2Ndgk3HYYVmD7m3NyHxS74NRi1cuq9ddxmhG8RxP",
                    "xpub6AL6oiHLkP5bDMry27vH7uethb1g8iTysk5MZJvNe1yBv5fedvqqgiaPS2riWCiu4o3H8xinEVdQ5zz8pZKH1RtjTbdQyxHsMMCBrp2PP8S"
            ]
            cosigners_keys = [
                    "02644cf9e2b78feb0a751e50502f530a4cbd0bbda3020779605391e71654dd66c2",
                    "03ced55d1208bd8c6b42b11e29baa577711cae831b3a1296607c5e5d3ed365f49c",
                    "026237f655f3bf45fd6b7aa00e91c2603d6155f1cc001e40f5e47662d965c4c779",
                    "030a3cbcfbfdf7122fe7fa830354c956ea6595f2dbde23286f03bc1ec0c1685ca3"
            ]
            managers_xpubs = [
                    "xpub6AtVcKWPpZ9t3Aa3VvzWid1dzJFeXPfNntPbkGsYjNrp7uhXpzSL5QVMCmaHqUzbVUGENEwbBbzF9E8emTxQeP3AzbMjfzvwSDkwUrxg2G4",
                    "xpub6AMXQWzNN9GSrWk5SeKdEUK6Ntha87BBtprp95EGSsLiMkUedYcHh53P3J1frsnMqRSssARq6EdRnAJmizJMaBqxCrA3MVGjV7d9wNQAEtm"
            ]
            unvault_csv = 42

            [bitcoind_config]
            network = "bitcoin"
            cookie_path = "/home/user/.bitcoin/.cookie"
            addr = "127.0.0.1:8332"
            poll_interval_secs = 12

            # We are one of the above managers
            [manager_config]
            xpub = "xpub6AtVcKWPpZ9t3Aa3VvzWid1dzJFeXPfNntPbkGsYjNrp7uhXpzSL5QVMCmaHqUzbVUGENEwbBbzF9E8emTxQeP3AzbMjfzvwSDkwUrxg2G4"
            cosigners = [ { host = "127.0.0.1:1", noise_key = "087629614d227ff2b9ed5f2ce2eb7cd527d2d18f866b24009647251fce58de38" } ]
            # We are one of the above stakeholders
            [stakeholder_config]
            xpub = "xpub6AP3nZhB34Zoan3KCL9bAdnwNHdzMbskLudpbchwTfkHwnNDXYf1769gzozjgzDNUF7iwa5nCdhE5byrcx5PDKFCUDByeuqiHa382EKhcay"
            watchtowers = [ { host = "127.0.0.1:1", noise_key = "46084f8a7da40ef7ffc38efa5af8a33a742b90f920885d17c533bb2a0b680cb3" } ]
            emergency_address = "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"
        "#;
        toml::from_str::<Config>(toml_str).expect("Deserializing stakeholder-manager toml_str");

        // Not enough parameters
        let toml_str = r#"
            daemon = false
            log_level = "trace"
            data_dir = "/home/wizardsardine/custom/folder/"

            coordinator_host = "127.0.0.1:1"
            coordinator_noise_key = "d91563973102454a7830137e92d0548bc83b4ea2799f1df04622ca1307381402"
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
