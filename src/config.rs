use std::{net::SocketAddr, path::PathBuf, str::FromStr, time::Duration, vec::Vec};

use revault_net::noise::PublicKey as NoisePubkey;
use revault_tx::{
    bitcoin::{hashes::hex::FromHex, util::bip32, Network},
    miniscript::descriptor::{DescriptorPublicKey, DescriptorXKey, Wildcard},
    scripts::{CpfpDescriptor, DepositDescriptor, EmergencyAddress, UnvaultDescriptor},
};

use serde::{de, Deserialize, Deserializer};

fn deserialize_fromstr<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Display,
{
    let string = String::deserialize(deserializer)?;
    T::from_str(&string)
        .map_err(|e| de::Error::custom(format!("Error parsing descriptor '{}': '{}'", string, e)))
}

fn deserialize_noisepubkey<'de, D>(deserializer: D) -> Result<NoisePubkey, D::Error>
where
    D: Deserializer<'de>,
{
    let data = String::deserialize(deserializer)?;
    FromHex::from_hex(&data)
        .map_err(de::Error::custom)
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

fn default_minconf() -> u32 {
    6
}

fn default_cosig_servers() -> Vec<CosignerConfig> {
    vec![]
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
pub struct ScriptsConfig {
    #[serde(deserialize_with = "deserialize_fromstr")]
    pub deposit_descriptor: DepositDescriptor,
    #[serde(deserialize_with = "deserialize_fromstr")]
    pub unvault_descriptor: UnvaultDescriptor,
    #[serde(deserialize_with = "deserialize_fromstr")]
    pub cpfp_descriptor: CpfpDescriptor,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WatchtowerConfig {
    pub host: SocketAddr,
    #[serde(deserialize_with = "deserialize_noisepubkey")]
    pub noise_key: NoisePubkey,
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
    // TODO: Tor
    pub host: SocketAddr,
    #[serde(deserialize_with = "deserialize_noisepubkey")]
    pub noise_key: NoisePubkey,
}

/// If we are a manager, we need to connect to cosigning servers
#[derive(Debug, Clone, Deserialize)]
pub struct ManagerConfig {
    pub xpub: bip32::ExtendedPubKey,
    #[serde(default = "default_cosig_servers")]
    pub cosigners: Vec<CosignerConfig>,
}

/// Static informations we require to operate
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Everything we need to know to talk to bitcoind
    pub bitcoind_config: BitcoindConfig,
    pub scripts_config: ScriptsConfig,
    /// Some() if we are a stakeholder
    pub stakeholder_config: Option<StakeholderConfig>,
    /// Some() if we are a manager
    pub manager_config: Option<ManagerConfig>,
    // TODO: support hidden services
    /// The host of the sync server
    pub coordinator_host: SocketAddr,
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
    /// After how many blocks should we consider a deposit as confirmed?
    #[serde(default = "default_minconf")]
    pub min_conf: u32,
}

#[derive(PartialEq, Eq, Debug)]
pub enum ConfigError {
    DatadirNotFound,
    FileNotFound,
    ReadingFile(String),
    Unexpected(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Self::DatadirNotFound => write!(f, "Could not locate the configuration directory."),
            Self::FileNotFound => write!(f, "Could not locate the configuration file."),
            Self::ReadingFile(e) => write!(f, "Failed to read configuration file: {}", e),
            Self::Unexpected(e) => write!(f, "Configuration error: {}", e),
        }
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => Self::FileNotFound,
            _ => Self::ReadingFile(e.to_string()),
        }
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
pub fn config_folder_path() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    let configs_dir = dirs::home_dir();

    #[cfg(not(target_os = "linux"))]
    let configs_dir = dirs::config_dir();

    if let Some(mut path) = configs_dir {
        #[cfg(target_os = "linux")]
        path.push(".revault");

        #[cfg(not(target_os = "linux"))]
        path.push("Revault");

        return Some(path);
    }

    None
}

fn config_file_path() -> Option<PathBuf> {
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
        let config_file =
            custom_path.unwrap_or(config_file_path().ok_or_else(|| ConfigError::DatadirNotFound)?);

        let config = toml::from_slice::<Config>(&std::fs::read(&config_file)?)
            .map_err(|e| ConfigError::ReadingFile(format!("Parsing configuration file: {}", e)))?;

        let stk_xpubs = config.scripts_config.deposit_descriptor.xpubs();

        // Checking the network of the xpubs in the descriptors
        let mut xpubs = config.scripts_config.deposit_descriptor.xpubs();
        xpubs.append(&mut config.scripts_config.unvault_descriptor.xpubs());
        xpubs.append(&mut config.scripts_config.cpfp_descriptor.xpubs());

        let bitcoind_net = config.bitcoind_config.network;

        for xpub in xpubs {
            if let DescriptorPublicKey::XPub(xpub) = xpub {
                match bitcoind_net {
                    Network::Bitcoin => {
                        if xpub.xkey.network != Network::Bitcoin {
                            return Err(ConfigError::Unexpected(format!(
                                "Our bitcoin network is {} but one xpub has network {}",
                                config.bitcoind_config.network, xpub.xkey.network
                            )));
                        }
                    }
                    _ => {
                        if xpub.xkey.network != Network::Testnet {
                            return Err(ConfigError::Unexpected(format!(
                                "Our bitcoin network is {} but one xpub has network {}",
                                config.bitcoind_config.network, xpub.xkey.network
                            )));
                        }
                    }
                }
            }
        }

        if let Some(ref stk_config) = config.stakeholder_config {
            let our_desc_xpub = DescriptorPublicKey::XPub(DescriptorXKey {
                origin: None,
                xkey: stk_config.xpub,
                derivation_path: bip32::DerivationPath::from(vec![]),
                wildcard: Wildcard::Unhardened,
            });

            if !stk_xpubs.iter().any(|x| x == &our_desc_xpub) {
                return Err(ConfigError::Unexpected(format!(
                    r#"Our "stakeholder_config" xpub is not part of the given stakeholders' xpubs: {}"#,
                    stk_config.xpub
                )));
            }

            let emer_addr_net = stk_config.emergency_address.address().network;
            // Signet addresses have testnet type
            let signet_special_case =
                bitcoind_net == Network::Signet && emer_addr_net == Network::Testnet;
            if emer_addr_net != bitcoind_net && !signet_special_case {
                return Err(ConfigError::Unexpected(format!(
                    r#"Our "emergency_address" is for '{}' but bitcoind is on '{}'"#,
                    emer_addr_net, bitcoind_net
                )));
            }
        }

        if let Some(ref man_config) = config.manager_config {
            let our_desc_xpub = DescriptorPublicKey::XPub(DescriptorXKey {
                origin: None,
                xkey: man_config.xpub,
                derivation_path: bip32::DerivationPath::from(vec![]),
                wildcard: Wildcard::Unhardened,
            });
            let man_xpubs: Vec<DescriptorPublicKey> = config
                .scripts_config
                .unvault_descriptor
                .xpubs()
                .into_iter()
                .filter(|xpub| {
                    match xpub {
                        DescriptorPublicKey::SinglePub(_) => false, // Cosig
                        DescriptorPublicKey::XPub(_) => {
                            // Stakeholder or Manager
                            !stk_xpubs.contains(xpub)
                        }
                    }
                })
                .collect();

            if !man_xpubs.iter().any(|x| x == &our_desc_xpub) {
                return Err(ConfigError::Unexpected(format!(
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

            [scripts_config]
            cpfp_descriptor = "wsh(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)))#cwycq5xu"
            deposit_descriptor = "wsh(multi(2,xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*,xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))#n3cj9mhy"
            unvault_descriptor = "wsh(andor(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)),and_v(v:multi(2,03b506a1dbe57b4bf48c95e0c7d417b87dd3b4349d290d2e7e9ba72c912652d80a,0295e7f5d12a2061f1fd2286cefec592dff656a19f55f4f01305d6aa56630880ce),older(4)),thresh(2,pkh(xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*),a:pkh(xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))))#532k8uvf"

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

            [scripts_config]
            cpfp_descriptor = "wsh(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)))#cwycq5xu"
            deposit_descriptor = "wsh(multi(2,xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*,xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))#n3cj9mhy"
            unvault_descriptor = "wsh(andor(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)),and_v(v:multi(2,03b506a1dbe57b4bf48c95e0c7d417b87dd3b4349d290d2e7e9ba72c912652d80a,0295e7f5d12a2061f1fd2286cefec592dff656a19f55f4f01305d6aa56630880ce),older(4)),thresh(2,pkh(xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*),a:pkh(xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))))#532k8uvf"

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

        // A valid manager config (no cosigning server)
        let toml_str = r#"
            daemon = false
            log_level = "trace"
            data_dir = "/home/wizardsardine/custom/folder/"

            coordinator_host = "127.0.0.1:1"
            coordinator_noise_key = "d91563973102454a7830137e92d0548bc83b4ea2799f1df04622ca1307381402"

            [scripts_config]
            cpfp_descriptor = "wsh(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)))#cwycq5xu"
            deposit_descriptor = "wsh(multi(2,xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*,xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))#n3cj9mhy"
            unvault_descriptor = "wsh(andor(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)),and_v(v:multi(2,03b506a1dbe57b4bf48c95e0c7d417b87dd3b4349d290d2e7e9ba72c912652d80a,0295e7f5d12a2061f1fd2286cefec592dff656a19f55f4f01305d6aa56630880ce),older(4)),thresh(2,pkh(xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*),a:pkh(xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))))#532k8uvf"

            [bitcoind_config]
            network = "bitcoin"
            cookie_path = "/home/user/.bitcoin/.cookie"
            addr = "127.0.0.1:8332"
            poll_interval_secs = 4

            # We are one of the above managers
            [manager_config]
            xpub = "xpub6AtVcKWPpZ9t3Aa3VvzWid1dzJFeXPfNntPbkGsYjNrp7uhXpzSL5QVMCmaHqUzbVUGENEwbBbzF9E8emTxQeP3AzbMjfzvwSDkwUrxg2G4"
        "#;
        toml::from_str::<Config>(toml_str).expect("Deserializing manager toml_str");

        // A valid sakeholder-manager config
        let toml_str = r#"
            daemon = false
            log_level = "trace"
            data_dir = "/home/wizardsardine/custom/folder/"

            coordinator_host = "127.0.0.1:1"
            coordinator_noise_key = "d91563973102454a7830137e92d0548bc83b4ea2799f1df04622ca1307381402"

            [scripts_config]
            cpfp_descriptor = "wsh(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)))#cwycq5xu"
            deposit_descriptor = "wsh(multi(2,xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*,xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))#n3cj9mhy"
            unvault_descriptor = "wsh(andor(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)),and_v(v:multi(2,03b506a1dbe57b4bf48c95e0c7d417b87dd3b4349d290d2e7e9ba72c912652d80a,0295e7f5d12a2061f1fd2286cefec592dff656a19f55f4f01305d6aa56630880ce),older(4)),thresh(2,pkh(xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*),a:pkh(xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))))#532k8uvf"

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

        // Invalid descriptors checksum
        let toml_str = r#"
            daemon = false
            log_level = "trace"
            data_dir = "/home/wizardsardine/custom/folder/"

            coordinator_host = "127.0.0.1:1"
            coordinator_noise_key = "d91563973102454a7830137e92d0548bc83b4ea2799f1df04622ca1307381402"

            [scripts_config]
            cpfp_descriptor = "wsh(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)))#cwycq5xu"
            deposit_descriptor = "wsh(multi(2,xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*,xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))#n3cj9mhy"
            # The checksum is for older(4) but it was replaced by older(42)
            unvault_descriptor = "wsh(andor(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)),and_v(v:multi(2,03b506a1dbe57b4bf48c95e0c7d417b87dd3b4349d290d2e7e9ba72c912652d80a,0295e7f5d12a2061f1fd2286cefec592dff656a19f55f4f01305d6aa56630880ce),older(42)),thresh(2,pkh(xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*),a:pkh(xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))))#532k8uvf"

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
        let config_res: Result<Config, toml::de::Error> = toml::from_str(toml_str);
        config_res.expect_err("Deserializing an invalid toml_str");

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
