use crate::config::{config_folder_path, BitcoindConfig, Config, ConfigError, OurSelves};

use std::fs;
use std::path::PathBuf;
use std::vec::Vec;

use revault_tx::{
    bitcoin::{util::bip32::ChildNumber, Network},
    miniscript::descriptor::DescriptorPublicKey,
    scripts::{
        unvault_cpfp_descriptor, unvault_descriptor, vault_descriptor, CpfpDescriptor,
        UnvaultDescriptor, VaultDescriptor,
    },
};

/// Our global state
pub struct RevaultD {
    /// We store all our data in one place, that's here.
    pub data_dir: PathBuf,

    /// Everything we need to know to talk to bitcoind
    pub bitcoind_config: BitcoindConfig,

    /// Who am i, and where am i in all this mess ?
    pub ourselves: OurSelves,
    /// The miniscript descriptor of vault's outputs scripts
    pub vault_descriptor: VaultDescriptor<DescriptorPublicKey>,
    /// The miniscript descriptor of unvault's outputs scripts
    pub unvault_descriptor: UnvaultDescriptor<DescriptorPublicKey>,
    /// The miniscript descriptor of unvault's CPFP output scripts
    pub unvault_cpfp_descriptor: CpfpDescriptor<DescriptorPublicKey>,
    /// We don't make an enormous deal of address reuse (we cancel to the same keys),
    /// however we at least try to generate new addresses once they're used.
    // FIXME: think more about desync reconciliation..
    pub current_unused_index: u32,
    // TODO: servers connection stuff

    // TODO: RPC server stuff

    // TODO: Coin tracking stuff
}

impl RevaultD {
    /// Creates our global state by consuming the static configuration
    pub fn from_config(config: Config) -> Result<RevaultD, Box<dyn std::error::Error>> {
        let managers_pubkeys: Vec<DescriptorPublicKey> =
            config.managers.into_iter().map(|m| m.xpub).collect();

        let mut stakeholders_pubkeys = Vec::with_capacity(config.stakeholders.len());
        let mut cosigners_pubkeys = stakeholders_pubkeys.clone();
        for non_manager in config.stakeholders.into_iter() {
            stakeholders_pubkeys.push(non_manager.xpub);
            cosigners_pubkeys.push(non_manager.cosigner_key);
        }

        let vault_descriptor = vault_descriptor(
            managers_pubkeys
                .iter()
                .chain(stakeholders_pubkeys.iter())
                .cloned()
                .collect::<Vec<DescriptorPublicKey>>(),
        )?;

        let unvault_descriptor = unvault_descriptor(
            stakeholders_pubkeys,
            managers_pubkeys.clone(),
            managers_pubkeys.len(),
            cosigners_pubkeys,
            config.unvault_csv,
        )?;

        let unvault_cpfp_descriptor = unvault_cpfp_descriptor(managers_pubkeys)?;

        let data_dir = config.data_dir.unwrap_or(config_folder_path()?);
        if !data_dir.as_path().exists() {
            if let Err(e) = fs::create_dir_all(&data_dir) {
                return Err(Box::from(ConfigError(format!(
                    "Could not create data dir '{:?}': {}.",
                    data_dir,
                    e.to_string()
                ))));
            }
        }

        Ok(RevaultD {
            vault_descriptor,
            unvault_descriptor,
            unvault_cpfp_descriptor,
            data_dir,
            bitcoind_config: config.bitcoind_config,
            ourselves: config.ourselves,
            // Will be updated by the database
            current_unused_index: 0,
        })
    }

    fn file_from_datadir(&self, file_name: &str) -> PathBuf {
        let data_dir_str = self
            .data_dir
            .to_str()
            .expect("Impossible: the datadir path is valid unicode");

        [data_dir_str, file_name].iter().collect()
    }

    fn vault_address(&self, child_number: u32) -> String {
        let network = match self.bitcoind_config.network.as_str() {
            "main" => Network::Bitcoin,
            "test" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => unreachable!("Network is checked at startup"),
        };

        self.vault_descriptor
            .derive(ChildNumber::from(child_number))
            .0
            .address(network)
            .expect("vault_descriptor is a wsh")
            .to_string()
    }

    pub fn log_file(&self) -> PathBuf {
        self.file_from_datadir("log")
    }

    pub fn pid_file(&self) -> PathBuf {
        self.file_from_datadir("revaultd.pid")
    }

    pub fn db_file(&self) -> PathBuf {
        self.file_from_datadir("revaultd.sqlite3")
    }

    pub fn watchonly_wallet_file(&self, wallet_id: u32) -> PathBuf {
        self.file_from_datadir(&format!("revaultd-watchonly-wallet-{}", wallet_id))
    }

    pub fn deposit_address(&self) -> String {
        self.vault_address(self.current_unused_index)
    }

    /// All deposit addresses up to the gap limit (100)
    pub fn all_deposit_addresses(&self) -> Vec<String> {
        (0..self.current_unused_index + 100)
            .map(|index| self.vault_address(index))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::RevaultD;
    use crate::config::{parse_config, Config};

    use std::path::PathBuf;

    #[test]
    fn test_from_config() {
        let mut path = PathBuf::from(file!());
        path = path.parent().unwrap().to_path_buf();
        path.push("../test_data/valid_config.toml");

        let config: Config = parse_config(Some(path)).expect("Parsing valid config file");
        RevaultD::from_config(config).expect("Creating state from config");
        // TODO: test actual fields..
    }
}
