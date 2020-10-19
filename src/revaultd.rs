use crate::config::{config_folder_path, BitcoindConfig, Config, ConfigError, OurSelves};

use std::fs;
use std::path::PathBuf;
use std::vec::Vec;

use revault_tx::{
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
    /// The miniscript descriptor of vault outputs' scripts
    pub vault_descriptor: VaultDescriptor<DescriptorPublicKey>,
    /// The miniscript descriptor of vault outputs' scripts
    pub unvault_descriptor: UnvaultDescriptor<DescriptorPublicKey>,
    /// The miniscript descriptor of vault outputs' scripts
    pub unvault_cpfp_descriptor: CpfpDescriptor<DescriptorPublicKey>,
    // TODO: servers connection stuff

    // TODO: RPC server stuff

    // TODO: Coin tracking stuff
}

impl RevaultD {
    /// Creates our global state by consuming the static configuration
    pub fn from_config(config: Config) -> Result<RevaultD, Box<dyn std::error::Error>> {
        let managers_pubkeys: Vec<DescriptorPublicKey> =
            config.managers.into_iter().map(|m| m.xpub).collect();

        let mut non_managers_pubkeys = Vec::with_capacity(config.non_managers.len());
        let mut cosigners_pubkeys = non_managers_pubkeys.clone();
        for non_manager in config.non_managers.into_iter() {
            non_managers_pubkeys.push(non_manager.xpub);
            cosigners_pubkeys.push(non_manager.cosigner_key);
        }

        let vault_descriptor = vault_descriptor(
            managers_pubkeys
                .iter()
                .chain(non_managers_pubkeys.iter())
                .cloned()
                .collect::<Vec<DescriptorPublicKey>>(),
        )?;

        let unvault_descriptor = unvault_descriptor(
            non_managers_pubkeys,
            managers_pubkeys.clone(),
            managers_pubkeys.len(),
            cosigners_pubkeys,
            config.unvault_csv,
        )?;

        let unvault_cpfp_descriptor = unvault_cpfp_descriptor(managers_pubkeys)?;

        let data_dir = config.data_dir.unwrap_or(config_folder_path()?);
        if !data_dir.as_path().exists() {
            if let Err(_) = fs::create_dir_all(&data_dir) {
                return Err(Box::from(ConfigError(format!(
                    "Could not create data dir: '{:?}'.",
                    data_dir
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
        })
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
