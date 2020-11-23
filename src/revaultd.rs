use crate::config::{config_folder_path, BitcoindConfig, Config, ConfigError, OurSelves};

use std::{collections::HashMap, convert::TryFrom, fs, path::PathBuf, vec::Vec};

use revault_tx::{
    bitcoin::{util::bip32::ChildNumber, Address, Network, OutPoint, Script, TxOut},
    miniscript::descriptor::DescriptorPublicKey,
    scripts::{
        unvault_cpfp_descriptor, unvault_descriptor, vault_descriptor, CpfpDescriptor,
        UnvaultDescriptor, VaultDescriptor,
    },
    transactions::{
        CancelTransaction, EmergencyTransaction, UnvaultEmergencyTransaction, UnvaultTransaction,
        VaultTransaction,
    },
};

/// The status of a [Vault], depends both on the block chain and the set of pre-signed
/// transactions
#[derive(Debug, Clone, Copy)]
pub enum VaultStatus {
    // FIXME: More formally analyze the impact of reorgs
    // FIXME: Min confirms ?
    /// The deposit transaction is confirmed
    Funded,
    /// The emergency transaction is signed
    Secured,
    /// The unvault transaction is signed (implies that the second emergency and the
    /// cancel transaction are signed).
    Active,
    /// The unvault transaction has been broadcast
    Unvaulting,
    /// The unvault transaction is confirmed
    Unvaulted,
    /// The cancel transaction has been broadcast
    Canceling,
    /// The cancel transaction is confirmed
    Canceled,
    /// One of the emergency transactions has been broadcast
    EmergencyVaulting,
    /// One of the emergency transactions is confirmed
    EmergencyVaulted,
    /// The unvault transaction CSV is expired
    Spendable,
    /// The spend transaction has been broadcast
    Spending,
    // TODO: At what depth do we forget it ?
    /// The spend transaction is confirmed
    Spent,
}

impl TryFrom<u32> for VaultStatus {
    type Error = ();

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        match n {
            0 => Ok(Self::Funded),
            1 => Ok(Self::Secured),
            2 => Ok(Self::Active),
            3 => Ok(Self::Unvaulting),
            4 => Ok(Self::Unvaulted),
            5 => Ok(Self::Canceling),
            6 => Ok(Self::Canceled),
            7 => Ok(Self::EmergencyVaulting),
            8 => Ok(Self::EmergencyVaulted),
            9 => Ok(Self::Spendable),
            10 => Ok(Self::Spending),
            11 => Ok(Self::Spent),
            _ => Err(()),
        }
    }
}

/// We cache the known vault and their status to avoid too frequent lookups to the DB.
/// This stores the deposit utxo and the status of the vault.
#[derive(Debug, Clone)]
pub struct CachedVault {
    pub txo: TxOut,
    pub status: VaultStatus,
}

/// A vault is defined as a confirmed utxo paying to the Vault Descriptor for which
/// we have a set of pre-signed transaction (emergency, cancel, unvault).
/// Depending on its status we may not yet be in possession of part -or the entirety-
/// of the pre-signed transactions.
/// Likewise, depending on our role (manager or stakeholder), we may not have the
/// emergency transactions.
pub struct Vault {
    /// The deposit utxo and the status of the vault, that we keep in memory
    pub cached_vault: CachedVault,
    pub vault_tx: Option<VaultTransaction>,
    pub emergency_tx: Option<EmergencyTransaction>,
    pub unvault_tx: Option<UnvaultTransaction>,
    pub cancel_tx: Option<CancelTransaction>,
    pub unvault_emergency_tx: Option<UnvaultEmergencyTransaction>,
}

/// Our global state
pub struct RevaultD {
    /// We store all our data in one place, that's here.
    pub data_dir: PathBuf,
    /// Should we run as a daemon? (Default: yes)
    pub daemon: bool,

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

    /// A cache of known vaults by txid
    pub vaults: HashMap<OutPoint, CachedVault>,
    /// A hack, kind of the entire reason why we use Miniscript is to not use patterns
    /// such as what will follow. If you stumble on this after expectations of seeing
    /// revaultd a modern Bitcoin wallet, please just bypass this line. Otherwise, be
    /// brave or help reviewing stuff on bitcoin-core so that we can have modern Bitcoin
    /// stuff there too.
    /// A map from a scriptPubKey to a derivation index. Used to retrieve the actual public
    /// keys used to generate a script from bitcoind while we cannot pass it xpub-expressed
    /// Miniscript descriptors.
    pub derivation_index_map: HashMap<Script, u32>,

    /// The id of the wallet used in the db
    pub wallet_id: u32,

    /// Are we told to stop ?
    pub shutdown: bool,
    // TODO: servers connection stuff
}

fn create_datadir(datadir_path: &PathBuf) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    return {
        use fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = DirBuilder::new();
        builder.mode(0o700).recursive(true).create(datadir_path)
    };

    #[cfg(not(unix))]
    return {
        // FIXME: make Windows secure (again?)
        fs::create_dir_all(datadir_path)
    };
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
            if let Err(e) = create_datadir(&data_dir) {
                return Err(Box::from(ConfigError(format!(
                    "Could not create data dir '{:?}': {}.",
                    data_dir,
                    e.to_string()
                ))));
            }
        }

        let daemon = match config.daemon {
            Some(false) => false,
            _ => true,
        };

        Ok(RevaultD {
            vault_descriptor,
            unvault_descriptor,
            unvault_cpfp_descriptor,
            data_dir,
            daemon,
            bitcoind_config: config.bitcoind_config,
            ourselves: config.ourselves,
            // Will be updated by the database
            current_unused_index: 0,
            // FIXME: we don't need SipHash for those, use a faster alternative
            derivation_index_map: HashMap::new(),
            vaults: HashMap::new(),
            // Will be updated soon (:tm:)
            wallet_id: 0,
            shutdown: false,
        })
    }

    fn file_from_datadir(&self, file_name: &str) -> PathBuf {
        let data_dir_str = self
            .data_dir
            .to_str()
            .expect("Impossible: the datadir path is valid unicode");

        [data_dir_str, file_name].iter().collect()
    }

    fn network(&self) -> Network {
        match self.bitcoind_config.network.as_str() {
            "main" => Network::Bitcoin,
            "test" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => unreachable!("Network is checked at startup"),
        }
    }

    pub fn vault_address(&mut self, child_number: u32) -> Address {
        let addr = self
            .vault_descriptor
            .derive(ChildNumber::from(child_number))
            .0
            .address(self.network())
            .expect("vault_descriptor is a wsh");
        // So we can retrieve it later..
        self.derivation_index_map
            .insert(addr.script_pubkey(), child_number);

        addr
    }

    pub fn unvault_address(&mut self, child_number: u32) -> Address {
        let addr = self
            .unvault_descriptor
            .derive(ChildNumber::from(child_number))
            .0
            .address(self.network())
            .expect("vault_descriptor is a wsh");
        // So we can retrieve it later..
        self.derivation_index_map
            .insert(addr.script_pubkey(), child_number);

        addr
    }

    fn gap_limit(&self) -> u32 {
        100
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

    pub fn rpc_socket_file(&self) -> PathBuf {
        self.file_from_datadir("revaultd_rpc")
    }

    pub fn deposit_address(&mut self) -> Address {
        self.vault_address(self.current_unused_index)
    }

    pub fn last_deposit_address(&mut self) -> Address {
        self.vault_address(self.current_unused_index + self.gap_limit())
    }

    pub fn last_unvault_address(&mut self) -> Address {
        self.unvault_address(self.current_unused_index + self.gap_limit())
    }

    /// All deposit addresses as strings up to the gap limit (100)
    pub fn all_deposit_addresses(&mut self) -> Vec<String> {
        (0..self.current_unused_index + self.gap_limit())
            .map(|index| self.vault_address(index).to_string())
            .collect()
    }

    /// All unvault addresses as strings up to the gap limit (100)
    pub fn all_unvault_addresses(&mut self) -> Vec<String> {
        (0..self.current_unused_index + self.gap_limit())
            .map(|index| self.unvault_address(index).to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::RevaultD;
    use crate::config::Config;

    use std::path::PathBuf;

    #[test]
    fn test_from_config() {
        let mut path = PathBuf::from(file!());
        path = path.parent().unwrap().to_path_buf();
        path.push("../test_data/valid_config.toml");

        let config = Config::from_file(Some(path)).expect("Parsing valid config file");
        RevaultD::from_config(config).expect("Creating state from config");
        // TODO: test actual fields..
    }
}
