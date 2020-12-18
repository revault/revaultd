use common::config::{config_folder_path, BitcoindConfig, Config, ConfigError, OurSelves};

use std::{collections::HashMap, convert::TryFrom, fmt, fs, path::PathBuf, str::FromStr, vec::Vec};

use revault_tx::{
    bitcoin::{secp256k1, util::bip32::ChildNumber, Address, BlockHash, OutPoint, Script, TxOut},
    miniscript::descriptor::{DescriptorPublicKey, DescriptorPublicKeyCtx},
    scripts::{
        cpfp_descriptor, unvault_descriptor, vault_descriptor, CpfpDescriptor, EmergencyAddress,
        UnvaultDescriptor, VaultDescriptor,
    },
    transactions::{
        CancelTransaction, EmergencyTransaction, UnvaultEmergencyTransaction, UnvaultTransaction,
        VaultTransaction,
    },
};

/// The status of a [Vault], depends both on the block chain and the set of pre-signed
/// transactions
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VaultStatus {
    /// The deposit transaction has less than 6 confirmations
    Unconfirmed,
    // FIXME: Do we assume "no reorgs > 6 blocks" ?
    /// The deposit transaction has more than 6 confirmations
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
    /// The first emergency transactions has been broadcast
    EmergencyVaulting,
    /// The first emergency transactions is confirmed
    EmergencyVaulted,
    /// The unvault emergency transactions has been broadcast
    UnvaultEmergencyVaulting,
    /// The unvault emergency transactions is confirmed
    UnvaultEmergencyVaulted,
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
            0 => Ok(Self::Unconfirmed),
            1 => Ok(Self::Funded),
            2 => Ok(Self::Secured),
            3 => Ok(Self::Active),
            4 => Ok(Self::Unvaulting),
            5 => Ok(Self::Unvaulted),
            6 => Ok(Self::Canceling),
            7 => Ok(Self::Canceled),
            8 => Ok(Self::EmergencyVaulting),
            9 => Ok(Self::EmergencyVaulted),
            10 => Ok(Self::UnvaultEmergencyVaulting),
            11 => Ok(Self::UnvaultEmergencyVaulted),
            12 => Ok(Self::Spendable),
            13 => Ok(Self::Spending),
            14 => Ok(Self::Spent),
            _ => Err(()),
        }
    }
}

impl FromStr for VaultStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unconfirmed" => Ok(Self::Unconfirmed),
            "funded" => Ok(Self::Funded),
            "secured" => Ok(Self::Secured),
            "active" => Ok(Self::Active),
            "unvaulting" => Ok(Self::Unvaulting),
            "unvaulted" => Ok(Self::Unvaulted),
            "canceling" => Ok(Self::Canceling),
            "canceled" => Ok(Self::Canceled),
            "emergencyvaulting" => Ok(Self::EmergencyVaulting),
            "emergencyvaulted" => Ok(Self::EmergencyVaulted),
            "unvaultermergencyvaulting" => Ok(Self::UnvaultEmergencyVaulting),
            "unvaultermergencyvaulted" => Ok(Self::UnvaultEmergencyVaulted),
            "spendable" => Ok(Self::Spendable),
            "spending" => Ok(Self::Spending),
            "spent" => Ok(Self::Spent),
            _ => Err(()),
        }
    }
}

impl fmt::Display for VaultStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Self::Unconfirmed => "unconfirmed",
                Self::Funded => "funded",
                Self::Secured => "secured",
                Self::Active => "active",
                Self::Unvaulting => "unvaulting",
                Self::Unvaulted => "unvaulted",
                Self::Canceling => "canceling",
                Self::Canceled => "canceled",
                Self::EmergencyVaulting => "emergencyvaulting",
                Self::EmergencyVaulted => "emergencyvaulted",
                Self::UnvaultEmergencyVaulting => "unvaultermergencyvaulting",
                Self::UnvaultEmergencyVaulted => "unvaultermergencyvaulted",
                Self::Spendable => "spendable",
                Self::Spending => "spending",
                Self::Spent => "spent",
            }
        )
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
pub struct _Vault {
    /// The deposit utxo and the status of the vault, that we keep in memory
    pub cached_vault: CachedVault,
    pub vault_tx: Option<VaultTransaction>,
    pub emergency_tx: Option<EmergencyTransaction>,
    pub unvault_tx: Option<UnvaultTransaction>,
    pub cancel_tx: Option<CancelTransaction>,
    pub unvault_emergency_tx: Option<UnvaultEmergencyTransaction>,
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct BlockchainTip {
    pub height: u32,
    pub hash: BlockHash,
}

/// Our global state
pub struct RevaultD {
    // Bitcoind stuff
    /// Everything we need to know to talk to bitcoind
    pub bitcoind_config: BitcoindConfig,
    /// Last block we heard about
    pub tip: Option<BlockchainTip>,

    // Scripts stuff
    /// Who am i, and where am i in all this mess ?
    pub ourselves: OurSelves,
    /// The miniscript descriptor of vault's outputs scripts
    pub vault_descriptor: VaultDescriptor<DescriptorPublicKey>,
    /// The miniscript descriptor of unvault's outputs scripts
    pub unvault_descriptor: UnvaultDescriptor<DescriptorPublicKey>,
    /// The miniscript descriptor of CPFP output scripts (in unvault and spend transaction)
    pub cpfp_descriptor: CpfpDescriptor<DescriptorPublicKey>,
    pub emergency_address: EmergencyAddress,
    /// We don't make an enormous deal of address reuse (we cancel to the same keys),
    /// however we at least try to generate new addresses once they're used.
    // FIXME: think more about desync reconciliation..
    pub current_unused_index: ChildNumber,
    /// The secp context required by the xpub one.. We'll eventually use it to verify keys.
    pub secp_ctx: secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    /// The locktime to use on all created transaction. Always 0 for now.
    pub lock_time: u32,
    /// The CSV in the unvault_descriptor. Unfortunately segregated from the descriptor..
    pub unvault_csv: u32,

    // UTXOs stuff
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
    pub derivation_index_map: HashMap<Script, ChildNumber>,

    // Misc stuff
    /// The id of the wallet used in the db
    pub wallet_id: Option<u32>,
    /// We store all our data in one place, that's here.
    pub data_dir: PathBuf,
    /// Should we run as a daemon? (Default: yes)
    pub daemon: bool,
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

        let cpfp_descriptor = cpfp_descriptor(managers_pubkeys)?;

        let mut data_dir = config.data_dir.unwrap_or(config_folder_path()?);
        data_dir.push(config.bitcoind_config.network.to_string());
        if !data_dir.as_path().exists() {
            if let Err(e) = create_datadir(&data_dir) {
                return Err(Box::from(ConfigError(format!(
                    "Could not create data dir '{:?}': {}.",
                    data_dir,
                    e.to_string()
                ))));
            }
        }
        data_dir = fs::canonicalize(data_dir)?;

        let daemon = !matches!(config.daemon, Some(false));

        let secp_ctx = secp256k1::Secp256k1::verification_only();

        Ok(RevaultD {
            vault_descriptor,
            unvault_descriptor,
            cpfp_descriptor,
            secp_ctx,
            data_dir,
            daemon,
            emergency_address: config.emergency_address.0,
            lock_time: 0,
            unvault_csv: config.unvault_csv,
            bitcoind_config: config.bitcoind_config,
            tip: None,
            ourselves: config.ourselves,
            // Will be updated by the database
            current_unused_index: ChildNumber::from(0),
            // FIXME: we don't need SipHash for those, use a faster alternative
            derivation_index_map: HashMap::new(),
            vaults: HashMap::new(),
            // Will be updated soon (:tm:)
            wallet_id: None,
        })
    }

    fn file_from_datadir(&self, file_name: &str) -> PathBuf {
        let data_dir_str = self
            .data_dir
            .to_str()
            .expect("Impossible: the datadir path is valid unicode");

        [data_dir_str, file_name].iter().collect()
    }

    /// The context required for deriving keys. We don't use it, as it's redundant with the
    /// descriptor derivation, therefore the ChildNumber is always 0.
    pub fn xpub_ctx(&self) -> DescriptorPublicKeyCtx<'_, secp256k1::VerifyOnly> {
        DescriptorPublicKeyCtx::new(&self.secp_ctx, ChildNumber::from(0))
    }

    pub fn vault_address(&self, child_number: ChildNumber) -> Address {
        self.vault_descriptor
            .derive(child_number)
            .0
            .address(self.bitcoind_config.network, self.xpub_ctx())
            .expect("vault_descriptor is a wsh")
    }

    pub fn unvault_address(&self, child_number: ChildNumber) -> Address {
        self.unvault_descriptor
            .derive(child_number)
            .0
            .address(self.bitcoind_config.network, self.xpub_ctx())
            .expect("vault_descriptor is a wsh")
    }

    pub fn gap_limit(&self) -> u32 {
        100
    }

    pub fn watchonly_wallet_name(&self) -> Option<String> {
        self.wallet_id
            .map(|ref id| format!("revaultd-watchonly-wallet-{}", id))
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

    pub fn watchonly_wallet_file(&self) -> Option<String> {
        self.watchonly_wallet_name().map(|ref name| {
            self.file_from_datadir(name)
                .to_str()
                .expect("Valid utf-8")
                .to_string()
        })
    }

    pub fn rpc_socket_file(&self) -> PathBuf {
        self.file_from_datadir("revaultd_rpc")
    }

    pub fn deposit_address(&self) -> Address {
        self.vault_address(self.current_unused_index)
    }

    pub fn last_deposit_address(&self) -> Address {
        let raw_index: u32 = self.current_unused_index.into();
        // FIXME: this should fail instead of creating a hardened index
        self.vault_address(ChildNumber::from(raw_index + self.gap_limit()))
    }

    pub fn last_unvault_address(&self) -> Address {
        let raw_index: u32 = self.current_unused_index.into();
        // FIXME: this should fail instead of creating a hardened index
        self.unvault_address(ChildNumber::from(raw_index + self.gap_limit()))
    }

    /// All deposit addresses as strings up to the gap limit (100)
    pub fn all_deposit_addresses(&mut self) -> Vec<String> {
        self.derivation_index_map
            .keys()
            .map(|s| {
                Address::from_script(s, self.bitcoind_config.network)
                    .expect("Created from P2WSH address")
                    .to_string()
            })
            .collect()
    }

    /// All unvault addresses as strings up to the gap limit (100)
    pub fn all_unvault_addresses(&mut self) -> Vec<String> {
        let raw_index: u32 = self.current_unused_index.into();
        (0..raw_index + self.gap_limit())
            .map(|raw_index| {
                // FIXME: this should fail instead of creating a hardened index
                self.unvault_address(ChildNumber::from(raw_index))
                    .to_string()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::RevaultD;
    use common::config::Config;

    use std::path::PathBuf;

    #[test]
    fn test_from_config() {
        let mut path = PathBuf::from(file!()).parent().unwrap().to_path_buf();
        path.push("../../test_data/valid_config.toml");

        let config = Config::from_file(Some(path)).expect("Parsing valid config file");
        RevaultD::from_config(config).expect("Creating state from config");
        // TODO: test actual fields..
    }
}
