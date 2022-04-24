use crate::{
    config::{config_folder_path, BitcoindConfig, Config},
    StartupError,
};

use std::{
    collections::HashMap,
    convert::TryFrom,
    fmt, fs,
    io::{self, Read, Write},
    iter::FromIterator,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time,
    vec::Vec,
};

use revault_net::{
    noise::{PublicKey as NoisePubKey, SecretKey as NoisePrivKey},
    sodiumoxide::{self, crypto::scalarmult::curve25519},
};
use revault_tx::{
    bitcoin::{
        secp256k1,
        util::bip32::{self, ChildNumber, ExtendedPrivKey, ExtendedPubKey},
        Address, BlockHash, Network, PublicKey as BitcoinPublicKey, Script,
    },
    miniscript::descriptor::{DescriptorPublicKey, DescriptorTrait},
    scripts::{
        CpfpDescriptor, DepositDescriptor, DerivedCpfpDescriptor, DerivedDepositDescriptor,
        DerivedUnvaultDescriptor, EmergencyAddress, UnvaultDescriptor,
    },
};

const CPFP_SEED_FILE_SIZE: usize = 32;

/// The status of a [Vault], depends both on the block chain and the set of pre-signed
/// transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaultStatus {
    /// The deposit transaction has less than 6 confirmations
    Unconfirmed,
    /// The deposit transaction has more than 6 confirmations
    Funded,
    /// The revocation transactions are signed by us
    Securing,
    /// The revocation transactions are signed by everyone
    Secured,
    /// The unvault transaction is signed (implies that the second emergency and the
    /// cancel transaction are signed).
    Activating,
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
            2 => Ok(Self::Securing),
            3 => Ok(Self::Secured),
            4 => Ok(Self::Activating),
            5 => Ok(Self::Active),
            6 => Ok(Self::Unvaulting),
            7 => Ok(Self::Unvaulted),
            8 => Ok(Self::Canceling),
            9 => Ok(Self::Canceled),
            10 => Ok(Self::EmergencyVaulting),
            11 => Ok(Self::EmergencyVaulted),
            12 => Ok(Self::UnvaultEmergencyVaulting),
            13 => Ok(Self::UnvaultEmergencyVaulted),
            14 => Ok(Self::Spending),
            15 => Ok(Self::Spent),
            _ => Err(()),
        }
    }
}

impl FromStr for VaultStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unconfirmed" => Ok(Self::Unconfirmed),
            "funded" => Ok(Self::Funded),
            "securing" => Ok(Self::Securing),
            "secured" => Ok(Self::Secured),
            "activating" => Ok(Self::Activating),
            "active" => Ok(Self::Active),
            "unvaulting" => Ok(Self::Unvaulting),
            "unvaulted" => Ok(Self::Unvaulted),
            "canceling" => Ok(Self::Canceling),
            "canceled" => Ok(Self::Canceled),
            "emergencyvaulting" => Ok(Self::EmergencyVaulting),
            "emergencyvaulted" => Ok(Self::EmergencyVaulted),
            "unvaultemergencyvaulting" => Ok(Self::UnvaultEmergencyVaulting),
            "unvaultemergencyvaulted" => Ok(Self::UnvaultEmergencyVaulted),
            "spending" => Ok(Self::Spending),
            "spent" => Ok(Self::Spent),
            _ => Err(format!("Unknown status: {}", s)),
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
                Self::Securing => "securing",
                Self::Secured => "secured",
                Self::Activating => "activating",
                Self::Active => "active",
                Self::Unvaulting => "unvaulting",
                Self::Unvaulted => "unvaulted",
                Self::Canceling => "canceling",
                Self::Canceled => "canceled",
                Self::EmergencyVaulting => "emergencyvaulting",
                Self::EmergencyVaulted => "emergencyvaulted",
                Self::UnvaultEmergencyVaulting => "unvaultemergencyvaulting",
                Self::UnvaultEmergencyVaulted => "unvaultemergencyvaulted",
                Self::Spending => "spending",
                Self::Spent => "spent",
            }
        )
    }
}

/// An error related to the initialization of communication keys.
#[derive(Debug)]
pub enum NoiseKeyError {
    ReadingKey(io::Error),
    WritingKey(io::Error),
}

impl fmt::Display for NoiseKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ReadingKey(e) => write!(f, "Error reading Noise key: '{}'", e),
            Self::WritingKey(e) => write!(f, "Error writing Noise key: '{}'", e),
        }
    }
}

impl std::error::Error for NoiseKeyError {}

/// An error related to the initialization of the CPFP private key.
#[derive(Debug)]
pub enum CpfpKeyError {
    InvalidSeedFile,
    ReadingSeed(io::Error),
    InvalidSeed(bip32::Error),
    KeyNotInDescriptor(String),
}

impl fmt::Display for CpfpKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidSeedFile => write!(f, "Invalid CPFP seed file"),
            Self::ReadingSeed(e) => write!(f, "Error reading CPFP seed: '{}'", e),
            Self::InvalidSeed(e) => write!(f, "Invalid CPFP seed: '{}'", e),
            Self::KeyNotInDescriptor(s) => {
                write!(
                    f,
                    "The key provided is not present in the CPFP descriptor: {}",
                    s
                )
            }
        }
    }
}

impl std::error::Error for CpfpKeyError {}

// The communication keys are (for now) hot, so we just create it ourselves on first run.
fn read_or_create_noise_key(secret_file: PathBuf) -> Result<NoisePrivKey, NoiseKeyError> {
    let mut noise_secret = NoisePrivKey([0; 32]);

    if !secret_file.as_path().exists() {
        log::info!(
            "No Noise private key at '{:?}', generating a new one",
            secret_file
        );
        noise_secret = sodiumoxide::crypto::box_::gen_keypair().1;

        // We create it in read-only but open it in write only.
        let mut options = fs::OpenOptions::new();
        options = options.write(true).create_new(true).clone();
        // FIXME: handle Windows ACLs
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options = options.mode(0o400).clone();
        }

        let mut fd = options
            .open(secret_file)
            .map_err(NoiseKeyError::WritingKey)?;
        fd.write_all(noise_secret.as_ref())
            .map_err(NoiseKeyError::WritingKey)?;
    } else {
        let mut noise_secret_fd = fs::File::open(secret_file).map_err(NoiseKeyError::ReadingKey)?;
        noise_secret_fd
            .read_exact(&mut noise_secret.0)
            .map_err(NoiseKeyError::ReadingKey)?;
    }

    // TODO: have a decent memory management and mlock() the key

    assert!(noise_secret.0 != [0; 32]);
    Ok(noise_secret)
}

// Read the CPFP extended private key from the BIP32 seed stored in the given file.
fn read_cpfp_key(
    secret_file: PathBuf,
    network: Network,
) -> Result<Option<ExtendedPrivKey>, CpfpKeyError> {
    // No file? No key :)
    let mut cpfp_secret_fd = match fs::File::open(secret_file) {
        Ok(fd) => fd,
        Err(_) => return Ok(None),
    };

    if cpfp_secret_fd
        .metadata()
        .map_err(CpfpKeyError::ReadingSeed)?
        .len()
        != CPFP_SEED_FILE_SIZE as u64
    {
        return Err(CpfpKeyError::InvalidSeedFile);
    }

    let mut seed_buffer = [0; CPFP_SEED_FILE_SIZE];
    cpfp_secret_fd
        .read_exact(&mut seed_buffer)
        .map_err(CpfpKeyError::ReadingSeed)?;

    ExtendedPrivKey::new_master(network, &seed_buffer)
        .map_err(CpfpKeyError::InvalidSeed)
        .map(Option::Some)
}

/// Information about the last block in the chain.
#[derive(Debug, PartialEq, Copy, Clone)]
pub struct BlockchainTip {
    pub height: u32,
    pub hash: BlockHash,
}

#[derive(Debug, Clone)]
pub enum UserRole {
    Stakeholder,
    Manager,
    StakeholderManager,
}

impl FromStr for UserRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "stakeholder" => Ok(Self::Stakeholder),
            "stakeholdermanager" => Ok(Self::StakeholderManager),
            "manager" => Ok(Self::Manager),
            _ => Err(format!("Unknown role: {}", s)),
        }
    }
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Self::Stakeholder => "stakeholder",
                Self::Manager => "manager",
                Self::StakeholderManager => "stakeholdermanager",
            }
        )
    }
}

/// Our global state
pub struct RevaultD {
    // Bitcoind stuff
    /// Everything we need to know to talk to bitcoind
    pub bitcoind_config: BitcoindConfig,
    /// Last block we heard about
    pub tip: Option<BlockchainTip>,
    /// Minimum confirmations before considering a deposit as mature
    pub min_conf: u32,

    // Scripts stuff
    /// Who am i, and where am i in all this mess ?
    pub our_stk_xpub: Option<ExtendedPubKey>,
    pub our_man_xpub: Option<ExtendedPubKey>,
    /// The miniscript descriptor of vault's outputs scripts
    pub deposit_descriptor: DepositDescriptor,
    /// The miniscript descriptor of unvault's outputs scripts
    pub unvault_descriptor: UnvaultDescriptor,
    /// The miniscript descriptor of CPFP output scripts (in unvault and spend transaction)
    pub cpfp_descriptor: CpfpDescriptor,
    /// The Emergency address, only available if we are a stakeholder
    pub emergency_address: Option<EmergencyAddress>,
    /// We don't make an enormous deal of address reuse (we cancel to the same keys),
    /// however we at least try to generate new addresses once they're used.
    // FIXME: think more about desync reconciliation..
    pub current_unused_index: ChildNumber,
    /// The secp context required by the xpub one.. We'll eventually use it to verify keys.
    pub secp_ctx: secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    /// The locktime to use on all created transaction. Always 0 for now.
    pub lock_time: u32,
    /// CPFP private key to fee-bump Unvault and Spend transactions.
    /// In the absence of the key file in the data directory, the automated CPFP mechanism
    /// is silently disabled.
    pub cpfp_key: Option<ExtendedPrivKey>,

    // Network stuff
    /// The static private key we use to establish connections to servers. We reuse it, but Trevor
    /// said it's fine! https://github.com/noiseprotocol/noise_spec/blob/master/noise.md#14-security-considerations
    pub noise_secret: NoisePrivKey,
    /// The ip:port the coordinator is listening on. TODO: Tor
    pub coordinator_host: SocketAddr,
    /// The static public key to enact the Noise channel with the Coordinator
    pub coordinator_noisekey: NoisePubKey,
    pub coordinator_poll_interval: time::Duration,
    /// The ip:port (TODO: Tor) and Noise public key of each cosigning server, only set if we are
    /// a manager.
    pub cosigs: Option<Vec<(SocketAddr, NoisePubKey)>>,
    /// The ip:port (TODO: Tor) and Noise public key of each watchtower, only set if we are
    /// a stakeholder.
    pub watchtowers: Option<Vec<(SocketAddr, NoisePubKey)>>,

    // 'Wallet' stuff
    /// A map from a scriptPubKey to a derivation index. Used to retrieve the actual public
    /// keys used to generate a script from bitcoind until we can pass it xpub-expressed
    /// Miniscript descriptors.
    pub derivation_index_map: HashMap<Script, ChildNumber>,
    /// The id of the wallet used in the db
    pub wallet_id: Option<u32>,

    // Misc stuff
    /// We store all our data in one place, that's here.
    pub data_dir: PathBuf,
    /// Should we run as a daemon? (Default: yes)
    pub daemon: bool,
    // TODO: servers connection stuff
}

fn create_datadir(datadir_path: &Path) -> Result<(), DatadirError> {
    #[cfg(unix)]
    return {
        use fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = DirBuilder::new();
        builder
            .mode(0o700)
            .recursive(true)
            .create(datadir_path)
            .map_err(|e| DatadirError::CreateDatadir(datadir_path.to_path_buf(), e.to_string()))
    };

    #[cfg(not(unix))]
    return {
        // FIXME: make Windows secure (again?)
        fs::create_dir_all(datadir_path)
            .map_err(|e| DatadirError::CreateDatadir(datadir_path.to_path_buf(), e.to_string()))
    };
}

#[derive(Debug)]
pub enum DatadirError {
    CreateDatadir(PathBuf, String),
    DefaultNotFound,
}

impl fmt::Display for DatadirError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::CreateDatadir(path, e) => {
                write!(f, "Could not create data directory '{:?}': {}", path, e)
            }
            Self::DefaultNotFound => write!(f, "Could not locate the default data directory "),
        }
    }
}

impl std::error::Error for DatadirError {}

#[derive(Debug)]
pub enum ChecksumError {
    Checksum(String),
}

impl fmt::Display for ChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Checksum(e) => {
                write!(f, "Error computing checksum: {}", e)
            }
        }
    }
}

impl std::error::Error for ChecksumError {}

const INPUT_CHARSET: &str =  "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn poly_mod(mut c: u64, val: u64) -> u64 {
    let c0 = c >> 35;

    c = ((c & 0x7ffffffff) << 5) ^ val;
    if c0 & 1 > 0 {
        c ^= 0xf5dee51989
    };
    if c0 & 2 > 0 {
        c ^= 0xa9fdca3312
    };
    if c0 & 4 > 0 {
        c ^= 0x1bab10e32d
    };
    if c0 & 8 > 0 {
        c ^= 0x3706b1677a
    };
    if c0 & 16 > 0 {
        c ^= 0x644d626ffd
    };

    c
}

/// Compute the checksum of a descriptor
/// Note that this function does not check if the
/// descriptor string is syntactically correct or not.
/// This only computes the checksum
pub fn desc_checksum(desc: &str) -> Result<String, ChecksumError> {
    let mut c = 1;
    let mut cls = 0;
    let mut clscount = 0;

    for ch in desc.chars() {
        let pos = INPUT_CHARSET
            .find(ch)
            .ok_or(ChecksumError::Checksum(format!(
                "Invalid character in checksum: '{}'",
                ch
            )))? as u64;
        c = poly_mod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        clscount += 1;
        if clscount == 3 {
            c = poly_mod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if clscount > 0 {
        c = poly_mod(c, cls);
    }
    (0..8).for_each(|_| c = poly_mod(c, 0));
    c ^= 1;

    let mut chars = Vec::with_capacity(8);
    for j in 0..8 {
        chars.push(
            CHECKSUM_CHARSET
                .chars()
                .nth(((c >> (5 * (7 - j))) & 31) as usize)
                .unwrap(),
        );
    }

    Ok(String::from_iter(chars))
}

impl RevaultD {
    /// Creates our global state by consuming the static configuration
    pub fn from_config(config: Config) -> Result<RevaultD, StartupError> {
        let our_man_xpub = config.manager_config.as_ref().map(|x| x.xpub);
        let our_stk_xpub = config.stakeholder_config.as_ref().map(|x| x.xpub);
        // Config should have checked that!
        assert!(our_man_xpub.is_some() || our_stk_xpub.is_some());

        let deposit_descriptor = config.scripts_config.deposit_descriptor;
        let unvault_descriptor = config.scripts_config.unvault_descriptor;
        let cpfp_descriptor = config.scripts_config.cpfp_descriptor;
        let emergency_address = config
            .stakeholder_config
            .clone()
            .map(|x| x.emergency_address);

        let mut data_dir = config
            .data_dir
            .unwrap_or(config_folder_path().ok_or(DatadirError::DefaultNotFound)?);
        data_dir.push(config.bitcoind_config.network.to_string());
        if !data_dir.as_path().exists() {
            create_datadir(&data_dir)?;
        }
        data_dir = fs::canonicalize(data_dir)?;

        let data_dir_str = data_dir
            .to_str()
            .expect("Impossible: the datadir path is valid unicode");
        let noise_secret_file = [data_dir_str, "noise_secret"].iter().collect();
        let noise_secret = read_or_create_noise_key(noise_secret_file)?;

        let cpfp_key = if our_man_xpub.is_some() {
            let cpfp_key_file = [data_dir_str, "cpfp_secret"].iter().collect();
            let net = if config.bitcoind_config.network == Network::Bitcoin {
                Network::Bitcoin
            } else {
                Network::Testnet
            };
            let key = read_cpfp_key(cpfp_key_file, net)?;
            if let Some(key) = key {
                // Checking if the key is in the cpfp descriptor
                let secp_ctx = secp256k1::Secp256k1::signing_only();
                let pubkey = ExtendedPubKey::from_private(&secp_ctx, &key);
                cpfp_descriptor
                    .xpubs()
                    .iter()
                    .find(|k| {
                        if let DescriptorPublicKey::XPub(k) = k {
                            k.xkey == pubkey
                        } else {
                            unreachable!();
                        }
                    })
                    .ok_or_else(|| CpfpKeyError::KeyNotInDescriptor(pubkey.to_string()))?;
            } else {
                log::warn!(
                    "CPFP key not found, consider creating a cpfp_secret file in the datadir. \
                    Automated CPFP won't be available."
                );
            }
            key
        } else {
            None
        };

        let coordinator_noisekey = config.coordinator_noise_key;
        let coordinator_poll_interval = config.coordinator_poll_seconds;

        let cosigs = config.manager_config.map(|config| {
            config
                .cosigners
                .into_iter()
                .map(|config| (config.host, config.noise_key))
                .collect()
        });

        let watchtowers = config.stakeholder_config.map(|config| {
            config
                .watchtowers
                .into_iter()
                .map(|config| (config.host, config.noise_key))
                .collect()
        });

        let daemon = !matches!(config.daemon, Some(false));

        let secp_ctx = secp256k1::Secp256k1::verification_only();

        Ok(RevaultD {
            our_stk_xpub,
            our_man_xpub,
            deposit_descriptor,
            unvault_descriptor,
            cpfp_descriptor,
            secp_ctx,
            data_dir,
            daemon,
            emergency_address,
            noise_secret,
            coordinator_host: config.coordinator_host,
            coordinator_noisekey,
            coordinator_poll_interval,
            cosigs,
            watchtowers,
            lock_time: 0,
            cpfp_key,
            min_conf: config.min_conf,
            bitcoind_config: config.bitcoind_config,
            tip: None,
            // Will be updated by the database
            current_unused_index: ChildNumber::from(0),
            // FIXME: we don't need SipHash for those, use a faster alternative
            derivation_index_map: HashMap::new(),
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

    /// Our Noise static public key
    pub fn noise_pubkey(&self) -> NoisePubKey {
        let scalar = curve25519::Scalar(self.noise_secret.0);
        NoisePubKey(curve25519::scalarmult_base(&scalar).0)
    }

    /// vault (deposit) address descriptor with checksum in canonical form (e.g.
    /// 'addr(ADDRESS)#CHECKSUM') for importing with bitcoind
    pub fn vault_desc(&self, child_number: ChildNumber) -> Result<String, ChecksumError> {
        let addr_desc = format!("addr({})", self.vault_address(child_number));
        Ok(format!("{}#{}", addr_desc, desc_checksum(&addr_desc)?))
    }

    pub fn vault_address(&self, child_number: ChildNumber) -> Address {
        self.deposit_descriptor
            .derive(child_number, &self.secp_ctx)
            .inner()
            .address(self.bitcoind_config.network)
            .expect("deposit_descriptor is a wsh")
    }

    /// unvault address descriptor with checksum in canonical form (e.g.
    /// 'addr(ADDRESS)#CHECKSUM') for importing with bitcoind
    pub fn unvault_desc(&self, child_number: ChildNumber) -> Result<String, ChecksumError> {
        let addr_desc = format!("addr({})", self.unvault_address(child_number));
        Ok(format!("{}#{}", addr_desc, desc_checksum(&addr_desc)?))
    }

    pub fn unvault_address(&self, child_number: ChildNumber) -> Address {
        self.unvault_descriptor
            .derive(child_number, &self.secp_ctx)
            .inner()
            .address(self.bitcoind_config.network)
            .expect("unvault_descriptor is a wsh")
    }

    pub fn cpfp_address(&self, child_number: ChildNumber) -> Address {
        self.cpfp_descriptor
            .derive(child_number, &self.secp_ctx)
            .inner()
            .address(self.bitcoind_config.network)
            .expect("cpfp_descriptor is a wsh")
    }

    pub fn gap_limit(&self) -> u32 {
        100
    }

    pub fn watchonly_wallet_name(&self) -> Option<String> {
        self.wallet_id
            .map(|ref id| format!("revaultd-watchonly-wallet-{}", id))
    }

    pub fn cpfp_wallet_name(&self) -> Option<String> {
        self.wallet_id
            .map(|ref id| format!("revaultd-cpfp-wallet-{}", id))
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

    pub fn cpfp_wallet_file(&self) -> Option<String> {
        self.cpfp_wallet_name().map(|ref name| {
            self.file_from_datadir(name)
                .to_str()
                .expect("Valid utf-8")
                .to_string()
        })
    }

    pub fn rpc_socket_file(&self) -> PathBuf {
        self.file_from_datadir("revaultd_rpc")
    }

    pub fn is_stakeholder(&self) -> bool {
        self.our_stk_xpub.is_some()
    }

    pub fn is_manager(&self) -> bool {
        self.our_man_xpub.is_some()
    }

    pub fn deposit_address(&self) -> Address {
        self.vault_address(self.current_unused_index)
    }

    pub fn last_deposit_desc(&self) -> Result<String, ChecksumError> {
        let raw_index: u32 = self.current_unused_index.into();
        // FIXME: this should fail instead of creating a hardened index
        self.vault_desc(ChildNumber::from(raw_index + self.gap_limit()))
    }

    pub fn last_deposit_address(&self) -> Address {
        let raw_index: u32 = self.current_unused_index.into();
        // FIXME: this should fail instead of creating a hardened index
        self.vault_address(ChildNumber::from(raw_index + self.gap_limit()))
    }

    pub fn last_unvault_desc(&self) -> Result<String, ChecksumError> {
        let raw_index: u32 = self.current_unused_index.into();
        // FIXME: this should fail instead of creating a hardened index
        self.unvault_desc(ChildNumber::from(raw_index + self.gap_limit()))
    }

    pub fn last_unvault_address(&self) -> Address {
        let raw_index: u32 = self.current_unused_index.into();
        // FIXME: this should fail instead of creating a hardened index
        self.unvault_address(ChildNumber::from(raw_index + self.gap_limit()))
    }

    /// All deposit address descriptors as strings up to the gap limit (100)
    pub fn all_deposit_descriptors(&mut self) -> Vec<String> {
        self.derivation_index_map
            .values()
            .map(|child_num| {
                self.vault_desc(ChildNumber::from(*child_num))
                    .expect("Failed checksum computation")
            })
            .collect()
    }

    /// All unvault address descriptors as strings up to the gap limit (100)
    pub fn all_unvault_descriptors(&mut self) -> Vec<String> {
        let raw_index: u32 = self.current_unused_index.into();
        (0..raw_index + self.gap_limit())
            .map(|raw_index| {
                // FIXME: this should fail instead of creating a hardened index
                self.unvault_desc(ChildNumber::from(raw_index))
                    .expect("Failed to comput checksum")
            })
            .collect()
    }

    pub fn derived_deposit_descriptor(&self, index: ChildNumber) -> DerivedDepositDescriptor {
        self.deposit_descriptor.derive(index, &self.secp_ctx)
    }

    pub fn derived_unvault_descriptor(&self, index: ChildNumber) -> DerivedUnvaultDescriptor {
        self.unvault_descriptor.derive(index, &self.secp_ctx)
    }

    pub fn derived_cpfp_descriptor(&self, index: ChildNumber) -> DerivedCpfpDescriptor {
        self.cpfp_descriptor.derive(index, &self.secp_ctx)
    }

    pub fn stakeholders_xpubs(&self) -> Vec<DescriptorPublicKey> {
        self.deposit_descriptor.xpubs()
    }

    pub fn managers_xpubs(&self) -> Vec<DescriptorPublicKey> {
        // The managers' xpubs are all the xpubs from the Unvault descriptor except the
        // Stakehodlers' ones and the Cosigning Servers' ones.
        let stk_xpubs = self.stakeholders_xpubs();
        self.unvault_descriptor
            .xpubs()
            .into_iter()
            .filter(|xpub| {
                match xpub {
                    DescriptorPublicKey::SinglePub(_) => false, // Cosig
                    DescriptorPublicKey::XPub(_) => {
                        // Either Manager or Stakeholder
                        !stk_xpubs.contains(xpub)
                    }
                }
            })
            .collect()
    }

    pub fn stakeholders_xpubs_at(&self, index: ChildNumber) -> Vec<BitcoinPublicKey> {
        self.deposit_descriptor
            .xpubs()
            .into_iter()
            .map(|desc_xpub| {
                desc_xpub
                    .derive(index.into())
                    .derive_public_key(&self.secp_ctx)
                    .expect("Is derived, and there is never any hardened path")
            })
            .collect()
    }

    pub fn our_stk_xpub_at(&self, index: ChildNumber) -> Option<BitcoinPublicKey> {
        self.our_stk_xpub.map(|xpub| {
            xpub.derive_pub(&self.secp_ctx, &[index])
                .expect("The derivation index stored in the database is sane (unhardened)")
                .public_key
        })
    }

    pub fn managers_threshold(&self) -> usize {
        self.unvault_descriptor
            .managers_threshold()
            .unwrap_or(self.managers_xpubs().len())
    }
}

#[cfg(test)]
mod tests {
    use super::RevaultD;
    use crate::config::Config;

    use std::path::PathBuf;

    #[test]
    fn test_from_config() {
        let mut path = PathBuf::from(file!()).parent().unwrap().to_path_buf();

        path.push("../test_data/invalid_config.toml");
        Config::from_file(Some(path.clone())).expect_err("Parsing invalid config file");

        path.pop();
        path.push("invalid_config_network.toml");
        assert!(Config::from_file(Some(path.clone()))
            .unwrap_err()
            .to_string()
            .contains("Our bitcoin network is signet but one xpub has network bitcoin"));

        path.pop();
        path.push("valid_config_man.toml");
        let config = Config::from_file(Some(path.clone())).expect("Parsing valid config file");
        RevaultD::from_config(config).expect("Creating state from config");

        path.pop();
        path.push("valid_config_stake.toml");
        let config = Config::from_file(Some(path)).expect("Parsing valid config file");
        RevaultD::from_config(config).expect("Creating state from config");
        // TODO: test actual fields..
    }
}
