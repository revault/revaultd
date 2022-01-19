#[cfg(test)]
pub mod test_utils {
    use crate::config::Config;
    use crate::{
        bitcoind::{interface::WalletTransaction, BitcoindError},
        database::interface::db_exec,
        revaultd::{RevaultD, VaultStatus},
        threadmessages::{
            BitcoindMessageOut, BitcoindSender, BitcoindThread, SigFetcherMessageOut,
        },
        DaemonControl,
    };
    use revault_tx::bitcoin::{
        util::bip32::ChildNumber, Amount, OutPoint, Transaction as BitcoinTransaction, Txid,
    };

    use std::{
        collections::HashMap,
        fs,
        path::{Path, PathBuf},
        sync::{mpsc, Arc, RwLock},
        thread,
    };

    use rusqlite::params;

    #[derive(Debug, Clone)]
    pub enum UserRole {
        Stakeholder,
        Manager,
        ManagerStakeholder,
    }

    pub fn test_datadir() -> PathBuf {
        static mut COUNTER: u64 = 0;
        unsafe {
            COUNTER += 1;
            format!("scratch_test_{:?}-{}", std::thread::current().id(), COUNTER).into()
        }
    }

    // Create a RevaultD state instance using a scratch data directory, trying to be portable
    // across UNIX, MacOS, and Windows
    pub fn dummy_revaultd(datadir: PathBuf, role: UserRole) -> RevaultD {
        // TODO directly create RevaultD instead of using conf strings
        let stake_config = r#"
[stakeholder_config]
xpub = "xpub6EKrK11LwLcNyJ4arJnCtxPGAuxSYPX35fMfJcmadvTSue6YZn2W9kEUHy7PFyQsy7zkrbmhxtevsgwsfyCiRBayJdWSTohRQua43jMw9FQ"
watchtowers = [ { host = "127.0.0.1:1", noise_key = "46084f8a7da40ef7ffc38efa5af8a33a742b90f920885d17c533bb2a0b680cb3" } ]
emergency_address = "bcrt1qewc2348370pgw8kjz8gy09z8xyh0d9fxde6nzamd3txc9gkmjqmq8m4cdq"
"#;

        let man_config = r#"
[manager_config]
xpub = "xpub6De9kLSb2vvujzLqBbQvcnfaNfCGv8vBKNikWsvu3yDL6CpdNEE5CKH9J6TpT6ARFsiAdTpH7iJdA8tgAwNeo46FH9CSTv6CURBJSCPAeUu"
cosigners = [ { host = "127.0.0.1:1", noise_key = "087629614d227ff2b9ed5f2ce2eb7cd527d2d18f866b24009647251fce58de38" } ]
"#;

        let mut config = r#"
log_level = "debug"

coordinator_host = "127.0.0.1:1"
coordinator_noise_key = "d91563973102454a7830137e92d0548bc83b4ea2799f1df04622ca1307381402"

[scripts_config]
cpfp_descriptor = "wsh(thresh(1,pk(xpub6BhQvtXJmw6hi2ALFeWMi9m7G8rGterJnMTNRqUm29uvB6dVTELvnEs7hfxyN3JM48FR2oh4t8chsvw7bRRRukkyhqp9WZD4oB9UvxAMpqC/*)))#c6th4le3"
deposit_descriptor = "wsh(multi(2,xpub6EKrK11LwLcNyJ4arJnCtxPGAuxSYPX35fMfJcmadvTSue6YZn2W9kEUHy7PFyQsy7zkrbmhxtevsgwsfyCiRBayJdWSTohRQua43jMw9FQ/*,xpub6BhQvtXJmw6hksh9rRRfdLjaWjQiNMZWtkM5ebn8QkAgh5na2Un6mCDABwkUmHhPCMYtsM9zHY5jxbQ86ayvjfY8XtavbovB6NcNy8KyQLa/*))#wu049esu"
unvault_descriptor = "wsh(andor(thresh(1,pk(xpub6De9kLSb2vvujzLqBbQvcnfaNfCGv8vBKNikWsvu3yDL6CpdNEE5CKH9J6TpT6ARFsiAdTpH7iJdA8tgAwNeo46FH9CSTv6CURBJSCPAeUu/*)),and_v(v:multi(2,0332e5c86d0938a83ed80d13c5644ec92fd16b9d7184bb35d6ead8227b4ad47803,02807e5c4f7b228aa9f1aef77effde768356480f5268376644464e714d0205eb1c),older(6)),thresh(2,pkh(xpub6EKrK11LwLcNyJ4arJnCtxPGAuxSYPX35fMfJcmadvTSue6YZn2W9kEUHy7PFyQsy7zkrbmhxtevsgwsfyCiRBayJdWSTohRQua43jMw9FQ/*),a:pkh(xpub6BhQvtXJmw6hksh9rRRfdLjaWjQiNMZWtkM5ebn8QkAgh5na2Un6mCDABwkUmHhPCMYtsM9zHY5jxbQ86ayvjfY8XtavbovB6NcNy8KyQLa/*))))#ef5vfw3p"

[bitcoind_config]
network = "regtest"
cookie_path = "/home/user/.bitcoin/.cookie"
addr = "127.0.0.1:8332"
"#.to_string();

        match role {
            UserRole::Stakeholder => config += stake_config,
            UserRole::Manager => config += man_config,
            UserRole::ManagerStakeholder => {
                config += stake_config;
                config += man_config;
            }
        };

        // Just in case there is a leftover from a previous run
        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());

        let mut config: Config = toml::from_str(&config).expect("Parsing valid config file");
        config.data_dir = Some(datadir);
        RevaultD::from_config(config).expect("Creating state from config")
    }

    // Get a dummy handle for the RPC calls.
    // FIXME: we could do something cleaner at some point
    pub fn dummy_rpcutil(datadir: PathBuf, role: UserRole) -> DaemonControl {
        let revaultd = Arc::from(RwLock::from(dummy_revaultd(datadir, role)));

        let (bitcoind_tx, bitcoind_rx) = mpsc::channel();
        let (sigfetcher_tx, sigfetcher_rx) = mpsc::channel();

        let _ = Arc::from(RwLock::from(thread::spawn(move || {
            for msg in bitcoind_rx {
                match msg {
                    BitcoindMessageOut::Shutdown => return,
                    _ => unreachable!(),
                }
            }
        })));
        let _ = Arc::from(RwLock::from(thread::spawn(move || {
            for msg in sigfetcher_rx {
                match msg {
                    SigFetcherMessageOut::Shutdown => return,
                }
            }
        })));

        DaemonControl {
            revaultd,
            bitcoind_conn: BitcoindSender::from(bitcoind_tx),
            sigfetcher_conn: sigfetcher_tx.into(),
        }
    }

    /// Insert a new vault in the database
    #[allow(clippy::too_many_arguments)]
    pub fn insert_vault_in_db(
        db_path: &Path,
        wallet_id: u32,
        deposit_outpoint: &OutPoint,
        amount: &Amount,
        blockheight: u32,
        derivation_index: ChildNumber,
        funded_at: Option<u32>,
        moved_at: Option<u32>,
        status: VaultStatus,
        final_txid: Option<&Txid>,
    ) {
        db_exec(db_path, |tx| {
            let derivation_index: u32 = derivation_index.into();
            tx.execute(
            "INSERT INTO vaults ( \
                wallet_id, status, blockheight, deposit_txid, deposit_vout, amount, derivation_index, \
                funded_at, moved_at, final_txid, emer_shared \
            ) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0)",
            params![
                wallet_id,
                status as u32,
                blockheight,
                deposit_outpoint.txid.to_vec(),
                deposit_outpoint.vout,
                amount.as_sat() as i64,
                derivation_index,
                funded_at,
                moved_at,
                final_txid.map(|txid| txid.to_vec())
            ],
        )
        .expect("Must not fail to insert vault in a test database");

            Ok(())
        }).unwrap()
    }

    /// MockBitcoindThread implements the BitcoindThread trait as a mock backend.
    pub struct MockBitcoindThread {
        txs: HashMap<Txid, WalletTransaction>,
    }

    impl MockBitcoindThread {
        pub fn new(txs: HashMap<Txid, WalletTransaction>) -> Self {
            Self { txs }
        }
    }

    impl BitcoindThread for MockBitcoindThread {
        fn wallet_tx(&self, txid: Txid) -> Result<Option<WalletTransaction>, BitcoindError> {
            let tx = self.txs.get(&txid).map(|tx| (*tx).clone());
            Ok(tx)
        }
        fn broadcast(&self, _transactions: Vec<BitcoinTransaction>) -> Result<(), BitcoindError> {
            Ok(())
        }
        fn shutdown(&self) {}
        fn sync_progress(&self) -> f64 {
            1.0
        }
    }
}
