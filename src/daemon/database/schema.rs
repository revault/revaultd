use crate::revaultd::VaultStatus;
use common::config;
use revault_tx::{
    bitcoin::{util::bip32::ChildNumber, Amount, OutPoint},
    transactions::{
        CancelTransaction, EmergencyTransaction, SpendTransaction, UnvaultEmergencyTransaction,
        UnvaultTransaction, VaultTransaction,
    },
};

use std::convert::TryFrom;

pub const SCHEMA: &str = "\
CREATE TABLE version (
    version INTEGER NOT NULL
);

CREATE TABLE tip (
    network TEXT NOT NULL,
    blockheight INTEGER NOT NULL,
    blockhash BLOB NOT NULL
);

CREATE TABLE wallets (
    id INTEGER PRIMARY KEY NOT NULL,
    timestamp INTEGER NOT NULL,
    vault_descriptor TEXT NOT NULL,
    unvault_descriptor TEXT NOT NULL,
    our_manager_xpub TEXT,
    our_stakeholder_xpub TEXT,
    deposit_derivation_index INTEGER NOT NULL
);

CREATE TABLE vaults (
    id INTEGER PRIMARY KEY NOT NULL,
    wallet_id INTEGER NOT NULL,
    status INTEGER NOT NULL,
    blockheight INTEGER NOT NULL,
    deposit_txid BLOB UNIQUE NOT NULL,
    deposit_vout INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    derivation_index INTEGER NOT NULL,
    FOREIGN KEY (wallet_id) REFERENCES wallets (id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
);

CREATE TABLE transactions (
    id INTEGER PRIMARY KEY NOT NULL,
    vault_id INTEGER NOT NULL,
    type INTEGER NOT NULL,
    tx BLOB UNIQUE NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults (id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
);

CREATE INDEX vault_status ON vaults (status);
CREATE INDEX vault_transactions ON transactions (vault_id);
";

/// A row in the "wallets" table
#[derive(Clone)]
pub struct DbWallet {
    pub id: u32,
    pub timestamp: u32,
    pub vault_descriptor: String,
    pub unvault_descriptor: String,
    pub ourselves: config::OurSelves,
    pub deposit_derivation_index: ChildNumber,
}

/// A row of the "vaults" table
#[derive(Debug, Clone, Copy)]
pub struct DbVault {
    pub id: u32,
    pub wallet_id: u32,
    pub status: VaultStatus,
    pub blockheight: u32,
    pub deposit_outpoint: OutPoint,
    pub amount: Amount,
    pub derivation_index: ChildNumber,
}

/// The type of the transaction, as stored in the "transactions" table
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransactionType {
    Deposit,
    Unvault,
    Spend,
    Cancel,
    Emergency,
    UnvaultEmergency,
}

impl TryFrom<u32> for TransactionType {
    type Error = ();

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        match n {
            0 => Ok(Self::Deposit),
            1 => Ok(Self::Unvault),
            2 => Ok(Self::Spend),
            3 => Ok(Self::Cancel),
            4 => Ok(Self::Emergency),
            5 => Ok(Self::UnvaultEmergency),
            _ => Err(()),
        }
    }
}

macro_rules! tx_type_from_tx {
    ($tx:ident, $tx_type:ident) => {
        impl From<&$tx> for TransactionType {
            fn from(_: &$tx) -> Self {
                Self::$tx_type
            }
        }
    };
}
tx_type_from_tx!(VaultTransaction, Deposit);
tx_type_from_tx!(UnvaultTransaction, Unvault);
tx_type_from_tx!(CancelTransaction, Cancel);
tx_type_from_tx!(EmergencyTransaction, Emergency);
tx_type_from_tx!(UnvaultEmergencyTransaction, UnvaultEmergency);
tx_type_from_tx!(SpendTransaction, Spend);

/// A transaction stored in the 'transactions' table
#[derive(Debug, PartialEq)]
pub enum RevaultTx {
    Deposit(VaultTransaction),
    Unvault(UnvaultTransaction),
    Cancel(CancelTransaction),
    Emergency(EmergencyTransaction),
    UnvaultEmergency(UnvaultEmergencyTransaction),
    Spend(SpendTransaction),
}

/// Boilerplate to get a specific variant of the RevaultTx enum if You Are Confident :TM:
#[macro_export]
macro_rules! assert_tx_type {
    ($tx:expr, $variant:ident, $reason:literal) => {
        match $tx {
            RevaultTx::$variant(inner_tx) => inner_tx,
            _ => unreachable!($reason),
        }
    };
}

/// A row in the "transactions" table
#[derive(Debug)]
pub struct DbTransaction {
    pub id: u32,
    pub vault_id: u32,
    pub tx_type: TransactionType,
    pub tx: RevaultTx,
}
