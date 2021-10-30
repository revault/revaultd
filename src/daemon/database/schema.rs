use crate::daemon::{
    database::bitcointx::{RevaultTx, TransactionType},
    revaultd::VaultStatus,
};
use revault_tx::{
    bitcoin::{
        util::bip32::{ChildNumber, ExtendedPubKey},
        Amount, OutPoint, Txid,
    },
    scripts::{CpfpDescriptor, DepositDescriptor, UnvaultDescriptor},
    transactions::SpendTransaction,
};

pub const SCHEMA: &str = "\
CREATE TABLE version (
    version INTEGER NOT NULL
);

CREATE TABLE tip (
    network TEXT NOT NULL,
    blockheight INTEGER NOT NULL,
    blockhash BLOB NOT NULL
);

/* This stores metadata about our wallet. We only support single wallet for
 * now (and the foreseeable future). This MUST be in sync with bitcoind's
 * wallet.
 */
CREATE TABLE wallets (
    id INTEGER PRIMARY KEY NOT NULL,
    timestamp INTEGER NOT NULL,
    deposit_descriptor TEXT NOT NULL,
    unvault_descriptor TEXT NOT NULL,
    cpfp_descriptor TEXT NOT NULL,
    our_manager_xpub TEXT,
    our_stakeholder_xpub TEXT,
    deposit_derivation_index INTEGER NOT NULL
);

/* This stores the vaults we heard about. The deposit may be unconfirmed,
 * in which case the blockheight will be 0 (FIXME: should be NULL instead?).
 * For any vault entry a deposit transaction MUST be present in bitcoind's
 * wallet.
 * The final_txid is stored to not harass bitcoind trying to guess the
 * spending txid or the canceling txid out of a deposit outpoint.
 * It MUST be NOT NULL if status is 'spending', 'spent', 'canceling'
 * or 'canceled'.
 */
CREATE TABLE vaults (
    id INTEGER PRIMARY KEY NOT NULL,
    wallet_id INTEGER NOT NULL,
    status INTEGER NOT NULL,
    blockheight INTEGER NOT NULL,
    deposit_txid BLOB NOT NULL,
    deposit_vout INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    derivation_index INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    final_txid BLOB,
    FOREIGN KEY (wallet_id) REFERENCES wallets (id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
);

/* This stores transactions we presign:
 * - Emergency (only for stakeholders)
 * - Unvault
 * - Cancel
 * - Unvault Emergency (only for stakeholders)
 */
CREATE TABLE presigned_transactions (
    id INTEGER PRIMARY KEY NOT NULL,
    vault_id INTEGER NOT NULL,
    type INTEGER NOT NULL,
    psbt BLOB UNIQUE NOT NULL,
    txid BLOB UNIQUE NOT NULL,
    fullysigned BOOLEAN NOT NULL CHECK (fullysigned IN (0,1)),
    FOREIGN KEY (vault_id) REFERENCES vaults (id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
);

/* A bridge between the Unvault transactions a Spend transaction
 * may refer and the possible Spend transactions an Unvault one
 * may be associated with.
 */
CREATE TABLE spend_inputs (
    id INTEGER PRIMARY KEY NOT NULL,
    unvault_id INTEGER NOT NULL,
    spend_id INTEGER NOT NULL,
    FOREIGN KEY (unvault_id) REFERENCES presigned_transactions (id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    FOREIGN KEY (spend_id) REFERENCES spend_transactions (id)
        ON UPDATE RESTRICT
        ON DELETE CASCADE
);

/* This stores Spend transactions we created. A txid column is there to
 * ease research.
 * The 'broadcasted' column indicates wether a Spend transaction is:
 *  - Not elligible for broadcast (NULL)
 *  - Waiting to be broadcasted (0)
 *  - Already broadcasted (1)
 */
CREATE TABLE spend_transactions (
    id INTEGER PRIMARY KEY NOT NULL,
    psbt BLOB UNIQUE NOT NULL,
    txid BLOB UNIQUE NOT NULL,
    broadcasted BOOLEAN CHECK (broadcasted IN (NULL, 0,1))
);

CREATE INDEX vault_status ON vaults (status);
CREATE INDEX vault_transactions ON presigned_transactions (vault_id);
";

/// A row in the "wallets" table
#[derive(Clone)]
pub struct DbWallet {
    pub id: u32, // FIXME: should be an i64
    pub timestamp: u32,
    pub deposit_descriptor: DepositDescriptor,
    pub unvault_descriptor: UnvaultDescriptor,
    pub cpfp_descriptor: CpfpDescriptor,
    pub our_man_xpub: Option<ExtendedPubKey>,
    pub our_stk_xpub: Option<ExtendedPubKey>,
    pub deposit_derivation_index: ChildNumber,
}

/// A row of the "vaults" table
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DbVault {
    pub id: u32, // FIXME: should be an i64
    pub wallet_id: u32,
    pub status: VaultStatus,
    pub blockheight: u32,
    pub deposit_outpoint: OutPoint,
    pub amount: Amount,
    pub derivation_index: ChildNumber,
    pub received_at: u32,
    pub updated_at: u32,
    pub final_txid: Option<Txid>,
}

// FIXME: naming it "db transaction" was ambiguous..
/// A row in the "presigned_transactions" table
#[derive(Debug, Clone)]
pub struct DbTransaction {
    pub id: u32, // FIXME: should be an i64
    pub vault_id: u32,
    pub tx_type: TransactionType,
    pub psbt: RevaultTx,
    pub is_fully_signed: bool,
}

/// A row in the "spend_inputs" table
#[derive(Debug)]
pub struct DbSpendInput {
    pub id: i64,
    pub unvault_id: u32,
    pub spend_id: u32,
}

/// A row in the "spend_transactions" table
#[derive(Debug, PartialEq)]
pub struct DbSpendTransaction {
    pub id: i64,
    pub psbt: SpendTransaction,
    pub broadcasted: Option<bool>,
    // txid is intentionally not there as it's already part of the psbt
}
