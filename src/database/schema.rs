pub const SCHEMA: &str = "\
CREATE TABLE version (
    version INTEGER NOT NULL
);

CREATE TABLE wallets (
    id INTEGER PRIMARY KEY NOT NULL,
    timestamp INTEGER NOT NULL,
    vault_descriptor TEXT NOT NULL,
    unvault_descriptor TEXT NOT NULL
);

CREATE TABLE vaults (
    id INTEGER PRIMARY KEY NOT NULL,
    wallet_id INTEGER NOT NULL,
    status INTEGER NOT NULL,
    blockheight INTEGER NOT NULL,
    deposit_txid BLOB UNIQUE NOT NULL,
    deposit_vout INTEGER NOT NULL,
    FOREIGN KEY (wallet_id) REFERENCES wallets (id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
);

CREATE TABLE transactions (
    id INTEGER PRIMARY KEY NOT NULL,
    vault_id INTEGER NOT NULL,
    type INTEGER NOT NULL,
    psbt TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults (id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
);

CREATE INDEX vault_status ON vaults (status);
CREATE INDEX vault_transactions ON transactions (vault_id);
";
