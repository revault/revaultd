# revaultd API

revaultd exposes a [JSON-RPC 2.0](https://www.jsonrpc.org/specification)
interface over a Unix Domain socket.

Note that all addresses are bech32-encoded *version 0* native Segwit `scriptPubKey`s.

| Command                                   | Description                                          |
| ----------------------------------------- | ---------------------------------------------------- |
| [`getinfo`](#getinfo)                     | Display general information                          |
| [`listvaults`](#listvaults)               | Display a paginated list of vaults                   |
| [`getonchaintxs`](#getonchaintxs)         | Retrieve the vault on chain transactions             |
| [`getrevocationtxs`](#getrevocationtxs)   | Retrieve the Revault revocation transactions to sign |
| [`getunvaulttx`](#getunvaulttx)           | Retrieve the Revault unvault transaction to sign     |
| [`getspendtx`](#getspendtx)               | Retrieve the Revault spend transaction to sign       |
| [`revocationtxs`](#revocationtxs)         | Give back the revocation transactions signed         |
| [`unvaulttx`](#unvaulttx)                 | Give back the unvault transaction signed             |
| [`spendtx`](#spendtx)                     | Give back the spend transaction signed               |

# Reference

## General

### `getinfo`

Display general information about the current daemon state.

#### Response

| Field         | Type    | Description                                                     |
| ------------- | ------- | --------------------------------------------------------------- |
| `blockheight` | integer | Current block height                                            |
| `network`     | string  | Answer can be `mainnet`, `testnet`, `regtest`                   |
| `sync`        | float   | The synchronization progress as percentage (`0 < sync < 1`)     |
| `version`     | string  | Version following the [SimVer](http://www.simver.org/) format   |


### `getdepositaddress`

Get an address to build a deposit transaction.

#### Response

| Field         | Type   | Description                                                 |
| ------------- | ------ | ----------------------------------------------------------- |
| `address`     | string | An address for the N-of-N multisig deposit script           |


## Vault

### Vault statuses

| Order | Value                | Description                                                                                                  |
| ----- | -------------------- | ------------------------------------------------------------------------------------------------------------ |
| 0     | `unconfirmed`        | The vault's deposit transaction is less than 6 blocks-deep in the chain                                      |
| 1     | `funded`             | The vault is initiated by a vault tx                                                                         |
| 2     | `secured`            | The vault's emergency transaction is fully signed and shared with the watchtowers                            |
| 3     | `active`             | The vault's unvault, cancel, and unvault-emergency txs are fully signed and shared with the watchtowers      |
| 4     | `unvaulting`         | The vault has its unvault tx broadcasted                                                                     |
| 5     | `unvaulted`          | The vault has its unvault tx confirmed                                                                       |
| 6     | `cancelling`         | The vault has its cancel tx broadcasted, funds are sent to an other vault                                    |
| 7     | `cancelled`          | The vault has its cancel tx confirmed, funds are in an other vault                                           |
| 3 / 6 | `emergency_vaulting` | The vault has its emergency tx broadcasted, funds are sent to the Deep Emergency Vault                       |
| 4 / 7 | `emergency_vaulted`  | The vault has its emergency tx confirmed, funds are in the Deep Emergency Vault                              |
| 6     | `spendable`          | The vault has its unvault tx timelock expired and can be spent                                               |
| 7     | `spending`           | The vault has a spending tx broadcasted                                                                      |
| 8     | `spent`              | The vault has a spending tx confirmed, the vault is spent                                                    |

### Vault resource

| Field         | Type   | Description                                                 |
| ------------- | ------ | ----------------------------------------------------------- |
| `amount`      | int    | Amount of the vault in satoshis                             |
| `blockheight` | int    | Blockheight of the deposit transaction block                |
| `received_at` | int    | Timestamp of the deposit transaction reception time         |
| `status`      | string | Status of the vault (see [vault statuses](#vault-statuses)) |
| `txid`        | string | Deposit txid of the vault deposit transaction               |
| `updated_at`  | int    | Timestamp of the last status change                         |
| `vout`        | int    | Index of the deposit output in the deposit transaction.     |

Note that the `scriptPubKey` is implicitly known as we have the vault output Miniscript descriptor.
**TODO** Maybe we should store and give the xpub derivation index as well ?

### Vault Transaction resource

| Field         | Type   | Description                                         |
| ------------- | ------ | ------------------------------------------------    |
| `blockheight` | int    | Block height of the transaction                     |
| `hex`         | string | Hexadecimal format of the transaction               |
| `received_at` | int    | Timestamp of the reception time of the transaction |

### `listvaults`

The `listvaults` RPC command displays a list of vaults optionally filtered by
either `status` or deposit `outpoints`.

#### Request

| Parameter   | Type         | Description                                                                                     |
| ----------- | ------------ | ----------------------------------------------------------------------------------------------- |
| `outpoints` | string array | Vault IDs -- optional, filter the list with the given vault Outpoints                           |
| `status`    | string array | Vault status -- optional, see [vault statuses](#vault-statuses) for possible values             |

#### Response

| Field         | Type                                       | Description               |
| ------------- | ------------------------------------------ | ------------------------- |
| `vaults`      | array of [vault resource](#vault-resource) | Vaults filtered by status |

### `getonchaintxs`

The `getonchaintxs` RPC Command retrieves the on chain transactions of a
vault with the given deposit `outpoint`.

#### Request

| Parameter        | Type    | Description                                     |
| ---------------- | ------- | ----------------------------------------------- |
| `outpoint`       | string  | Deposit outpoint of the vault                   |

#### Response

| Field         | Type                                                      | Description                                                           |
| ------------- | --------------------------------------------------------- | --------------------------------------------------------------------- |
| `cancel_tx`   | [Vault transaction resource](#vault-transaction-resource) | Cancel transaction -- present if the vault is cancelling or cancelled |
| `deposit_tx`  | [Vault transaction resource](#vault-transaction-resource) | Deposit transaction                                                   |
| `spend_tx`    | [Vault transaction resource](#vault-transaction-resource) | Spend transaction -- present if vault is spending or spent            |
| `unvault_tx`  | [Vault transaction resource](#vault-transaction-resource) | Unvault transaction -- present if vault is unvaulting or unvaulted    |

### `getrevocationtxs`

The `getrevocationtxs` RPC Command builds and returns the revocation transactions
corresponding to a given vault. The call will fail if the `outpoint` does not refer to a
known and confirmed ([`funded`](#vault-statuses)) vault.

#### Request

| Parameter            | Type    | Description                                     |
| -------------------- | ------- | ----------------------------------------------- |
| `outpoint`           | string  | Deposit outpoint of the vault                   |

#### Response

| Field                  | Type   | Description                                                 |
| ---------------------- | ------ | ----------------------------------------------------------- |
| `emergency_tx`         | string | Emergency transaction to sign using the PSBT format         |
| `cancel_tx`            | string | Cancel transaction to sign using the PSBT format            |
| `emergency_unvault_tx` | string | Emergency unvault transaction to sign using the PSBT format |

### `revocationtxs`

The PSBTs once signed must be given back to the daemon.

#### Request

| Field                  | Type   | Description                                                |
| ---------------------- | ------ | ---------------------------------------------------------- |
| `emergency_tx`         | string | Emergency transaction signed using the PSBT format         |
| `cancel_tx`            | string | Cancel transaction signed using the PSBT format            |
| `emergency_unvault_tx` | string | Emergency unvault transaction signed using the PSBT format |

### `getunvaulttx`

The `getunvaulttx` RPC Command builds and returns the unvault transaction of the given
vault.

#### Request

| Parameter        | Type    | Description                               |
| ---------------- | ------- | ----------------------------------------- |
| `outpoint`       | string  | Deposit outpoint of the vault to activate |

#### Response

| Field        | Type   | Description                                                 |
| ------------ | ------ | ----------------------------------------------------------- |
| `unvault_tx` | string | Unvault transaction to sign using the PSBT format           |

### `unvaultx`

#### Request

| Field        | Type   | Description                                                 |
| ------------ | ------ | ----------------------------------------------------------- |
| `unvault_tx` | string | Unvault transaction signed using the PSBT format            |

### `getspendtx`

The `getspendtx` RPC Command builds and returns the spend transaction given a
set of vaults to spend.

#### Request

| Parameter   | Type                 | Description                                                           |
| ----------- | -------------------- | --------------------------------------------------------------------- |
| `outpoints` | string array         | Vault deposit outpoints -- vaults must be [`active`](#vault-statuses) |
| `output`    | map of string to int | Map of Bitcoin addresses to amount                                    |

Fee is deducted from the total amount of the vaults spent minus the total
amount of the output.

#### Response

| Field      | Type   | Description                                     |
| ---------- | ------ | ----------------------------------------------- |
| `spend_tx` | string | Spend transaction to sign using the PSBT format |

### `spendtx`

#### Request

| Field        | Type   | Description                                    |
| ------------ | ------ | ---------------------------------------------- |
| `spend_tx`   | string | Spend transaction signed using the PSBT format |

## User flows

### Stakeholder flows

#### Sign the revocation transactions

```
 HSM                  client                    revaultd
  +                      +                          +
  |                      |                          |
  |                      | +--+listvaults deposit+> |
  |                      | <--------vaults+-------+ |
  |                      |                          |
  |                      | +--getrevocationtxs----> |
  |                      | <----psbts-------------+ |
  |                      |                          |
  | <----sign emer-----+ |                          |
  | +------sig---------> |                          |
  |                      |                          |
  | <---sign cancel----+ |                          |
  | +------sig---------> |                          |
  |                      |                          |
  | <+sign unvault_emer+ |                          |
  | +------sig---------> |                          |
  |                      | +---revocationtxs------> |
  |                      |                          |
  +                      | +--+listvaults secure+-> |  // check if the watchtowers has the
                         | <--------vaults+-------+ |  // revocation transactions
                         +                          +
```

#### Sign the unvault transaction

```
HSM                  client                      revaultd
 +                      +                          +
 |                      |                          |
 |                      | +---listvaults secure--> |
 |                      | <--------vaults--------+ |
 |                      |                          |
 |                      | +--getunvaulttx--------> |
 |                      | <----psbt--------------+ |
 |                      |                          |
 | <----sign unvault--+ |                          |
 | +------sig---------> |                          |
 |                      | +----unvaulttx---------> |
 |                      |                          |
 +                      | +---listvaults active--> |  // check if the other stakeholders
                        | <--------vaults--------+ |  // have signed the unvault tx too
                        +                          +
```

## Manager flow

```
HSM                client                      revaultd
  +                      +                          +
  |                      | +---listvaults active--> |
  |                      | <-------vaults---------+ |
  |                      |                          |
  |                      | +-------getspendtx-----> |
  |                      | <-----psbt or wt nack--+ |
  | <----sign spend tx-+ |                          |
  | +------sig---------> |                          |
  +                      |                          |
                         |                          |
client 2                 |                          |
  +                      |                          |
  | <---sign psbt------+ |                          |
  | +-----psbt---------> |                          | // daemon ask wt opinion
  +                      | +---spendtx------------> | // if ack, cosign server sign
                         | <---OK or wt nack------+ | // then daemon broadcasts tx
                         |                          |
                         | +--listvaults----------> | // check vaults are spent
                         + ^------vaults----------+ +

```
