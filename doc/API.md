# revaultd API

revaultd exposes a [JSON-RPC 2.0](https://www.jsonrpc.org/specification)
interface over a Unix Domain socket.

Note that all addresses are bech32-encoded *version 0* native Segwit `scriptPubKey`s.

| Command                                                     | Description                                          |
| ----------------------------------------------------------- | ---------------------------------------------------- |
| [`getinfo`](#getinfo)                                       | Display general information                          |
| [`getrevocationtxs`](#getrevocationtxs)                     | Retrieve the Revault revocation transactions to sign |
| [`getunvaulttx`](#getunvaulttx)                             | Retrieve the Revault unvault transaction to sign     |
| [`getspendtx`](#getspendtx)                                 | Retrieve the Revault spend transaction to sign       |
| [`listpresignedtransactions`](#listpresignedtransactions)   | List presigned transactions of a confirmed vault     |
| [`listonchaintransactions`](#listonchaintransactions)       | List broadcast transactions of a vault               |
| [`listvaults`](#listvaults)                                 | Display a paginated list of vaults                   |
| [`revocationtxs`](#revocationtxs)                           | Give back the revocation transactions signed         |
| [`unvaulttx`](#unvaulttx)                                   | Give back the unvault transaction signed             |
| [`spendtx`](#spendtx)                                       | Give back the spend transaction signed               |

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
| 1     | `funded`             | The vault is initiated by a deposit transaction                                                              |
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


### `listpresignedtransactions`

List the presigned transactions for a list of given confirmed vaults. Will error if any
of the vaults is unknown or not at least `funded`.

The output PSBTs may be unsigned, partially signed, or finalized (depending on each
vault's state).

| Parameter   | Type         | Description                                                                                     |
| ----------- | ------------ | ----------------------------------------------------------------------------------------------- |
| `outpoints` | string array | Vault IDs -- optional, filter the list with the given vault Outpoints                           |


### Response

| Field                         | Type                                                     | Description                                  |
| ----------------------------- | -------------------------------------------------------- | -------------------------------------------- |
| `presigned_transactions`      | array of [presigned txs](#presigned-txs)                 | Each vault's presigned transactions as PSBTs |


#### Presigned txs

| Field               | Type                                                           | Description                                                              |
| ------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `vault_outpoint`    | string                                                         | The vault deposit transaction outpoint.                                  |
| `unvault`           | string                                                         | The unvaulting transaction as a base64-encoded PSBT                      |
| `cancel`            | string                                                         | The cancel transaction as a base64-encoded PSBT                          |
| `emergency`         | string or `null`                                               | The Emergency transaction, or `null` if we are not a stakeholder         |
| `unvault_emergency` | string or `null`                                               | The Unvault Emergency transaction, or `null` if we are not a stakeholder |


### `listonchaintransactions`

List the transactions related to a list of vaults that were broadcast on the Bitcoin
network (hence they may be unconfirmed). Will error if any of the vaults is unknown.

| Parameter   | Type         | Description                                                                                     |
| ----------- | ------------ | ----------------------------------------------------------------------------------------------- |
| `outpoints` | string array | Vault IDs -- optional, filter the list with the given vault Outpoints                           |


### Response

| Field                         | Type                                                 | Description                       |
| ----------------------------- | ---------------------------------------------------- | --------------------------------- |
| `onchain_transactions`        | array of [onchain txs](#onchain-txs)                 | Each vault's onchain transactions |


#### Onchain txs

| Field               | Type                                                           | Description                                                              |
| ------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `vault_outpoint`    | string                                                         | The vault deposit transaction outpoint.                                  |
| `deposit`           | [wallet tx](#wallet-tx)                                        | The deposit transaction, always there since vault exists                 |
| `unvault`           | [wallet tx](#wallet-tx) or `null`                              | The Unvault transaction                                                  |
| `cancel`            | [wallet tx](#wallet-tx) or `null`                              | The Cancel transaction                                                   |
| `emergency`         | [wallet tx](#wallet-tx) or `null`                              | The Emergency transaction                                                |
| `unvault_emergency` | [wallet tx](#wallet-tx) or `null`                              | The Unvault Emergency transaction                                        |
| `spend`             | [wallet tx](#wallet-tx) or `null`                              | The Spend transaction                                                    |

#### Wallet tx

| Field         | Type             | Description                                                                   |
| ------------- | ---------------- | ----------------------------------------------------------------------------  |
| `blockheight` | int or `null`    | Height of the block containing the transaction, `null` if unconfirmed         |
| `hex`         | string           | Hexadecimal of the network-serialized transaction                             |
| `received_at` | int              | Transaction reception date as the number of seconds since UNIX epoch          |


### `getrevocationtxs`

The `getrevocationtxs` RPC Command builds and returns the (unsigned) revocation transactions
corresponding to a given vault. The call will fail if the `outpoint` does not refer to a
known and confirmed ([`funded`](#vault-statuses)) vault.

#### Request

| Parameter            | Type    | Description                                     |
| -------------------- | ------- | ----------------------------------------------- |
| `outpoint`           | string  | Deposit outpoint of the vault                   |

#### Response

| Field                  | Type   | Description                                                 |
| ---------------------- | ------ | ----------------------------------------------------------- |
| `cancel_tx`            | string | Base64-encoded Cancel transaction PSBT                      |
| `emergency_tx`         | string | Base64-encoded Emergency transaction PSBT                   |
| `emergency_unvault_tx` | string | Base64-encoded Unvault Emergency transaction PSBT           |


### `revocationtxs`

Hand signed PSBTs to the daemon. The PSBT may comport multiple signatures, but the call
will error if the signature for "our" key is not part of this set.  
See the [flows](#stakeholder-flows) for more information.  

#### Request

| Field                  | Type   | Description                                                 |
| ---------------------- | ------ | ----------------------------------------------------------- |
| `cancel_tx`            | string | Base64-encoded Cancel transaction PSBT                      |
| `emergency_tx`         | string | Base64-encoded Emergency transaction PSBT                   |
| `emergency_unvault_tx` | string | Base64-encoded Unvault Emergency transaction PSBT           |


#### Response

None; the `result` field will be set to the empty object `{}`. Any value should be
disregarded for forward compatibility.


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
| `unvault_tx` | string | Base64-encoded Unvault transaction PSBT                     |


### `unvaulttx`

Hand signed Unvault PSBT to the daemon. The PSBT may comport multiple signatures, but the call
will error if the signature for "our" key is not part of this set.  
Will error if the vault is not `secured`, or already `active`.  
See the [flows](#stakeholder-flows) for more information.  

#### Request

| Field        | Type   | Description                                                 |
| ------------ | ------ | ----------------------------------------------------------- |
| `unvault_tx` | string | Base64-encoded Unvault transaction PSBT                     |

#### Response

None; the `result` field will be set to the empty object `{}`. Any value should be
disregarded for forward compatibility.


### `getspendtx`

The `getspendtx` RPC Command builds and returns the spend transaction given a
set of vaults to spend.

#### Request

| Parameter   | Type                 | Description                                                           |
| ----------- | -------------------- | --------------------------------------------------------------------- |
| `outpoints` | string array         | Vault deposit outpoints -- vaults must be [`active`](#vault-statuses) |
| `outputs`   | map of string to int | Map of Bitcoin addresses to amount                                    |
| `feerate`   | int                  | Target feerate for the transaction                                    |

Fee is deducted from the total amount of the vaults spent minus the total
amount of the output.

`feerate` is tolerated to end up 10% below the target, or above if we can't create a
change output.

Mind the addition of the CPFP output we do, which must be taken into account by the
feerate.

#### Response

| Field      | Type   | Description                                     |
| ---------- | ------ | ----------------------------------------------- |
| `spend_tx` | string | Base64-encoded Spend transaction PSBT           |


### `updatespendtx`

The `updatespendtx` RPC Command stores or update the stored Spend transaction with the
given one.

#### Request

| Field       | Type         | Description                                                           |
| ----------- | ------------ | --------------------------------------------------------------------- |
| `spend_tx`  | string       | Base64-encoded Spend transaction PSBT                                 |

#### Response

None; the `result` field will be set to the empty object `{}`. Any value should be
disregarded for forward compatibility.


### `setspendtx`

#### Request

| Field          | Type   | Description                                    |
| -------------- | ------ | ---------------------------------------------- |
| `spend_txid`   | string | Txid of the Spend transaction to use           |

#### Response

None; the `result` field will be set to the empty object `{}`. Any value should be
disregarded for forward compatibility.


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

#### Sign the Unvault transaction

```
HSM                  client                      revaultd
 +                      +                          +
 |                      |                          |
 |                      | +---listvaults active--> |
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
  | +-----psbt---------> |                          |
  +                      | +---spendtx------------> | // if ack, cosign server sign
                         | <---OK or wt nack------+ | // then daemon broadcasts tx
                         |                          |
                         | +--listvaults----------> | // check vaults are spent
                         + ^------vaults----------+ +

```
