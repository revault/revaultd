# revaultd API

revaultd exposes a [JSON-RPC 2.0](https://www.jsonrpc.org/specification)
interface over a Unix Domain socket.

| Command                                   | Description                                          |
| ----------------------------------------- | ---------------------------------------------------- |
| [`getinfo`](#getinfo)                     | Display general information                          |
| [`listvaults`](#listvaults)               | Display a paginated list of vaults                   |
| [`securevault`](#securevault)             | Retrieve the Revault revocation transactions to sign |
| [`activatevault`](#activatevault)         | Retrieve the Revault unvault transaction to sign     |
| [`spendvaults`](#spendvault)              | Retrieve the Revault spend transaction to sign       |
| [`signedtx`](#signedtx)                   | Give back the transaction signed                     |

# Reference

## General

### `getinfo`

Display general information about the current daemon state.

#### Response

| Field         | Type    | Description                                                     |
| ------------- | ------- | --------------------------------------------------------------- |
| `blockheight` | integer | Current block height                                            |
| `network`     | string  | Answer can be `mainnet`, `testnet`, `regtest`                   |
| `sync`        | integer | The synchronization progress as percentage                      |
| `version`     | string  | Version following the [SimVer](http://www.simver.org/) format   |

## Vault

### Vault statuses

| Order | Value                | Description                                                                                                  |
| ----- | -------------------- | ------------------------------------------------------------------------------------------------------------ |
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

| Field         | Type   | Description                                                                          |
| ------------- | ------ | ------------------------------------------------------------------------------------ |
| `amount`      | int    | Amount of the vault in satoshis                                                      |
| `blockheight` | int    | Block height at which the vault deposit transaction was confirmed (0 if unconfirmed) |
| `status`      | string | Status of the vault ([vault statuses](#vault-statuses))                              |
| `txid`        | string | Unique ID of the vault deposit transaction                                           |
| `vout`        | vout   | Index of the deposit output in the deposit transaction.                              |

Note that the `scriptPubKey` is implicitly known as we have the vault output Miniscript descriptor.
**TODO** Maybe we should store and give the xpub derivation index as well ?


### `listvaults`

The `listvaults` RPC command displays a list of vaults
filtered by an optional `status` parameter.

#### Request

| Parameter | Type         | Description                                                                                     |
| --------- | ------------ | ----------------------------------------------------------------------------------------------- |
| `status`  | string array | Vault status -- optional, choices are [vault statuses](#vault-statuses)                         |
| `txid`    | string array | Vault IDs -- optional, filter the list with the given vault IDs                                 |

#### Response

| Field         | Type                                       | Description               |
| ------------- | ------------------------------------------ | ------------------------- |
| `vaults`      | array of [vault resource](#vault-resource) | Vaults filtered by status |

### `securevault`

The `securevault` RPC Command executes the signing process of the
Revault revocation transactions.

#### Request

| Parameter        | Type    | Description                                     |
| ---------------- | ------- | ----------------------------------------------- |
| `txid`           | string  | Unique ID of the vault to secure                |
| `only_emergency` | boolean | Retrieve only the emergency transaction to sign |

#### Response

| Field                | Type   | Description                                                 |
| -------------------- | ------ | ----------------------------------------------------------- |
| emergency_tx         | string | Emergency transaction to sign using the PSBT format         |
| cancel_tx            | string | Cancel transaction to sign using the PSBT format            |
| emergency_unvault_tx | string | Emergency unvault transaction to sign using the PSBT format |

### `activatevault`

The `activatevault` RPC Command executes the signing process of the
Revault unvault transaction.

#### Request

| Parameter        | Type    | Description                        |
| ---------------- | ------- | ---------------------------------- |
| `txid`           | string  | Unique ID of the vault to activate |

#### Response

| Field       | Type   | Description                                                 |
| ----------- | ------ | ----------------------------------------------------------- |
| unvault_tx  | string | Unvault transaction to sign using the PSBT format           |

### `spendvaults`

The `spendvaults` RPC Command retrieve the spend transaction to sign
according to the chosen vaults.

#### Request

| Parameter | Type                 | Description                                             |
| --------- | -------------------- | ------------------------------------------------------- |
| txid      | string array         | Vault IDs -- vaults must be [`active`](#vault-statuses) |
| output    | map of string to int | Map of Bitcoin addresses to amount                      |

Fee is deducted from the total amount of the vaults spent minus the total
amount of the output.

#### Response

| Field    | Type   | Description                                     |
| -------- | ------ | ----------------------------------------------- |
| spend_tx | string | Spend transaction to sign using the PSBT format |

### `signedtx`

The PSBT once signed must be given back to the daemon to be handled
according to the context. 

If the `signedtx` type is `spend_tx` and has enough manager signatures, 
then the revault daemon will start the spending process. 

#### Request

| Parameter | Type    | Description                                                                                                   |
| --------- | ------- | ------------------------------------------------------------------------------------------------------------- |
| tx        | string  | PSBT with the required signatures                                                                             |
| type      | string  | Type of the transaction, can be `emergency_tx`, `cancel_tx`, `emergency_unvault_tx`, `unvault_tx`, `spend_tx` |

#### Response

| Field    | Type | Description                                                                                             |
| -------- | ---- | ------------------------------------------------------------------------------------------------------- |
| sigs_ack | bool | Watchower has stored the given revocation tx (Field not present if tx type is `unvault_tx`, `spend_tx`) |


## User flows

### Stakeholder

#### Sign the revocation transactions

```
 HSM                  client                    revaultd
  +                      +                          +
  |                      |                          |
  |                      | +---listvaults deposit-> |
  |                      | <-------->aults--------+ |
  |                      |                          |
  |                      | +---securevault txid---> |
  |                      | <----psbts-------------+ |
  |                      |                          |
  | <----sign emer-----+ |                          |
  | +------sig---------> |                          |
  |                      | +-----signedtx (sig)---> |
  | <---sign cancel----+ |                          |
  | +------sig---------> |                          |
  |                      | +------signedtx (sig)--> |
  | <-sign unvault_emer+ |                          |
  | +------------------> |                          |
  |                      | +------signedtx--------> |
  |                      |                          |
  +                      | +---listvaults secure--> |  // check if the watchtowers has the
                         | <--------vaults--------+ |  // revocation transactions
                         +                          +
```
