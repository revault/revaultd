# revaultd API

revaultd exposes a [JSON-RPC 2.0](https://www.jsonrpc.org/specification)
interface over a Unix Domain socket.

| Command                     | Description                               |
| --------------------------- | ----------------------------------------- |
| [`getinfo`](#getinfo)       | Display general information               |
| [`listvaults`](#listvaults) | Display a paginated list of vaults        |
| [`signvault`](#signvault)   | Sign the Revault pre-signed transactions  |

# Reference

## General

### `getinfo`

Display general information about the current daemon state.

#### Response

| Field         | Type    | Description                                                   |
| ------------- | ------- | ------------------------------------------------------------- |
| `blockheight` | integer | Current block height                                          |
| `network`     | string  | Answer can be `mainnet`, `testnet`, `regtest`                 |
| `version`     | string  | Version following the [SimVer](http://www.simver.org/) format |

## Vault

### Vault statuses

| Order | Value                | Description                                                                                                  |
| ----- | -------------------- | ------------------------------------------------------------------------------------------------------------ |
| 1     | `funded`             | The vault is initiated by a vault tx                                                                         |
| 2     | `secured`            | The vault has an unvault tx cosigned by the right number of peer and all watchtowers have the revocation txs |
| 3     | `unvaulting`         | The vault has its unvault tx broadcasted                                                                     |
| 4     | `unvaulted`          | The vault has its unvault tx confirmed                                                                       |
| 5     | `cancelling`         | The vault has its cancel tx broadcasted, funds are sent to an other vault                                    |
| 6     | `cancelled`          | The vault has its cancel tx confirmed, funds are in an other vault                                           |
| 5     | `emergency_vaulting` | The vault has its emergency tx broadcasted, funds are sent to the Deep Emergency Vault                       |
| 6     | `emergency_vaulted`  | The vault has its emergency tx confirmed, funds are in the Deep Emergency Vault                              |
| 5     | `spendable`          | The vault has its unvault tx timelock expired and can be spent                                               |
| 6     | `spending`           | The vault has a spending tx broadcasted                                                                      |
| 7     | `spent`              | The vault has a spending tx confirmed, the vault is spent                                                    |

### Vault resource

| Field    | Type   | Description                                             |
| -------- | ------ | ------------------------------------------------------- |
| `amount` | int    | Amount of the vault in satoshis                         |
| `txid`   | string | Unique ID of the vault deposit transaction              |
| `status` | string | Status of the vault ([vault statuses](#vault-statuses)) |

**TODO:** add more fields to vault resource.

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

### `signvault`

The `signvault` RPC Command executes the signing process of the Revault
pre-signed transactions.

#### Request

| Parameter        | Type    | Description                         |
| ---------------- | ------- | ----------------------------------- |
| `txid`           | string  | Unique ID of the vault to sign      |
| `only_emergency` | boolean | Sign only the emergency transaction |

#### Response

TODO: specify response
