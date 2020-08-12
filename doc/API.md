# revaultd API

revaultd exposes a [JSON-RPC 2.0](https://www.jsonrpc.org/specification)
interface over a Unix Domain socket.

| Command                     | Description                        |
| --------------------------- | ---------------------------------- |
| [`listvaults`](#listvaults) | Display a paginated list of vaults |

# Reference

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
| `txid`   | string | Unique ID of the vault transaction                      |
| `status` | string | Status of the vault ([vault statuses](#vault-statuses)) |

**TODO:** add more fields to vault resource.

### `listvaults`

The `listvaults` RPC command displays a list of vaults
filtered by an optional `status` parameter.

#### Request

| Parameter | Type         | Description                                                                                     |
| --------- | ------------ | ----------------------------------------------------------------------------------------------- |
| `status`  | string array | vault status -- optional, choices are [vault statuses](#vault-statuses)                         |

#### Response

| Field         | Type                                       | Description               |
| ------------- | ------------------------------------------ | ------------------------- |
| `vaults`      | array of [vault resource](#vault-resource) | Vaults filtered by status |
