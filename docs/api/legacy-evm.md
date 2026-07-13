# Legacy EVM transaction signing

[EVM index](evm.md) · [API index](../API.md)

## EVM sign endpoints

### `POST v1/evm/transfers/legacy/sign`

Request type: `EVMLegacyTransferSignRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `chain_id` | int64 | yes | EVM chain ID. |
| `to` | string | yes | Recipient hex address. |
| `value` | string | yes | Transfer amount. |
| `nonce` | uint64 | yes | Sender nonce. |
| `gas_limit` | uint64 | yes | Gas limit. |
| `gas_price` | string | yes | Legacy gas price. |

Response `operation`: `evm_transfer_legacy`

### `POST v1/evm/transfers/eip1559/sign`

Request type: `EVMEIP1559TransferSignRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `chain_id` | int64 | yes | EVM chain ID. |
| `to` | string | yes | Recipient hex address. |
| `value` | string | yes | Transfer amount. |
| `nonce` | uint64 | yes | Sender nonce. |
| `gas_limit` | uint64 | yes | Gas limit. |
| `max_fee_per_gas` | string | yes | EIP-1559 fee cap. |
| `max_priority_fee_per_gas` | string | yes | EIP-1559 priority fee cap. |

Response `operation`: `evm_transfer_eip1559`

### `POST v1/evm/contracts/eip1559/sign`

Request type: `EVMContractCallSignRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `chain_id` | int64 | yes | EVM chain ID. |
| `to` | string | yes | Contract hex address. |
| `value` | string | yes | Native asset amount attached to the call. |
| `data` | string | yes | Contract call data as hex. |
| `nonce` | uint64 | yes | Sender nonce. |
| `gas_limit` | uint64 | yes | Gas limit. |
| `max_fee_per_gas` | string | yes | EIP-1559 fee cap. |
| `max_priority_fee_per_gas` | string | yes | EIP-1559 priority fee cap. |

Response `operation`: `evm_contract_call_eip1559`
