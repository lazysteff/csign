# chain-signer HTTP API

This document describes the Vault-exposed HTTP API for `chain-signer`, the supported request and response shapes, the policy definition, and a complete happy-path flow.

## Overview

`chain-signer` is mounted in Vault as an external secret plugin. If the plugin is mounted at `chain-signer`, the API base path is:

```text
${VAULT_ADDR}/v1/chain-signer/
```

Examples in this document use the Vault HTTP API directly with:

- `X-Vault-Token: ${VAULT_TOKEN}`
- `Content-Type: application/json`

Vault wraps plugin responses under the normal Vault top-level envelope. The plugin payload itself appears under the top-level `data` field.

## Supported operations

### Key lifecycle

- `GET v1/version`
- `POST v1/keys`
- `LIST v1/keys`
- `GET v1/keys/:key_id`
- `POST v1/keys/:key_id/status`

### Signing

- `POST v1/evm/transfers/legacy/sign`
- `POST v1/evm/transfers/eip1559/sign`
- `POST v1/evm/contracts/eip1559/sign`
- `POST v1/tron/transfers/trx/sign`
- `POST v1/tron/transfers/trc20/sign`

### Payload inspection

- `POST v1/verify`
- `POST v1/recover`

## Data conventions

- `chain_family` must be `evm` or `tron`.
- `custody_mode` must be `mvp` or `pkcs11`.
- EVM addresses are hex addresses. The plugin normalizes them before comparison.
- TRON addresses are Base58 addresses.
- Numeric string fields such as `value`, `gas_price`, `max_fee_per_gas`, and TRC-20 `amount` accept decimal values. The underlying parser also accepts `0x`-prefixed hex strings, but decimal is recommended for client clarity.
- `signed_payload` is always returned as a hex string and `payload_encoding` is currently always `hex`.
- `request_id`, `approval_ref`, and `labels` are accepted on sign requests as caller metadata. They are not echoed back in sign responses.
- Key responses never include `private_key_hex`.

## Happy path: EVM EIP-1559 transfer

This is the simplest end-to-end flow for a new caller:

1. Read plugin version.
2. Create an EVM signing key with guardrails.
3. Read the key metadata and capture `signer_address`.
4. Sign an EIP-1559 native transfer.
5. Verify the signed payload.

### 1. Read version

```bash
curl \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/chain-signer/v1/version"
```

Example response body:

```json
{
  "data": {
    "api_version": "v1",
    "build_version": "v0.2.0"
  }
}
```

### 2. Create a key

```bash
curl \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  --header "Content-Type: application/json" \
  --request POST \
  --data @- \
  "${VAULT_ADDR}/v1/chain-signer/v1/keys" <<'JSON'
{
  "key_id": "payments-evm",
  "chain_family": "evm",
  "custody_mode": "mvp",
  "labels": {
    "team": "payments",
    "env": "dev"
  },
  "policy": {
    "allowed_networks": ["ethereum-sepolia"],
    "allowed_chain_ids": [11155111],
    "max_value": "1000000000000000000",
    "max_gas_limit": 250000,
    "max_fee_per_gas": "2000000000",
    "max_priority_fee_per_gas": "1000000000"
  }
}
JSON
```

Example response body:

```json
{
  "data": {
    "api_version": "v1",
    "key_id": "payments-evm",
    "chain_family": "evm",
    "custody_mode": "mvp",
    "active": true,
    "labels": {
      "team": "payments",
      "env": "dev"
    },
    "policy": {
      "allowed_networks": ["ethereum-sepolia"],
      "allowed_chain_ids": [11155111],
      "max_value": "1000000000000000000",
      "max_gas_limit": 250000,
      "max_fee_per_gas": "2000000000",
      "max_priority_fee_per_gas": "1000000000"
    },
    "signer_address": "0xYourSignerAddress",
    "public_key_hex": "0x...",
    "created_at": "2026-04-10T12:00:00Z",
    "updated_at": "2026-04-10T12:00:00Z"
  }
}
```

Capture the signer address for later steps:

```bash
SIGNER_ADDRESS="$(curl \
  --silent \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/chain-signer/v1/keys/payments-evm" | jq -r '.data.signer_address')"
```

This uses `jq` for convenience. Any client that can extract `.data.signer_address` from the Vault response will work.

### 3. Read the key

```bash
curl \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/chain-signer/v1/keys/payments-evm"
```

Use this when the caller needs to confirm:

- the key exists
- the key is active
- the chain family matches the intended endpoint
- the `signer_address` is the expected source address

### 4. Sign a transfer

```bash
curl \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  --header "Content-Type: application/json" \
  --request POST \
  --data @- \
  "${VAULT_ADDR}/v1/chain-signer/v1/evm/transfers/eip1559/sign" <<JSON
{
  "key_id": "payments-evm",
  "chain_family": "evm",
  "network": "ethereum-sepolia",
  "request_id": "req-123",
  "source_address": "${SIGNER_ADDRESS}",
  "chain_id": 11155111,
  "to": "0x1111111111111111111111111111111111111111",
  "value": "1",
  "nonce": 7,
  "gas_limit": 21000,
  "max_fee_per_gas": "1500",
  "max_priority_fee_per_gas": "100"
}
JSON
```

Example response body:

```json
{
  "data": {
    "api_version": "v1",
    "key_id": "payments-evm",
    "chain_family": "evm",
    "network": "ethereum-sepolia",
    "operation": "evm_transfer_eip1559",
    "signer_address": "0xYourSignerAddress",
    "tx_hash": "0xSignedTransactionHash",
    "signed_payload": "0xSerializedSignedTransaction",
    "payload_encoding": "hex"
  }
}
```

The caller can then submit `signed_payload` to its chain-specific broadcaster.

### 5. Verify the signed payload

```bash
curl \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  --header "Content-Type: application/json" \
  --request POST \
  --data @- \
  "${VAULT_ADDR}/v1/chain-signer/v1/verify" <<'JSON'
{
  "chain_family": "evm",
  "network": "ethereum-sepolia",
  "operation": "evm_transfer_eip1559",
  "signed_payload": "0xSerializedSignedTransaction",
  "expected_signer_address": "0xYourSignerAddress"
}
JSON
```

Example response body:

```json
{
  "data": {
    "api_version": "v1",
    "chain_family": "evm",
    "network": "ethereum-sepolia",
    "operation": "evm_transfer_eip1559",
    "recovered_signer": "0xYourSignerAddress",
    "expected_signer": "0xYourSignerAddress",
    "matches_expected": true,
    "tx_hash": "0xSignedTransactionHash"
  }
}
```

## Key API

### `GET v1/version`

Returns plugin build metadata.

Response type: `VersionResponse`

| Field | Type | Meaning |
| --- | --- | --- |
| `api_version` | string | Wire contract version. Currently `v1`. |
| `build_version` | string | Plugin build identifier. |

### `POST v1/keys`

Creates a new chain-bound key record.

Request type: `CreateKeyRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `key_id` | string | no | Explicit key identifier. If omitted, the plugin generates one. |
| `chain_family` | string | yes | `evm` or `tron`. |
| `custody_mode` | string | no | `mvp` or `pkcs11`. Defaults to `mvp`. |
| `labels` | object | no | Arbitrary metadata stored with the key. |
| `policy` | object | no | Request guardrails applied at sign time. |
| `import_private_key_hex` | string | no | Only valid in `mvp` mode. Imports an existing secp256k1 private key. |
| `public_key_hex` | string | yes in `pkcs11` | Public key for externally managed signing material. |
| `external_signer_ref` | string | yes in `pkcs11` | Reference passed to the external signer resolver. |

Response type: `KeyResponse`

| Field | Type | Meaning |
| --- | --- | --- |
| `api_version` | string | Wire contract version. |
| `key_id` | string | Key identifier. |
| `chain_family` | string | `evm` or `tron`. |
| `custody_mode` | string | `mvp` or `pkcs11`. |
| `active` | bool | Whether the key can sign. |
| `labels` | object | Stored labels. |
| `policy` | object | Stored policy. |
| `signer_address` | string | Derived on-chain address for the key. |
| `public_key_hex` | string | Public key in hex. |
| `created_at` | string | RFC3339 timestamp. |
| `updated_at` | string | RFC3339 timestamp. |

Notes:

- The response never includes `private_key_hex`.
- Duplicate `key_id` values return `409`.

### `LIST v1/keys`

Lists configured key IDs.

Vault HTTP clients can use `LIST /v1/chain-signer/v1/keys` or `GET /v1/chain-signer/v1/keys?list=true`.

Example response body:

```json
{
  "data": {
    "keys": [
      "payments-evm",
      "settlement-tron"
    ]
  }
}
```

### `GET v1/keys/:key_id`

Reads key metadata.

Response type: `KeyResponse`

### `POST v1/keys/:key_id/status`

Enables or disables a key.

Request type: `UpdateKeyStatusRequest`

```json
{
  "active": false
}
```

Response type: `KeyResponse`

## Sign request base fields

All sign endpoints share these base fields through `BaseSignRequest`.

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `key_id` | string | yes | Key record to use. |
| `chain_family` | string | yes | Must match the endpoint family. |
| `network` | string | yes | Logical network name enforced by policy if configured. |
| `request_id` | string | yes | Caller correlation identifier. |
| `labels` | object | no | Arbitrary caller metadata. |
| `approval_ref` | string | no | Approval system reference. |
| `source_address` | string | yes | Must match the stored signer address for the key. |

All sign endpoints return `SignResponse`:

| Field | Type | Meaning |
| --- | --- | --- |
| `api_version` | string | Wire contract version. |
| `key_id` | string | Key identifier used. |
| `chain_family` | string | `evm` or `tron`. |
| `network` | string | Network name from the request. |
| `operation` | string | Typed operation name. |
| `signer_address` | string | Derived signer address. |
| `tx_hash` | string | Transaction hash or transaction ID. |
| `signed_payload` | string | Signed payload encoded as hex. |
| `payload_encoding` | string | Currently `hex`. |

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

## TRON sign endpoints

### `POST v1/tron/transfers/trx/sign`

Request type: `TRXTransferSignRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `to` | string | yes | Recipient Base58 address. |
| `amount` | int64 | yes | TRX amount. |
| `fee_limit` | int64 | yes | TRON fee limit. |
| `ref_block_bytes` | string | yes | Reference block bytes as hex. |
| `ref_block_hash` | string | yes | Reference block hash bytes as hex. |
| `ref_block_num` | int64 | no | Reference block number. |
| `timestamp` | int64 | yes | Request timestamp in milliseconds. |
| `expiration` | int64 | yes | Expiration timestamp in milliseconds. |

Response `operation`: `tron_transfer_trx`

### `POST v1/tron/transfers/trc20/sign`

Request type: `TRC20TransferSignRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `to` | string | yes | Recipient Base58 address. |
| `token_contract` | string | yes | TRC-20 contract Base58 address. |
| `amount` | string | yes | Token amount. |
| `fee_limit` | int64 | yes | TRON fee limit. |
| `ref_block_bytes` | string | yes | Reference block bytes as hex. |
| `ref_block_hash` | string | yes | Reference block hash bytes as hex. |
| `ref_block_num` | int64 | no | Reference block number. |
| `timestamp` | int64 | yes | Request timestamp in milliseconds. |
| `expiration` | int64 | yes | Expiration timestamp in milliseconds. |

Response `operation`: `tron_transfer_trc20`

## Verify and recover

### `POST v1/verify`

Validates a signed payload against an expected signer and, optionally, an expected operation.

Request type: `VerifyRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `chain_family` | string | yes | `evm` or `tron`. |
| `network` | string | yes | Logical network name. |
| `operation` | string | no | Expected operation. |
| `signed_payload` | string | yes | Signed payload as hex. |
| `expected_signer_address` | string | no | Expected signer address. |

Response type: `RecoverResponse`

| Field | Type | Meaning |
| --- | --- | --- |
| `api_version` | string | Wire contract version. |
| `chain_family` | string | `evm` or `tron`. |
| `network` | string | Network from the request. |
| `operation` | string | Recovered operation type. |
| `recovered_signer` | string | Address recovered from the signed payload. |
| `expected_signer` | string | Copied from the request when provided. |
| `matches_expected` | bool | `true` only when the expected signer matches and, if `operation` was provided, the recovered operation matches too. |
| `tx_hash` | string | Transaction hash or transaction ID. |

### `POST v1/recover`

Performs signer and operation recovery without enforcing an expected operation.

Uses the same request and response types as `verify`.

Difference from `verify`:

- `recover` returns the recovered signer and operation.
- `verify` additionally recomputes `matches_expected` against the provided expectations.

## Policy definition

The `policy` object is attached to a key and enforced at sign time.

| Field | Type | Applies to | Meaning |
| --- | --- | --- | --- |
| `allowed_networks` | array of string | all | Allowed `network` values. |
| `allowed_chain_ids` | array of int64 | EVM | Allowed `chain_id` values. |
| `max_value` | string | all | Maximum native or token amount. |
| `max_gas_limit` | uint64 | EVM | Maximum gas limit. |
| `max_gas_price` | string | EVM legacy | Maximum legacy gas price. |
| `max_fee_per_gas` | string | EVM EIP-1559 | Maximum EIP-1559 fee cap. |
| `max_priority_fee_per_gas` | string | EVM EIP-1559 | Maximum EIP-1559 priority fee cap. |
| `max_fee_limit` | int64 | TRON | Maximum TRON fee limit. |
| `allowed_token_contracts` | array of string | EVM contract calls, TRC-20 | Allowlisted contract addresses. |
| `allowed_selectors` | array of string | EVM contract calls, TRC-20 | Allowlisted function selectors. |
| `additional_policy_context` | object | stored only | Stored and returned, but not enforced by the current validators. |

Current enforcement rules:

- Sign requests fail if the key is disabled.
- `source_address` must match the stored key address.
- EVM contract calls require non-empty `data`.
- TRC-20 signing is limited to the `transfer(address,uint256)` selector.
- Policy denials currently return HTTP `400` through Vault, not `403`.

## Error behavior

The adapter maps internal failures to Vault HTTP responses like this:

| Status | When it happens |
| --- | --- |
| `400` | invalid request shape, policy denial, unsupported chain/operation, request/address mismatch, missing `key_id`, malformed payload, missing external signer resolver |
| `404` | missing key |
| `409` | duplicate key creation |
| `500` | unexpected internal failure |

Typical validation and policy errors include messages such as:

- `key_id is required`
- `source address does not match key signer address`
- `network "..." is not allowed`
- `gas_limit exceeds configured cap`
- `token contract is not allowlisted`

## Go client mapping

The Go client is organized by capability:

| Area | Methods |
| --- | --- |
| `Client` | `Version` |
| `Client.Keys` | `Create`, `Read`, `List`, `SetActive` |
| `Client.Signing` | `SignEVMLegacyTransfer`, `SignEVMEIP1559Transfer`, `SignEVMContractCall`, `SignTRXTransfer`, `SignTRC20Transfer` |
| `Client.Payloads` | `Verify`, `Recover` |

Example:

```go
vaultClient, _ := api.NewClient(api.DefaultConfig())
vaultClient.SetAddress(os.Getenv("VAULT_ADDR"))
vaultClient.SetToken(os.Getenv("VAULT_TOKEN"))

client := csclient.NewFromVault(vaultClient, "chain-signer")

resp, err := client.Signing.SignEVMEIP1559Transfer(ctx, v1.EVMEIP1559TransferSignRequest{
	BaseSignRequest: v1.BaseSignRequest{
		KeyID:         "payments-evm",
		ChainFamily:   v1.ChainFamilyEVM,
		Network:       "ethereum-sepolia",
		RequestID:     "req-123",
		SourceAddress: "0xYourSignerAddress",
	},
	ChainID:              11155111,
	To:                   "0x1111111111111111111111111111111111111111",
	Value:                "1",
	Nonce:                7,
	GasLimit:             21000,
	MaxFeePerGas:         "1500",
	MaxPriorityFeePerGas: "100",
})
```
