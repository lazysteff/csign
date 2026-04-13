# chain-signer

`chain-signer` is a HashiCorp Vault external plugin for typed transaction signing on EVM and TRON networks.

It is designed for teams that want applications to request signatures through Vault without exposing raw private keys or a generic `sign(hash)` / `sign(bytes)` endpoint. Instead of handing arbitrary payloads to a signer, callers submit structured transaction fields for a supported operation, and the plugin returns a signed transaction payload.

## Why use chain-signer

- Reduce blast radius. Applications can sign only supported transaction types.
- Enforce policy at the signing boundary. Keys can restrict networks, chain IDs, value, gas, fee limits, token contracts, and contract selectors.
- Keep Vault in the control plane. You can use Vault auth, ACLs, audit logging, plugin registration, and mount-level isolation.
- Support more than one custody model. Use plugin-managed keys for simple deployments or wire in an external signer for HSM-style setups.

## What it supports today

- EVM legacy native transfer
- EVM EIP-1559 native transfer
- EVM EIP-1559 contract call
- TRON TRX transfer
- TRON TRC-20 transfer through `transfer(address,uint256)`
- TRON Stake 2.0 freeze balance v2
- TRON Stake 2.0 unfreeze balance v2
- TRON resource delegation
- TRON resource undelegation
- TRON withdraw expired unfreeze

All application-facing signing is typed. There is currently no generic raw signing endpoint.

## How it works

1. Build and register the plugin with Vault as an external `secret` plugin.
2. Mount it at a path such as `chain-signer/`.
3. Create a key bound to a chain family and an optional policy.
4. Call a typed `/v1/.../sign` endpoint with structured transaction fields.
5. Use `/v1/verify` or `/v1/recover` when you need signer recovery and payload validation.

Detailed HTTP API reference: [docs/API.md](docs/API.md)

## Key custody modes

- `mvp`: the plugin generates or imports a secp256k1 private key and stores it in the plugin's Vault-backed storage.
- `pkcs11`: the key record stores a public key plus `external_signer_ref`, and signing is delegated through an injected external signer resolver.

This repository includes the external signer abstraction and conformance coverage for that flow. It does not ship a turnkey PKCS#11 runtime integration module.

## Vault paths

- `v1/version`
- `v1/keys`
- `v1/keys/<key_id>`
- `v1/keys/<key_id>/status`
- `v1/evm/transfers/legacy/sign`
- `v1/evm/transfers/eip1559/sign`
- `v1/evm/contracts/eip1559/sign`
- `v1/tron/transfers/trx/sign`
- `v1/tron/transfers/trc20/sign`
- `v1/tron/resources/freeze_v2/sign`
- `v1/tron/resources/unfreeze_v2/sign`
- `v1/tron/resources/delegate/sign`
- `v1/tron/resources/undelegate/sign`
- `v1/tron/resources/withdraw_expire_unfreeze/sign`
- `v1/verify`
- `v1/recover`

## Build

### Prerequisites

- Go 1.26.2 or newer
- `make`
- A Vault deployment with external plugin support if you want to run the plugin end-to-end

### Compile the plugin

```bash
make build
```

This produces `dist/chain-signer-plugin`.

### Create a versioned release artifact

```bash
./packaging/release.sh
```

This creates `dist/<version>/chain-signer-plugin`, a SHA-256 checksum file, and `version.txt`.

## Register and mount in Vault

1. Configure Vault with a plugin directory.
2. Copy `dist/chain-signer-plugin` into that directory.
3. Register the plugin checksum in the Vault plugin catalog.
4. Enable the plugin at a mount path.
5. Apply Vault ACLs so each caller can access only the typed endpoints it needs.

Example:

```bash
vault plugin register \
  -sha256="$(shasum -a 256 dist/chain-signer-plugin | awk '{print $1}')" \
  secret \
  chain-signer-plugin

vault secrets enable \
  -path=chain-signer \
  -plugin-name=chain-signer-plugin \
  plugin
```

After mounting, the plugin is available under `chain-signer/v1/...`.

## How to use it

You can call the plugin through the Vault CLI, the Vault HTTP API, or the Go client in `pkg/client`. The examples below use the Vault HTTP API because it maps directly to the plugin's JSON request and response types.

For the full endpoint reference, field definitions, error behavior, and a complete happy-path flow, see [docs/API.md](docs/API.md).

### 1. Create a key

Example EVM key with policy guardrails:

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
    "max_priority_fee_per_gas": "1000000000",
    "allowed_token_contracts": ["0x2222222222222222222222222222222222222222"],
    "allowed_selectors": ["a9059cbb"]
  }
}
JSON
```

The response includes the signer address, public key, policy, and timestamps. It does not return the private key.

If you want to use an external signer, create the key with `custody_mode` set to `pkcs11`, and provide `public_key_hex` plus `external_signer_ref` instead of `import_private_key_hex`.

### 2. Sign a transaction

Example EVM EIP-1559 native transfer:

```bash
curl \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  --header "Content-Type: application/json" \
  --request POST \
  --data @- \
  "${VAULT_ADDR}/v1/chain-signer/v1/evm/transfers/eip1559/sign" <<'JSON'
{
  "key_id": "payments-evm",
  "chain_family": "evm",
  "network": "ethereum-sepolia",
  "request_id": "req-123",
  "source_address": "0xYourSignerAddress",
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

The plugin rejects requests when the key is disabled, the `source_address` does not match the stored signer address, or the request violates the configured policy.

The response includes:

- `signer_address`
- `tx_hash`
- `signed_payload`
- `payload_encoding`

For EVM, `signed_payload` is the signed transaction bytes encoded as hex. For TRON, it is the signed protobuf transaction encoded as hex.

### 3. Verify or recover a signed payload

Use `verify` when you want the plugin to compare the recovered signer and, optionally, the operation you expect:

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
  "signed_payload": "0x...",
  "expected_signer_address": "0xYourSignerAddress"
}
JSON
```

Use `recover` when you want the recovered signer, operation, and transaction hash back without enforcing an expectation.

### TRON requests

The TRON signing endpoints require the transaction envelope fields expected by TRON signing, including:

- `ref_block_bytes`
- `ref_block_hash`
- `timestamp`
- `expiration`

`fee_limit` remains required on the existing TRX and TRC-20 routes. On the new Stake 2.0 resource routes it is optional and, when omitted, defaults to `0` in TRON `raw_data`.

Use `v1/tron/transfers/trx/sign` for TRX transfers and `v1/tron/transfers/trc20/sign` for TRC-20 transfers.

Use the new resource routes for treasury operations:

- `v1/tron/resources/freeze_v2/sign`
- `v1/tron/resources/unfreeze_v2/sign`
- `v1/tron/resources/delegate/sign`
- `v1/tron/resources/undelegate/sign`
- `v1/tron/resources/withdraw_expire_unfreeze/sign`

The new resource routes intentionally use `owner_address` instead of `source_address`. This matches TRON stake and delegation contract semantics and is not a migration of the older transfer request schemas.

`/v1/version` now returns `supported_routes`, a lexicographically sorted list of public callable mount-relative routes. Callers can use it to detect whether a mounted plugin supports the new TRON resource operations.

## Use from Go

The repository ships with a small Vault client package at `github.com/chain-signer/chain-signer/pkg/client`.
The client is organized by capability through `Keys`, `Signing`, and `Payloads`.

```go
package main

import (
	"context"
	"log"
	"os"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	csclient "github.com/chain-signer/chain-signer/pkg/client"
	"github.com/hashicorp/vault/api"
)

func main() {
	vaultClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		log.Fatal(err)
	}
	vaultClient.SetAddress(os.Getenv("VAULT_ADDR"))
	vaultClient.SetToken(os.Getenv("VAULT_TOKEN"))

	client := csclient.NewFromVault(vaultClient, "chain-signer")

	resp, err := client.Signing.SignEVMEIP1559Transfer(context.Background(), v1.EVMEIP1559TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "payments-evm",
			ChainFamily:   "evm",
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
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("tx hash: %s", resp.TxHash)
}
```

## Test

Run the full test suite:

```bash
make test
```

This runs the Go tests in the repository, including the conformance suite in `tests/conformance`. The tests exercise the backend through Vault's logical test harness, so they do not require a live Vault server.

## Development

Useful commands:

```bash
make fmt
make tidy
make build
make test
```

Key source directories:

- `cmd/chain-signer-plugin`: Vault plugin entrypoint
- `pkg/api/v1`: request and response contracts
- `pkg/client`: Go client for calling the plugin through Vault
- `internal/vaultbackend`: Vault transport adapter and error mapping
- `internal/service`: key lifecycle, signing orchestration, and recovery services
- `internal/chain`: EVM and TRON signing and recovery logic
- `tests/conformance`: end-to-end backend conformance tests

## Contributing

Contributions are welcome.

If you want to help:

- open an issue for bugs, missing features, or API design questions
- send a pull request for fixes, tests, docs, or new typed signing operations
- keep changes scoped and well documented
- add or update tests when behavior changes
- run `make fmt`, `make test`, and `make build` before opening a PR

Useful areas for contribution include additional typed transaction support, stronger policy controls, external signer integrations, deployment examples, and documentation improvements.
