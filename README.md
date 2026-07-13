# chain-signer

`chain-signer` is a HashiCorp Vault external plugin for typed transaction and structured protocol signing on EVM and TRON networks.

It is designed for teams that want applications to request signatures through Vault without exposing raw private keys or a generic `sign(hash)` / `sign(bytes)` endpoint. Instead of handing arbitrary payloads to a signer, callers submit structured protocol fields for a supported operation, and the plugin returns a verified signature or signed transaction artifact.

## Why use chain-signer

- Reduce blast radius. Applications can sign only supported transaction types.
- Enforce policy at the signing boundary. Keys can restrict networks, chain IDs, value, gas, fee limits, token contracts, and contract selectors.
- Keep Vault in the control plane. You can use Vault auth, ACLs, audit logging, plugin registration, and mount-level isolation.
- Support more than one custody model. Use plugin-managed keys for simple deployments or wire in an external signer for HSM-style setups.

## What it supports today

- EVM legacy native transfer
- EVM EIP-1559 native transfer
- EVM EIP-1559 contract call
- constrained EIP-712 signing for the fixed ERC-2612 `Permit` schema `eip2612-permit-v1`
- ERC-4337 v0.9 UserOperation signing for SimpleAccount `0.9`
- EIP-7702 authorization signing with schema `eip7702-v1`
- EIP-7702 type-4 transaction signing and recovery
- TRON TRX transfer
- TRON TRC-20 transfer through `transfer(address,uint256)`
- TRON Stake 2.0 freeze balance v2
- TRON Stake 2.0 unfreeze balance v2
- TRON resource delegation
- TRON resource undelegation
- TRON withdraw expired unfreeze
- TRON vote witness
- TRON SR/voter reward claim

All application-facing signing is typed. There is no generic raw-hash, arbitrary-byte, arbitrary EIP-712, or unsigned-transaction signing endpoint.

## How it works

1. Build and register the plugin with Vault as an external `secret` plugin.
2. Mount it at a path such as `chain-signer/`.
3. Create a key bound to a chain family and an optional policy.
4. Call a typed `/v1/.../sign` endpoint with structured transaction fields.
5. Use `/v1/verify` or `/v1/recover` for legacy transaction inspection, or the dedicated EIP-712, ERC-4337, and EIP-7702 inspection routes for structured verification and recovery.

Detailed HTTP API reference: [docs/API.md](docs/API.md)

## Key custody modes

- `mvp`: the plugin generates or imports a secp256k1 private key and stores it in the plugin's Vault-backed storage.
- `pkcs11`: the key record stores a public key plus `external_signer_ref`, and signing is delegated through an injected external signer resolver.

This repository includes the external signer abstraction and conformance coverage for that flow. It does not ship a turnkey PKCS#11 runtime integration module.

The advanced EVM operations use the same custody abstraction as existing routes. An external implementation must supply both the public key and a valid secp256k1 digest signature. CSign canonicalizes low-S signatures, determines recovery parity, checks that the custody public key matches the stored key, and verifies the produced artifact before returning it. The shipped plugin executable supports `mvp` directly; `pkcs11` remains an integration point that must be wired by the embedding deployment.

## Vault paths

- `v1/version`
- `v1/keys`
- `v1/keys/<key_id>`
- `v1/key-status/<key_id>`
- `v1/key-policy/<key_id>`
- `v1/evm/transfers/legacy/sign`
- `v1/evm/transfers/eip1559/sign`
- `v1/evm/contracts/eip1559/sign`
- `v1/evm/eip712/sign`
- `v1/evm/eip712/verify`
- `v1/evm/erc4337/user-operations/sign`
- `v1/evm/erc4337/user-operations/verify`
- `v1/evm/eip7702/authorizations/sign`
- `v1/evm/eip7702/authorizations/verify`
- `v1/evm/eip7702/transactions/sign`
- `v1/evm/eip7702/transactions/recover`
- `v1/tron/transfers/trx/sign`
- `v1/tron/transfers/trc20/sign`
- `v1/tron/resources/freeze_v2/sign`
- `v1/tron/resources/unfreeze_v2/sign`
- `v1/tron/resources/delegate/sign`
- `v1/tron/resources/undelegate/sign`
- `v1/tron/resources/withdraw_expire_unfreeze/sign`
- `v1/tron/governance/vote_witness/sign`
- `v1/tron/rewards/withdraw_balance/sign`
- `v1/verify`
- `v1/recover`

Hierarchical slash-delimited `key_id` values are supported end-to-end. A valid `key_id` is one or more non-empty `/`-delimited segments such as `gateway/tron/hot/main` or `orgs/123/signing/default`.

`GET v1/keys/<key_id>` is greedy over the remaining path, `POST v1/key-status/<key_id>` changes activation, `POST v1/key-policy/<key_id>` replaces the structured, enforced policy fields, and `LIST v1/keys` returns full hierarchical key IDs. Policy updates reject opaque `additional_policy_context`; any such deprecated context already stored on a legacy key is preserved server-side but cannot be created or changed through the update route. Invalid key forms such as leading slash, trailing slash, empty segments, `.` segments, and `..` segments are rejected. Clients must validate decoded values and escape path segments individually; percent-encoding must not be used to give `/` alternate semantics.

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

This first runs `make verify`. If tests or golangci-lint fail, no release artifact is created. When verification passes, it creates `dist/<version>/chain-signer-plugin`, a SHA-256 checksum file, and `version.txt`.

`make verify` also performs a read-only network check that every direct Go module is pinned to the latest stable compatible release available at build time. Builds continue to use the exact versions in `go.mod` and `go.sum`; the check fails instead of silently changing the dependency graph.

### Publish a release

```bash
VERSION=v0.6.0 make publish-release
```

This is the supported release path. It requires a clean `main` worktree, verifies the changelog entry, runs the gated artifact build, creates and pushes the annotated tag, and lets the GitHub Actions release workflow publish the GitHub release. The workflow runs the same verification gate again before uploading release assets.

The requested `VERSION` must match `internal/version/version.go`; mismatches are rejected before any tag or GitHub release is created.

Do not create GitHub releases manually. Manual release creation bypasses the test and lint gate.

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

Vault authorizes the plugin's POST routes as the `update` capability. Keep policy administration separate from application signing. For example, a signing application can receive only the routes it uses:

```hcl
path "chain-signer/v1/version" {
  capabilities = ["read"]
}

path "chain-signer/v1/evm/eip712/sign" {
  capabilities = ["update"]
}

path "chain-signer/v1/evm/eip712/verify" {
  capabilities = ["update"]
}
```

Grant policy replacement separately to an administrator:

```hcl
path "chain-signer/v1/key-policy/payments-evm" {
  capabilities = ["update"]
}
```

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

### Advanced EVM signing

Advanced EVM signing is deliberately narrow, versioned, and default-deny:

- EIP-712: schema `eip2612-permit-v1`, schema version `1`, fixed primary type `Permit`
- ERC-4337: protocol `erc4337-v0.9`, account implementation `simple-account` version `0.9`, signing schema `simple-account-eip712-v1`, signature encoding `rsv-v27`
- EIP-7702 authorization: schema `eip7702-v1`
- EIP-7702 transaction: capability `eip7702-type-4`, type number `4`

Read `v1/version` before signing to discover the exact compiled capabilities. A key must explicitly allow the operation, network, chain ID, and each operation-specific schema, implementation, EntryPoint, delegate, destination, or transaction type.

Advanced requests reject unknown fields and use canonical decimal quantities plus lowercase `0x`-encoded protocol values. CSign reconstructs and verifies every artifact locally; it does not query chain state, allocate nonces, simulate account validation, or broadcast transactions.

See the focused references for [protocol requests and responses](docs/api/evm.md), [policy and custody boundaries](docs/api/policy.md), and [wire conventions](docs/api/conventions.md).

### TRON requests

The TRON signing endpoints require the transaction envelope fields expected by TRON signing, including:

- `ref_block_bytes`
- `ref_block_hash`
- `timestamp`
- `expiration`

`fee_limit` remains required on the existing TRX and TRC-20 routes. On the owner-based Stake 2.0, governance, and reward routes it is optional and, when omitted, defaults to `0` in TRON `raw_data`.

Use `v1/tron/transfers/trx/sign` for TRX transfers and `v1/tron/transfers/trc20/sign` for TRC-20 transfers.

Use the owner-based TRON routes for treasury, governance, and reward operations:

- `v1/tron/resources/freeze_v2/sign`
- `v1/tron/resources/unfreeze_v2/sign`
- `v1/tron/resources/delegate/sign`
- `v1/tron/resources/undelegate/sign`
- `v1/tron/resources/withdraw_expire_unfreeze/sign`
- `v1/tron/governance/vote_witness/sign`
- `v1/tron/rewards/withdraw_balance/sign`

The new resource routes intentionally use `owner_address` instead of `source_address`. This matches TRON stake and delegation contract semantics and is not a migration of the older transfer request schemas.

`v1/tron/governance/vote_witness/sign` signs a complete `VoteWitnessContract` vote allocation. The submitted `votes` list replaces the owner's prior vote allocation; callers must not send deltas. `csign` rejects empty lists, more than 30 vote entries, non-positive `vote_count` values, invalid TRON addresses, and duplicate normalized witness addresses. It does not enforce witness allowlists, allocation strategy, available TRON Power, witness eligibility, or any live-chain cap.

`v1/tron/rewards/withdraw_balance/sign` signs `WithdrawBalanceContract` for SR/voter reward claiming and allowance withdrawal. It is separate from `v1/tron/resources/withdraw_expire_unfreeze/sign`, which withdraws matured Stake 2.0 unstake entries after `UnfreezeBalanceV2Contract`.

The new routes are forward-only. There is no migration, alias route, compatibility layer for older request shapes, or support for previously submitted signing requests. Recovery remains stateless and may classify any structurally valid signed TRON payload for a supported contract type, including payloads created outside `csign`.

`/v1/version` returns `supported_routes`, a lexicographically sorted list of public callable mount-relative routes, plus typed, versioned advanced-EVM protocol capabilities. Callers can use it to detect whether a mounted plugin supports a route and the exact signing schema behind it.

## Use from Go

The repository ships with a small Vault client package at `github.com/chain-signer/chain-signer/pkg/client`.
The client is organized by capability through `Keys`, `Signing`, and `Payloads`.

Advanced methods are `Keys.SetPolicy`, `Signing.SignEVMEIP712`, `Signing.SignEVMUserOperation`, `Signing.SignEVMEIP7702Authorization`, `Signing.SignEVMEIP7702Transaction`, `Payloads.VerifyEVMEIP712`, `Payloads.VerifyEVMUserOperation`, `Payloads.VerifyEVMEIP7702Authorization`, and `Payloads.RecoverEVMEIP7702Transaction`. `Keys.SetPolicy` accepts `v1.StructuredPolicy`, which contains only typed, enforced policy fields. `Client.Version` returns typed protocol capabilities used to select compatible schema and protocol identifiers. Classified advanced errors are exposed as `*client.APIError`; `client.ErrorCode(err)` returns a typed `v1.ErrorCode` for comparison with constants such as `v1.ErrorUnsupportedEIP712Schema`.

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

Run linting:

```bash
make lint
```

Run the release verification checks:

```bash
make verify
```

This checks direct dependencies for newer compatible releases, then runs `make test` and `make lint`. The lint target uses `golangci-lint` and the repository's `.golangci.yml` configuration.

## Development

Useful commands:

```bash
make fmt
make tidy
make build
make test
make lint
make lint-backend
make verify
make release
make publish-release
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
- run `make fmt`, `make build`, and `make verify` before opening a PR

Useful areas for contribution include additional typed transaction support, stronger policy controls, external signer integrations, deployment examples, and documentation improvements.
