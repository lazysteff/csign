# chain-signer

`chain-signer` is a standalone Vault external plugin for typed EVM and TRON signing. The repository owns the Vault backend, generic Go client, API contracts, policy engine, typed signing logic, conformance tests, packaging, and deployment instructions.

## Current scope

- EVM legacy native transfer
- EVM EIP-1559 native transfer
- EVM EIP-1559 contract call
- TRON TRX transfer
- TRON TRC-20 transfer through `TriggerSmartContract.transfer(address,uint256)`

There is no generic `sign(hash)` or `sign(bytes)` endpoint for application roles. All application-facing signing is typed.

## Repository layout

- `cmd/chain-signer-plugin`: Vault plugin entrypoint
- `pkg/api/v1`: request and response contracts
- `pkg/backend`: Vault backend paths and handlers
- `pkg/client`: generic Vault client
- `pkg/model`: shared constants, policy model, key metadata helpers
- `pkg/policy`: policy enforcement
- `pkg/signer`: EVM and TRON signing and recovery logic
- `pkg/storage`: Vault storage helpers
- `tests/conformance`: signing and policy tests
- `packaging`: release packaging helpers

## Build

```bash
make build
```

This produces `dist/chain-signer-plugin`.

## Test

```bash
make test
```

## Vault registration

1. Build the plugin binary.
2. Place the binary in Vault's plugin directory.
3. Register the checksum in the Vault plugin catalog.
4. Mount the plugin under a chosen path, for example `chain-signer/`.
5. Provision ACLs so callers can only reach the typed `v1` endpoints they need.

Example registration flow:

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

## Key modes

- `mvp`: plugin-managed secp256k1 keys
- `pkcs11`: external signer mode for HSM-backed secp256k1 keys, addressed through `external_signer_ref`

The plugin-managed mode is fully self-contained. The PKCS#11 mode uses the same typed backend paths but expects the runtime to inject an external signer resolver for the configured `external_signer_ref`.
