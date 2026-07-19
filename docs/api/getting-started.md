# API getting started

[API index](../API.md)

## Happy path: EVM EIP-1559 transfer

This is the simplest end-to-end flow for a new caller:

1. Read plugin version.
2. Create an EVM signing key with guardrails.
3. Read the key record and capture `signer_address`.
4. Sign an EIP-1559 native transfer.
5. Verify the signed payload.

### 1. Read version

```bash
curl \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/chain-signer/v1/version"
```

Abridged example response body (the operation catalog below shows two of the registered entries):

```json
{
  "data": {
    "api_version": "v1",
    "build_version": "v1.1.1",
    "supported_routes": [
      "v1/evm/contracts/eip1559/sign",
      "v1/evm/eip712/sign",
      "v1/evm/eip712/verify",
      "v1/evm/eip7702/authorizations/sign",
      "v1/evm/eip7702/authorizations/verify",
      "v1/evm/eip7702/transactions/recover",
      "v1/evm/eip7702/transactions/sign",
      "v1/evm/erc4337/user-operations/sign",
      "v1/evm/erc4337/user-operations/verify",
      "v1/evm/transfers/eip1559/sign",
      "v1/evm/transfers/legacy/sign",
      "v1/key-policy/{key_id}",
      "v1/key-status/{key_id}",
      "v1/keys",
      "v1/keys/{key_id}",
      "v1/recover",
      "v1/tron/governance/vote_witness/sign",
      "v1/tron/resources/delegate/sign",
      "v1/tron/resources/freeze_v2/sign",
      "v1/tron/resources/undelegate/sign",
      "v1/tron/resources/unfreeze_v2/sign",
      "v1/tron/resources/withdraw_expire_unfreeze/sign",
      "v1/tron/rewards/withdraw_balance/sign",
      "v1/tron/transfers/trc20/sign",
      "v1/tron/transfers/trx/sign",
      "v1/verify",
      "v1/version"
    ],
    "supported_signing_operations": [
      {
        "route": "v1/evm/transfers/legacy/sign",
        "operation": "evm_transfer_legacy"
      },
      {
        "route": "v1/evm/transfers/eip1559/sign",
        "operation": "evm_transfer_eip1559"
      }
    ],
    "supported_eip712_schemas": [
      {
        "id": "eip2612-permit-v1",
        "version": "1",
        "primary_type": "Permit",
        "signature_encoding": "rsv-v27"
      }
    ],
    "supported_erc4337_protocol_versions": ["erc4337-v0.9"],
    "supported_account_implementations": [
      {
        "id": "simple-account",
        "version": "0.9",
        "protocol_versions": ["erc4337-v0.9"],
        "signing_schemas": ["simple-account-eip712-v1"],
        "signature_encoding": "rsv-v27"
      }
    ],
    "supported_account_signing_schemas": ["simple-account-eip712-v1"],
    "supported_eip7702_authorization_schemas": ["eip7702-v1"],
    "supported_eip7702_transaction_types": [
      {
        "id": "eip7702-type-4",
        "number": 4
      }
    ]
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
    "allowed_signing_operations": ["evm_transfer_eip1559"],
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
      "allowed_signing_operations": ["evm_transfer_eip1559"],
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
