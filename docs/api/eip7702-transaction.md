# EIP-7702 type-4 transaction

[EVM index](evm.md) · [API index](../API.md)

Route: `POST v1/evm/eip7702/transactions/sign`

Request type: `EVMEIP7702TransactionSignRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `key_id`, `chain_family`, `network`, `request_id` | string | yes | Executor key, protocol context, and correlation identifier. |
| `source_address` | address | yes | Executor; must match the selected key. |
| `chain_id` | decimal string | yes | Positive uint256 and policy-allowed. |
| `nonce` | decimal string | yes | uint64 supplied by the caller. |
| `to` | address | yes | Type-4 destination; must be in `allowed_contract_destinations`. |
| `value` | decimal string | yes | uint256, subject to `max_value`. |
| `gas_limit` | decimal string | yes | Positive uint64, subject to `max_gas_limit`. |
| `max_fee_per_gas` | decimal string | yes | uint256, subject to policy. |
| `max_priority_fee_per_gas` | decimal string | yes | uint256, no greater than max fee and subject to policy. |
| `data` | hex bytes | yes | Complete calldata. When `allowed_selectors` is configured, this must contain at least a 4-byte selector and that selector must be allowed. |
| `access_list` | array of `EVMAccessTuple` | no | May be omitted, null, or empty. Storage keys, when present, are exact 32-byte hex values. |
| `authorization_list` | array of `EIP7702SignedAuthorization` | yes | Must be non-empty and no larger than `max_authorization_list_entries`. |

Each `EVMAccessTuple` contains an `address` and a `storage_keys` array of exact 32-byte hashes.

Each authorization-list entry is the exact EIP-7702 signed tuple: `chain_id`, `address`, `nonce`, `y_parity`, `r`, and `s`. CSign maps it directly to `go-ethereum/core/types.SetCodeAuthorization`, recovers the authority, and uses that recovered address for validation and duplicate detection. It rejects malformed or high-S signatures, parity outside 0/1, non-wildcard chain mismatches, forbidden wildcard/revocation/delegate entries, and any repeated recovered authority. Authority comparison is available only on the dedicated authorization-verification route.

Example request using fields returned by the authorization route:

```json
{
  "key_id": "payments-evm",
  "chain_family": "evm",
  "network": "ethereum-sepolia",
  "request_id": "type4-001",
  "source_address": "0x1111111111111111111111111111111111111111",
  "chain_id": "11155111",
  "nonce": "12",
  "to": "0x6666666666666666666666666666666666666666",
  "value": "0",
  "gas_limit": "250000",
  "max_fee_per_gas": "2000000000",
  "max_priority_fee_per_gas": "1000000000",
  "data": "0x",
  "access_list": [],
  "authorization_list": [
    {
      "chain_id": "11155111",
      "address": "0x5555555555555555555555555555555555555555",
      "nonce": "8",
      "y_parity": 0,
      "r": "0x0000000000000000000000000000000000000000000000000000000000000001",
      "s": "0x0000000000000000000000000000000000000000000000000000000000000002"
    }
  ]
}
```

The `r`, `s`, and `y_parity` values above illustrate the required wire shape; use the actual values returned by authorization signing.

Response type: `EVMEIP7702TransactionSignResponse`

```json
{
  "data": {
    "api_version": "v1",
    "key_id": "payments-evm",
    "chain_family": "evm",
    "network": "ethereum-sepolia",
    "operation": "evm_eip7702_transaction",
    "signer_address": "0x1111111111111111111111111111111111111111",
    "request_id": "type4-001",
    "transaction_type": "eip7702-type-4",
    "transaction_hash": "0x...",
    "transaction_signing_hash": "0x...",
    "signed_payload": "0x04...",
    "payload_encoding": "hex"
  }
}
```

CSign constructs the type-4 envelope, validates and recovers every embedded authorization, signs with the executor key, serializes the final transaction, and recovers the executor again before returning.

## `POST v1/evm/eip7702/transactions/recover`

Request type: `EVMEIP7702TransactionRecoverRequest`:

```json
{
  "chain_family": "evm",
  "network": "ethereum-sepolia",
  "request_id": "type4-recover-001",
  "signed_payload": "0x04...",
  "expected_signer_address": "0x1111111111111111111111111111111111111111"
}
```

`expected_signer_address` is optional. When supplied, the response compares it with the recovered executor; a mismatch returns `matches_expected: false` rather than suppressing the recovered artifact. Response type `EVMEIP7702TransactionRecoverResponse` returns the type-4 transaction hash/type, recovered and expected executor, `matches_expected`, and a fully decoded transaction including each recovered authorization authority.

```json
{
  "data": {
    "api_version": "v1",
    "chain_family": "evm",
    "network": "ethereum-sepolia",
    "operation": "evm_eip7702_transaction",
    "transaction_hash": "0x...",
    "transaction_type": "eip7702-type-4",
    "recovered_signer": "0x1111111111111111111111111111111111111111",
    "expected_signer": "0x1111111111111111111111111111111111111111",
    "matches_expected": true,
    "decoded_transaction": {
      "chain_id": "11155111",
      "nonce": "12",
      "to": "0x6666666666666666666666666666666666666666",
      "value": "0",
      "gas_limit": "250000",
      "max_fee_per_gas": "2000000000",
      "max_priority_fee_per_gas": "1000000000",
      "data": "0x",
      "access_list": [],
      "authorization_list": [
        {
          "authority_address": "0x1111111111111111111111111111111111111111",
          "chain_id": "11155111",
          "address": "0x5555555555555555555555555555555555555555",
          "nonce": "8",
          "y_parity": 0,
          "r": "0x...",
          "s": "0x..."
        }
      ]
    },
    "request_id": "type4-recover-001"
  }
}
```
