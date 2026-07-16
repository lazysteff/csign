# Keys and shared signing fields

[API index](../API.md)

## Key API

### `POST v1/keys`

Creates a new chain-bound key record.

Request type: `CreateKeyRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `key_id` | string | no | Explicit key identifier. If omitted, the plugin generates one. Hierarchical slash-delimited IDs are supported end-to-end. |
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
- A missing or empty `allowed_signing_operations` policy is valid but intentionally denies every signing route.

### `LIST v1/keys`

Lists configured key IDs.

The plugin recursively traverses the `keys/` storage subtree and returns full logical leaf `key_id` values only. Intermediate prefixes are never returned as keys.

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

Reads a key record. The route is greedy over the remaining path, so hierarchical slash-delimited `key_id` values are read unchanged.

Response type: `KeyResponse`

### `POST v1/key-status/:key_id`

Enables or disables a key. This is the only supported status mutation route.

Request type: `UpdateKeyStatusRequest`

```json
{
  "active": false
}
```

Response type: `KeyResponse`

The former `POST v1/keys/:key_id/status` route has been removed.

### `POST v1/key-policy/:key_id`

Replaces the structured, enforced policy fields attached to an existing key. This route is intentionally outside the greedy `v1/keys/:key_id` subtree and supports hierarchical key IDs.

Request type: `UpdateKeyPolicyRequest`

The nested `policy` member uses the canonical `Policy` fields (`StructuredPolicy` is a compatibility alias). The update decoder deliberately rejects opaque application metadata.

```json
{
  "policy": {
    "allowed_networks": ["ethereum-sepolia"],
    "allowed_chain_ids": [11155111],
    "allowed_signing_operations": ["evm_eip712_typed"],
    "allowed_eip712_schemas": ["eip2612-permit-v1"],
    "allowed_token_contracts": ["0x2222222222222222222222222222222222222222"],
    "allowed_contract_destinations": ["0x3333333333333333333333333333333333333333"],
    "max_value": "1000000000000000000"
  }
}
```

Response type: `KeyResponse`

This operation is replacement, not merge. The top-level `policy` member is required and must not be `null`; `{"policy": {}}` explicitly replaces the policy with a deny-all operation policy. Include every network, chain, destination, selector, value, gas, fee, protocol, delegate, and other guardrail that must remain active. Unknown, non-canonical, or duplicate operation identifiers reject the complete write. The request rejects unknown fields, including `additional_policy_context`; an already stored deprecated value remains server-managed and cannot be created, replaced, or cleared through this route.

See [Signing-operation policy](signing-operations.md) for the complete registry and replacement/rollout rules.

## Direct signing request base fields

Direct EOA transfer/contract-call and TRON transfer endpoints share these base fields through `BaseSignRequest`.

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `key_id` | string | yes | Key record to use. |
| `chain_family` | string | yes | Must match the endpoint family. |
| `network` | string | yes | Logical network name enforced by policy if configured. |
| `request_id` | string | yes | Caller correlation identifier. |
| `labels` | object | no | Arbitrary caller metadata. |
| `approval_ref` | string | no | Approval system reference. |
| `source_address` | string | yes | Must match the stored signer address for the key. |

TRON Stake 2.0 resource routes do not use `BaseSignRequest`. They use the same correlation and workflow fields plus `owner_address` instead of `source_address`. This matches TRON stake/delegation contract terminology.

Direct transaction endpoints return `SignResponse`:

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
