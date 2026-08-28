# API conventions and discovery

[API index](../API.md)

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
- `POST v1/key-status/:key_id`
- `POST v1/key-policy/:key_id`

### Signing

- `POST v1/evm/transfers/legacy/sign`
- `POST v1/evm/transfers/eip1559/sign`
- `POST v1/evm/contracts/eip1559/sign`
- `POST v1/evm/eip712/sign`
- `POST v1/evm/erc4337/user-operations/sign`
- `POST v1/evm/eip7702/authorizations/sign`
- `POST v1/evm/eip7702/transactions/sign`
- `POST v1/tron/governance/vote_witness/sign`
- `POST v1/tron/rewards/withdraw_balance/sign`
- `POST v1/tron/transfers/trx/sign`
- `POST v1/tron/transfers/trc20/sign`
- `POST v1/tron/resources/freeze_v2/sign`
- `POST v1/tron/resources/unfreeze_v2/sign`
- `POST v1/tron/resources/delegate/sign`
- `POST v1/tron/resources/undelegate/sign`
- `POST v1/tron/resources/withdraw_expire_unfreeze/sign`

### Payload inspection

- `POST v1/verify`
- `POST v1/recover`
- `POST v1/evm/eip712/verify`
- `POST v1/evm/erc4337/user-operations/verify`
- `POST v1/evm/eip7702/authorizations/verify`
- `POST v1/evm/eip7702/transactions/recover`

## Capability discovery

### `GET v1/version`

Returns the plugin build version and typed protocol-capability contract.

Response type: `VersionResponse`

| Field | Type | Meaning |
| --- | --- | --- |
| `api_version` | string | Wire contract version. Currently `v1`. |
| `build_version` | string | Plugin build identifier. |
| `supported_routes` | array of string | Lexicographically sorted public mount-relative routes exposed by the plugin. |
| `supported_signing_operations` | array of `SigningOperationCapability` | Canonical registered signing route and exact policy operation identifier. This describes compiled support, not Vault ACL access, per-key enablement, external custody availability, or deployment readiness. |
| `supported_eip712_schemas` | array of `EIP712SchemaCapability` | Registered schema ID, version, fixed primary type, and signature encoding, including ERC-2612 Permit and verifying-Paymaster approval schemas. |
| `supported_erc4337_protocol_versions` | array of string | Supported UserOperation protocol identifiers. Currently `erc4337-v0.9`. |
| `supported_account_implementations` | array of `ERC4337AccountCapability` | Account implementation/version, compatible protocols, signing schemas, and signature encoding. |
| `supported_account_signing_schemas` | array of string | Supported account signature behavior identifiers. Currently `simple-account-eip712-v1`. |
| `supported_eip7702_authorization_schemas` | array of string | Supported authorization hashing/encoding schemas. Currently `eip7702-v1`. |
| `supported_eip7702_transaction_types` | array of `EIP7702TransactionCapability` | Supported transaction capability ID and numeric envelope type. Currently `eip7702-type-4`, type `4`. |
| `supported_tron_memo_capabilities` | array of `TRONMemoCapability` | Byte-preserving memo encoding, serialized transaction ceiling, and exact TRON signing operations that accept `memo_hex`. Currently hex on TRX and TRC-20 transfers with a 512000-byte transaction ceiling. |

Callers should check `supported_signing_operations` and the relevant versioned protocol capability. The operation mapping is the authoritative policy vocabulary; a route name alone does not identify schema or account-signing behavior.

## Data conventions

- `chain_family` must be `evm` or `tron`.
- `custody_mode` must be `mvp` or `pkcs11`.
- EVM addresses are hex addresses. The plugin normalizes them before comparison.
- TRON addresses are Base58 addresses.
- TRX and TRC-20 `memo_hex` values are optional plain or `0x`-prefixed hexadecimal bytes. They are decoded into `TransactionRaw.data` without UTF-8 interpretation. Memo data is public on-chain.
- Direct-transaction numeric strings such as EVM `value`, `gas_price`, and `max_fee_per_gas`, plus TRC-20 `amount`, accept decimal values and `0x`-prefixed hexadecimal. EVM transaction values are parsed as unsigned uint256 values; negative, malformed, or overflowing values are rejected.
- Every wide protocol quantity on typed-data, account-abstraction, and authorization routes is a canonical base-10 string. It must contain only digits and must not contain a sign, whitespace, a hexadecimal prefix, or a leading zero unless the entire value is `"0"`. Small discriminators such as `y_parity` and capability `number` remain JSON numbers.
- Addresses in these structured EVM requests must be exactly 20 bytes encoded as lowercase, `0x`-prefixed hexadecimal. Byte strings, hashes, signatures, and signature scalars must also be lowercase and `0x`-prefixed; fixed-size values must have their exact encoded length.
- EVM `KeyResponse.signer_address` values use checksum casing. Lowercase that value before reusing it in a structured EVM request.
- Structured EVM request types reject unknown JSON fields, including unknown nested domain, message, UserOperation, authorization, transaction, access-list, and policy-update fields.
- `signed_payload` is always returned as a hex string and `payload_encoding` is currently always `hex`.
- `request_id`, `approval_ref`, and `labels` are accepted on direct EOA and TRON transaction requests as caller metadata. They are not echoed back in `SignResponse` values. Typed-data, account-abstraction, and authorization requests require a non-empty `request_id`, and their responses echo it.
- Key responses never include `private_key_hex`.
- Hierarchical slash-delimited `key_id` values are supported end-to-end across create/import, read, list, status mutation, and signing.
- A valid `key_id` is one or more non-empty slash-delimited segments.
- Invalid `key_id` values are rejected if they are empty, start with `/`, end with `/`, contain an empty segment, or contain `.` or `..` as a segment.
- Slash `/` is a structural delimiter inside `key_id`.
- Validation runs on decoded `key_id` values.
- Clients must escape each `key_id` segment separately when constructing paths.
- Percent-encoding must not be used to create an alternate interpretation of `/`.
