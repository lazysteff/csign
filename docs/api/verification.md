# Verification and recovery

[API index](../API.md)

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

The direct EOA and TRON routes remain transaction-payload endpoints. EIP-712, ERC-4337, and EIP-7702 use the dedicated structured inspection routes documented in the [EVM API](evm.md).
