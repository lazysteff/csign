# chain-signer HTTP API

This document describes the Vault-exposed HTTP API for `chain-signer`, the supported request and response shapes, the policy definition, and a complete happy-path flow.

The reference is organized by responsibility so each page stays focused and readable:

- [Conventions and capability discovery](api/conventions.md) — mount behavior, supported routes, wire conventions, and `GET v1/version` capabilities.
- [Getting started](api/getting-started.md) — complete EIP-1559 create, sign, and verify flow.
- [Keys and shared signing fields](api/keys.md) — key lifecycle, policy replacement, direct signing fields, and common responses.
- [Signing-operation policy](api/signing-operations.md) — authoritative operation registry, default-deny semantics, Paymaster control-key profile, and rollout requirements.
- [EVM](api/evm.md) — capability index for direct EOA transactions, EIP-712 Permit, ERC-4337, and EIP-7702.
- [TRON](api/tron.md) — supported signing routes and links to the detailed protobuf contract reference.
- [Verification and recovery](api/verification.md) — generic transaction-payload inspection; structured protocol inspection is documented with each [EVM capability](api/evm.md).
- [Policy, ACLs, and custody boundaries](api/policy.md) — policy fields, enforcement, Vault ACL examples, and live-chain responsibilities.
- [Errors and Go client](api/errors-client.md) — HTTP/error-code behavior and typed client methods.

## Endpoint index

| Area | Routes | Reference |
| --- | --- | --- |
| Discovery | `GET v1/version` | [Conventions and discovery](api/conventions.md) |
| Keys | `POST v1/keys`, `LIST v1/keys`, `GET v1/keys/:key_id`, `POST v1/key-status/:key_id`, `POST v1/key-policy/:key_id` | [Keys](api/keys.md) |
| Signing policy | Every key-backed `.../sign` route | [Signing-operation policy](api/signing-operations.md) |
| EVM signing | `POST v1/evm/.../sign` | [EVM](api/evm.md) |
| TRON signing | `POST v1/tron/.../sign` | [TRON](api/tron.md) |
| Payload inspection | `POST v1/verify`, `POST v1/recover` | [Verification and recovery](api/verification.md) |
| Structured EVM inspection | EIP-712, ERC-4337, and EIP-7702 verify/recover routes | [EVM](api/evm.md) |

All route paths are mount-relative. Examples assume the plugin is mounted at `chain-signer`; see [API conventions](api/conventions.md#overview) for the complete Vault base path and envelope behavior.
