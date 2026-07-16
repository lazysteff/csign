# EVM API

[API index](../API.md)

The EVM reference is organized by transaction or protocol capability:

- [Direct EOA transaction signing](legacy-evm.md)
- [Constrained EIP-712 ERC-2612 Permit](eip712.md)
- [ERC-4337 v0.9 SimpleAccount UserOperation](erc4337.md)
- [EIP-7702 authorization](eip7702-authorization.md)
- [EIP-7702 type-4 transaction](eip7702-transaction.md)

## Typed-data, account-abstraction, and authorization signing

These EVM APIs form a closed, versioned set of structured operations. They do not accept a caller-defined EIP-712 type graph, a precomputed digest, an unsigned serialized transaction, or an arbitrary account-contract signing scheme.

Structured requests contain only protocol fields, key selection, network/chain context, and the required `request_id` correlation identifier. Opaque `metadata`, `labels`, `approval_ref`, and other application workflow fields are rejected as unknown; applications should keep those concerns outside the signing protocol.

All four signing responses embed `EVMOperationResponseBase`:

| Field | Type | Meaning |
| --- | --- | --- |
| `api_version` | string | Wire contract version. |
| `key_id` | string | Custody-backed key used for signing. |
| `chain_family` | string | Always `evm`. |
| `network` | string | Caller-supplied network identifier. |
| `operation` | string | Stable policy/audit operation identifier. |
| `signer_address` | string | Signer recovered from the returned artifact. |
| `request_id` | string | Caller correlation identifier echoed from the request. |

These routes require a non-empty `network` and `request_id`. The signing address must match the selected key, every operation must appear in `allowed_signing_operations`, the network must appear in `allowed_networks`, and every positive chain ID must appear in `allowed_chain_ids`. Although protocol fields are parsed as uint256 where applicable, the current `allowed_chain_ids` policy contract is `int64`; requests with chain IDs above positive int64 range are denied. These requirements are default-deny and are separate from Vault ACL authorization.

Dedicated inspection routes are stateless and do not load a key, invoke custody, or apply key policy. They validate and reconstruct the supplied artifact cryptographically. Use Vault ACLs to control which callers may invoke them.
