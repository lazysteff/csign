# Signing architecture and security model

csign authorizes protocol-level signing operations and executes them through reusable cryptographic capabilities. Operations define permitted signing semantics and compatible schemes; managed keys identify material and custody relationships; the compatibility registry resolves their intersection with actual custody support; custody executes the resolved capability. Chain family does not select cryptography.

## Independent concepts

Key types describe cryptographic material (`secp256k1`, `ed25519`). Signing schemes describe its use (`ecdsa_secp256k1`, `ed25519`). Equal identifiers for an Ed25519 key type and scheme do not merge those concepts. The registry owns key-type/scheme compatibility. Digest/message input kinds are internal capabilities, never caller-selected API fields.

Each operation declares a set of compatible scheme/input bindings. The runtime intersects that set with registered key-type compatibility and the selected custody implementation's read-only capability description. Exactly one executable binding must remain. Zero matches or ambiguity deny signing; registration order supplies no preference. Managed records do not store derived supported schemes or input capabilities.

The service resolves an operation and one key, applies authorization/policy, normalizes and validates operation input, resolves the scheme, prepares and freezes its payload, resolves matching custody material, signs once, verifies the result, and formats the protocol artifact. Input normalization is separate from cryptographic payload preparation. A payload owns its bytes and gives custody a copy.

Canonical public-key material is independent of protocol identity: compressed SEC1 for secp256k1 and raw 32-byte Ed25519 public keys. Addresses are derived by protocol-facing adapters. A protocol binding restricts operations; it never selects a key type, signing scheme, input kind, or custody provider. Existing EVM/TRON bindings and API address/public-key representations remain supported.

## Typed semantic and opaque operations

EVM/TRON operations retain typed semantic validation and existing value, gas, fee, selector, protocol and other applicable policies. They prepare their existing signing digests, use registered secp256k1 ECDSA, and retain low-S normalization, recovery and verification.

`solana_message` is an explicitly authorized **opaque** operation. It signs the exact bytes supplied by the caller without interpreting instructions. Its guarantees are activation, exact per-key operation authorization, applicable network policy metadata, protocol restrictions, identity assertions, compatible cryptography/custody, and verified detached signature output. It does not enforce amount, token, instruction, account or fee restrictions. Those properties must be enforced by the Gateway.

csign does not expose unrestricted arbitrary signing. An Ed25519 key grants no operation permission, and authorization for another Ed25519 operation does not grant `solana_message`. Discovery describes compiled operations, security models, compatible key types, schemes and encodings; it is never an authorization decision.

## Managed records and compatibility

New records use `schema_version: 2`, explicit `key_type`, canonical `public_key_hex`, custody mode/reference or protected private material, and explicit `material_format` (`secp256k1_scalar` or `ed25519_seed`). Existing ID, status, labels, policy, protocol binding and timestamps are retained. Private material stays in Vault-backed storage and is excluded from response DTOs and payload-free denial audit events.

Historical EVM/TRON creation requests without `key_type` use an isolated compatibility adapter supplying the historical secp256k1 type. Generalized creation requires explicit type. For explicitly typed keys, `public_key_hex` is accepted only for external custody; managed generation/import derives the public key from its material. Ed25519 creation/import is protocol-neutral and uses existing managed custody (`mvp`); imports accept 32-byte seeds or 64-byte seed/public-key representations, verify the suffix, and store the seed.

Legacy reads strictly validate material/public-key consistency, custody metadata, protocol identity/binding, key ID and operation authorization metadata. Unknown or inconsistent records fail closed. External records validate stored public metadata and reference; runtime material must match the stored canonical key. Reads do not rewrite storage. A subsequent mutation writes the generalized representation only after complete mapping and preserves every unrelated semantic value.

Back up Vault storage before upgrading. The old binary cannot be assumed to understand schema version 2. For rollback, disable signing and restore a compatible snapshot before running the old binary. Do not roll back a live signing mount over new-format records.

### EVM/TRON upgrade compatibility

Existing `/v1` request shapes, operation identifiers, key IDs, policies and successful signing/recovery behavior remain supported. Historical create/import requests do not need `key_type`, and valid existing keys do not need recreation. EVM/TRON public API responses and the legacy external resolver callback retain uncompressed secp256k1 public keys; only internal canonical records use compressed SEC1.

Key responses add `key_type`, and discovery adds `signing_operation_details` plus Solana capabilities. Clients that reject unknown response fields or assume a fixed discovery catalog must update those assumptions. Stored records are validated more strictly: malformed JSON, unsupported fields, inconsistent material/public identity or custody metadata fail closed. Reads do not migrate storage, but new records and later mutations use schema version 2. Rollback follows the snapshot procedure above. Custody failure details are sanitized; applications should rely on HTTP statuses and established error codes rather than exact provider error text. Existing direct-operation verification errors retain their unclassified contract, while structured EVM verification failures retain `signature_verification_failed`.

## Extension boundary

Only secp256k1 ECDSA and Ed25519 are implemented. Synthetic tests cover same-key-type/multiple-scheme resolution, multi-scheme operations, ambiguity and new cryptographic types. They are absent from production discovery. EVM-compatible networks reuse existing operations through network/policy configuration. No blockchain SDK, RPC client, account lookup, submission, fee estimation or signer coordinator is part of this core.
