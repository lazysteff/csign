# Changelog

## v0.4.0 - 2026-04-15

Add end-to-end hierarchical `key_id` support across key management.

Highlights:

- hierarchical slash-delimited `key_id` values now round-trip unchanged across create, read, list, status mutation, and signing
- canonical status mutation route is now `/v1/key-status/{key_id}`
- legacy `/v1/keys/{key_id}/status` route has been removed
- key listing now recursively traverses stored key subtrees and returns full logical IDs
- shared server/client `key_id` contract now enforces decoded-value validation and segment-wise path escaping
- documentation and route discovery updated to advertise only canonical key-management routes

Notes:

- storage layout remains `keys/<key_id>` with no migration
- signing and activation semantics remain unchanged
- clients must escape `key_id` path segments individually and must not rely on percent-encoding to change `/` semantics

## v0.3.0 - 2026-04-13

Add TRON Stake 2.0 treasury and resource signing support.

Highlights:

- TRON freeze balance v2 signing
- TRON unfreeze balance v2 signing
- TRON delegate resource signing
- TRON undelegate resource signing
- TRON withdraw expired unfreeze signing
- `/v1/version` now returns `supported_routes` for runtime capability discovery
- Go client support for the new TRON resource routes and typed request builders
- documentation updates for TRON resource routes, API-to-protobuf field mapping, and signer/node validation boundaries

Notes:

- existing EVM and TRON transfer routes remain unchanged
- `TRON_POWER` unfreeze is intentionally out of scope for this release
- signer-side expiration freshness windows remain the caller/node responsibility
- opt-in live TRON integration coverage is available behind the `integration` build tag
- public Go packages remain limited to `pkg/api/v1` and `pkg/client`

## v0.2.0 - 2026-04-10

First public release of `chain-signer`.

Highlights:

- typed Vault signing plugin for EVM and TRON transaction flows
- policy-enforced key creation and signing boundaries
- support for plugin-managed (`mvp`) and external (`pkcs11`) custody modes
- capability-oriented Go client in `pkg/client`
- documented HTTP API with end-to-end happy path examples
- conformance, service, client, contract, and chain-level test coverage

Included operations:

- EVM legacy native transfer signing
- EVM EIP-1559 native transfer signing
- EVM EIP-1559 contract call signing
- TRON TRX transfer signing
- TRON TRC-20 transfer signing
- signed payload verify and recover endpoints

Notes:

- public Go packages are intentionally limited to `pkg/api/v1` and `pkg/client`
- Vault wire paths and JSON field shapes are pinned by tests in this release
