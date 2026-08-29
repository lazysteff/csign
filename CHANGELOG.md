# Changelog

## v1.2.1 - 2026-08-29

- raised the build and module baseline from Go 1.26.2 to Go 1.27.0
- updated the release workflow to `actions/checkout` v7.0.1 and `actions/setup-go` v7.0.0
- updated the release verification linter to golangci-lint v2.13.2

## v1.2.0 - 2026-08-28

Add byte-preserving memo signing for TRON transfers.

- added optional hex-encoded `memo_hex` fields to TRX and TRC-20 transfer signing requests
- populated `TransactionRaw.data` before hashing and signing, with byte-exact protobuf preservation
- rejected malformed hex and transactions that exceed java-tron's 500×1024-byte serialized transaction limit
- added typed `supported_tron_memo_capabilities` discovery metadata with encoding, operation, and size-limit details
- added TRX, TRC-20, empty-memo compatibility, binary/Unicode memo, size, conformance, and opt-in Nile broadcast coverage

Empty or omitted memos retain the prior serialized transaction and transaction hash. Memo contents are public on-chain and are not logged by `csign`.

## v1.1.1 - 2026-07-19

Refresh compatible transitive Go module dependencies.

- updated `github.com/mattn/go-isatty` to `v0.0.23`
- updated `github.com/petermattis/goid` to `v0.0.0-20260716134002-a9b348f0a2b9`
- updated `google.golang.org/api` to `v0.289.0`
- updated `google.golang.org/genproto/googleapis/api` and `google.golang.org/genproto/googleapis/rpc` to `v0.0.0-20260715232425-e75dac1f907d`
- updated `google.golang.org/grpc` to `v1.82.1`

There are no API or signing-policy changes in this release.

## v1.1.0 - 2026-07-16

Harden and simplify the mandatory signing-operation policy architecture.

- consolidated route and operation identities behind the single immutable signing-operation catalog
- validated descriptor request factories and their typed key-reference contract during startup
- made missing, mismatched, or malformed runtime descriptors fail closed before request decoding, repository lookup, or custody access
- required exact set equality between the catalog, descriptors, and registered Vault signing handlers during startup
- split request construction, operation enforcement, and route-registration validation into focused modules
- replaced the duplicated structured-policy model with a source-compatible alias of the canonical policy definition while retaining transport rejection of deprecated opaque context
- tightened denial auditing so only canonical registered route identities are emitted and documented the distinct missing-key category
- expanded startup-integrity and failure-path tests, including nil, malformed, and panicking request factories

There are no new signing routes in this release. The forward-only `v1.0.0` operation-policy rollout and rollback requirements remain mandatory.

## v1.0.0 - 2026-07-16

Make signing-operation policy mandatory across every key-backed signing route.

- added one authoritative route-to-operation catalog shared by registration, policy persistence, runtime enforcement, capability discovery, and tests
- changed `allowed_signing_operations` to default-deny for direct EOA transactions, EIP-712, ERC-4337, EIP-7702, and every TRON signing operation
- rejected unknown, non-canonical, and duplicate operation identifiers on policy writes; corrupted stored operation policies fail closed
- added `supported_signing_operations` to `v1/version`
- hardened ordinary EVM transaction values to unsigned uint256 parsing before custody access
- added payload-free denial audit events and category metrics without making audit availability a signing dependency
- added canonical semantic policy comparison for secure complete-policy rollout verification
- documented the complete operation registry, Paymaster pause/unpause control profile, custody boundary, rollout, and emergency rollback procedure

This is a forward-only breaking policy change. Every deployed signing key must receive a complete explicit operation allowlist before or together with this release. Rolling back to an older plugin while signing remains enabled can restore permissive ordinary-route behavior; disable affected keys or revoke signing ACLs before any emergency rollback.

## v0.7.0 - 2026-07-14

Add registered verifying-Paymaster approvals and refresh dependencies.

Highlights:

- added the fixed `verifying-paymaster-approval-v1` EIP-712 schema for signing and verifying bounded ERC-4337 sponsorship approvals
- generalized the registered EIP-712 envelope so each immutable schema owns and strictly decodes its message shape
- added policy controls for EIP-712 verifying contracts and reused the existing EntryPoint allowlist for Paymaster approvals
- preserved source compatibility for the original permit payload name while keeping ERC-2612-specific signer, token, spender, and value enforcement
- returned request IDs consistently in signing responses and tightened EVM/TRON request validation and conformance coverage
- refreshed compatible transitive Go module dependencies and verified all direct modules remain current

Notes:

- verifying-Paymaster approval signing is default-deny and requires explicit schema, verifying-contract, and EntryPoint allowlists
- the schema binds the chain ID, EntryPoint, Paymaster, UserOperation hash, validity window, maximum sponsored cost, approval nonce, and context hash
- existing ERC-2612, ERC-4337, EIP-7702, EVM transaction, and TRON signing contracts remain supported

## v0.6.0 - 2026-07-13

Add constrained account-abstraction and EIP-7702 signing for EVM keys.

Highlights:

- added fixed-schema EIP-712 signing and verification for ERC-2612 `Permit` as `eip2612-permit-v1` version `1`
- added ERC-4337 `erc4337-v0.9` UserOperation signing and verification for SimpleAccount `0.9` with `simple-account-eip712-v1` signatures
- added EIP-7702 `eip7702-v1` authorization signing/verification and `eip7702-type-4` transaction signing/recovery
- aligned authorization signing and type-4 authorization-list requests with the canonical `SetCodeAuthorization` fields (`chain_id`, `address`, `nonce`, `y_parity`, `r`, `s`); authorities are recovered from signatures, while explicit authority comparison remains on the verification route
- reused go-ethereum's canonical EIP-712, EIP-7702 authorization, access-list, transaction, and recovery definitions; consolidated EVM signature formatting and strict scalar parsing instead of maintaining parallel protocol implementations
- reorganized the advanced-EVM API, codecs, policy, Vault transport, client, conformance tests, and API manual into responsibility-focused modules with concise, non-repeating paths
- added dedicated Vault routes and typed Go client methods for all four capabilities
- extended `/v1/version` with typed schema, protocol, account, and transaction capability records
- added `POST v1/key-policy/{key_id}` and `Client.Keys.SetPolicy` with a source-compatible `StructuredPolicy` alias of the canonical `Policy` model to replace a key's enforced policy fields without duplicating definitions
- added default-deny policy controls for all advanced EVM signing operations, delegates, EntryPoints, account implementations, signing schemas, destinations, and authorization-list size
- added strict request decoding plus canonical decimal-string, lowercase address, and lowercase `0x`-hex validation for the new routes
- kept advanced requests protocol-only: opaque metadata, labels, approval references, and arbitrary workflow fields are rejected
- deprecated legacy `additional_policy_context`; structured policy updates reject it and preserve any value already stored on older keys without allowing mutation
- added stable advanced-operation error-code prefixes plus `client.APIError` and `client.ErrorCode` extraction while preserving legacy transport errors
- added end-to-end advanced-operation conformance through both plugin-managed and external signer custody paths
- verified every direct Go module against the latest stable compatible release and added a non-mutating dependency-freshness gate to `make verify`
- pinned the release workflow to the latest stable `actions/checkout` and `actions/setup-go` releases available at build time
- made published checksum files portable by recording the artifact basename instead of a CI workspace path
- upgraded `go-ethereum` to `v1.17.4` for the pinned implementation

Notes:

- existing EVM, TRON, `/v1/verify`, and `/v1/recover` request and response contracts remain unchanged
- advanced operations require explicit opt-in; an empty advanced allowlist never grants a new signing capability
- structured policy replacement is not a merge, so callers must resubmit every legacy and advanced enforced field they intend to retain; deprecated stored `additional_policy_context` is preserved separately
- only ERC-2612 `Permit`, ERC-4337 v0.9 SimpleAccount, EIP-7702 authorization schema `eip7702-v1`, and EIP-7702 transaction type 4 are registered
- CSign does not expose raw signing, query chain state, allocate nonces, simulate UserOperations, fund Paymasters, or broadcast transactions
- plugin-managed `mvp` custody works directly; external `pkcs11` signing still requires a deployment-provided resolver and is not a turnkey runtime integration
- `github.com/armon/go-metrics` remains pinned to `v0.4.1`; later tags through `v0.6.0` declare the renamed `github.com/hashicorp/go-metrics` module path and are explicitly excluded as incompatible

## v0.5.1 - 2026-06-09

Highlights:

- gated release artifact creation on `make verify`
- added a tag-driven GitHub Actions release workflow that runs tests and golangci-lint before publishing release assets
- added a guarded `make publish-release` path for future releases
- refreshed transitive Go module dependencies with `go get -u -t ./...`

## v0.5.0 - 2026-06-07

Add TRON governance vote signing and SR/voter reward-claim signing.

Highlights:

- added `v1/tron/governance/vote_witness/sign` for `VoteWitnessContract`
- added `v1/tron/rewards/withdraw_balance/sign` for `WithdrawBalanceContract`
- added typed Go API request structs, client helpers, route discovery, and recovery classification for the new TRON operations
- documented vote replacement semantics, reward allowance behavior, signer/node validation boundaries, and forward-only rollout scope
- refreshed Go dependencies with `go get -u -t ./...`
- added golangci-lint configuration plus `make lint` and `make verify`

Notes:

- this is a forward-only feature release with no migration, alias route, or compatibility layer for previously signed requests
- `withdraw_balance` is documented as SR/voter reward claiming and is distinct from Stake 2.0 expired-unfreeze withdrawal
- csign validates deterministic request structure only; witness selection, allocation policy, reward scheduling, and live-chain checks remain orchestration/node responsibilities

## v0.4.2 - 2026-05-01

Maintenance release for dependency refresh and repeatable module updates.

Highlights:

- refreshed retained transitive Go module dependencies with `go get -u -t all`
- added module excludes for incompatible `github.com/armon/go-metrics` tags so `go get -u ./...` completes cleanly
- rebuilt release artifacts for `v0.4.2`

Notes:

- no API, route, storage, or signing behavior changes
- `github.com/armon/go-metrics` remains pinned at `v0.4.1` because newer tags declare the renamed `github.com/hashicorp/go-metrics` module path

## v0.4.1 - 2026-05-01

Maintenance release for the Go toolchain and dependency graph.

Highlights:

- refreshed Go module dependencies, including `github.com/hashicorp/vault/api` to `v1.23.0`
- kept the module on Go `1.26.2`, matching the current release build toolchain
- rebuilt release artifacts for `v0.4.1`

Notes:

- no API, route, storage, or signing behavior changes
- `github.com/armon/go-metrics` remains pinned at `v0.4.1` because newer tags declare the renamed `github.com/hashicorp/go-metrics` module path

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
