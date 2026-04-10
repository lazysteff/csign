# Changelog

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
