# Solana opaque message signing

[API index](../API.md) · [Signing architecture and security model](../SIGNING_ARCHITECTURE.md)

`POST /v1/solana/messages/sign` returns one detached Ed25519 signature. The key's exact `allowed_signing_operations` must include `solana_message`. Every call resolves one managed key and independently authorizes that operation.

## Create a managed key

```json
{
  "key_id": "gateway/solana/source",
  "key_type": "ed25519",
  "chain_family": "solana",
  "policy": {
    "allowed_signing_operations": ["solana_message"],
    "allowed_networks": ["devnet"]
  }
}
```

`key_type` is required for generalized creation. `chain_family` is an optional restrictive protocol binding when creating an explicitly typed key; omitting it creates a protocol-unbound key. Cryptography does not follow from that binding. The default managed custody remains `mvp`, protected by Vault. Creation and reads return public metadata only.

## Request

```json
{
  "key_id": "gateway/solana/source",
  "chain_family": "solana",
  "network": "devnet",
  "request_id": "gateway-request-1",
  "message_hex": "0x010203"
}
```

The example bytes illustrate encoding, not a valid transaction. csign does not parse them as a transaction. Unknown fields, including caller scheme/input selection and multi-key signer lists, are rejected.

| Field | Meaning |
| --- | --- |
| `key_id` | One managed key; authoritative for public key and signer identity |
| `chain_family` | Required exact assertion `solana`; the registered route/operation selects behavior |
| `network` | Required caller-supplied policy metadata; it is not inferred or authenticated from the message |
| `request_id` | Required correlation metadata; it is not an idempotency or replay-protection token |
| `message_hex` | Exact serialized message bytes, optional `0x`/`0X` prefix; no application prehash or domain prefix |
| `expected_signer_address` | Optional fail-closed assertion against the derived signer identity; never selects a key or scheme |
| `labels`, `approval_ref` | Existing optional caller metadata; neither grants authorization |

Messages must contain 1–65,536 decoded bytes. Encoded input is bounded to 131,074 bytes before hex decoding (valid hex characters are ASCII). These are API resource-protection limits, not Solana transaction limits. Invalid hex, empty input and oversized messages are rejected. No instruction, account, version, recent-blockhash, or chain-specific size validation occurs.

## Response

The response includes `api_version`, `key_id`, `chain_family`, `network`, `request_id`, `operation: "solana_message"`, canonical `public_key_hex`, base58 `signer_address`, `signing_scheme: "ed25519"`, `signature_encoding: "hex"` and the detached 64-byte `signature_hex`. Scheme and encoding are separate concepts. No transaction envelope, transaction ID, signature-slot index or completeness claim is returned.

The service signs an immutable copy and verifies the signature against the resolved canonical public key before returning it. There is no Ed25519 signer recovery; the public key identifies the signer.

## Gateway responsibilities

The Gateway constructs and validates transactions, extracts/freezes their exact message bytes, determines required signers, and obtains blockhashes, account data and fee information. It calls csign independently for each managed signer over identical bytes, verifies and combines those results with existing valid external signatures, places signatures in the required slots, and handles RPC, submission and reconciliation. Choosing a sponsor/fee payer or changing any message field requires doing so before freezing/signing; changing bytes invalidates previously collected signatures.

csign never receives or rewrites the transaction envelope. Token semantics, transaction lifetime, signature coordination and blockchain execution remain Gateway responsibilities. Network metadata and request IDs do not modify the signed bytes.

## Go client and discovery

Use `client.Signing.SignSolanaMessage(ctx, v1.SolanaMessageSignRequest{...})`. `Client.Version` includes the route/operation in its existing catalog and describes it as `opaque` in `signing_operation_details`, with scheme/key type `ed25519` and encoding `hex`. Discovery does not imply that any key or caller is authorized.

## Sources

The cryptographic signing boundary follows [Solana partial signing](https://solana.com/docs/core/transactions/partial-signing) and [transaction structure](https://solana.com/docs/core/transactions/transaction-structure). The generic implementation uses [Go's ordinary Ed25519 primitives](https://pkg.go.dev/crypto/ed25519).
