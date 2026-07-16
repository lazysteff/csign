# Signing-operation policy

[API index](../API.md) · [Policy reference](policy.md)

Every key-backed signing request must match an exact operation explicitly listed in the key's `allowed_signing_operations`. Vault ACLs protect routes, but cannot inspect the request-body `key_id`; this key policy prevents an ACL-authorized caller from using a control key through another signer.

There is no compatibility fallback. A missing, `null`, or empty allowlist is a valid intentional deny-all policy. Unknown, non-canonical, or duplicate entries are invalid. Identifiers are compared exactly, without whitespace trimming, case folding, aliases, or prefix matching.

## Canonical registry

The service has one process-lifetime route/operation catalog. It is used by handler registration, descriptor validation, policy writes, runtime enforcement, `GET v1/version`, and route-coverage tests. It is compiled into the binary and cannot be changed by requests, stored policies, environment or deployment configuration.

| Signing route | Required operation |
| --- | --- |
| `v1/evm/transfers/legacy/sign` | `evm_transfer_legacy` |
| `v1/evm/transfers/eip1559/sign` | `evm_transfer_eip1559` |
| `v1/evm/contracts/eip1559/sign` | `evm_contract_call_eip1559` |
| `v1/evm/eip712/sign` | `evm_eip712_typed` |
| `v1/evm/erc4337/user-operations/sign` | `evm_erc4337_user_operation` |
| `v1/evm/eip7702/authorizations/sign` | `evm_eip7702_authorization` |
| `v1/evm/eip7702/transactions/sign` | `evm_eip7702_transaction` |
| `v1/tron/transfers/trx/sign` | `tron_transfer_trx` |
| `v1/tron/transfers/trc20/sign` | `tron_transfer_trc20` |
| `v1/tron/resources/freeze_v2/sign` | `tron_freeze_balance_v2` |
| `v1/tron/resources/unfreeze_v2/sign` | `tron_unfreeze_balance_v2` |
| `v1/tron/resources/delegate/sign` | `tron_delegate_resource` |
| `v1/tron/resources/undelegate/sign` | `tron_undelegate_resource` |
| `v1/tron/resources/withdraw_expire_unfreeze/sign` | `tron_withdraw_expire_unfreeze` |
| `v1/tron/governance/vote_witness/sign` | `tron_vote_witness` |
| `v1/tron/rewards/withdraw_balance/sign` | `tron_withdraw_balance` |

The plugin fails startup if catalog entries, signing descriptors, or registered signing handlers do not match exactly. Catalog lookup uses the internal route identity captured at handler registration, never a path reconstructed from an HTTP request, proxy rewrite, mount prefix, or router parameter.

`GET v1/version` exposes the same mapping under `supported_signing_operations`. This reports compiled support only; it does not report Vault ACL access, per-key enablement, custody availability, or deployment readiness.

## Enforcement and errors

The signer resolves and revalidates the registered descriptor before parsing the typed request. After syntactic `key_id` validation, it loads key metadata, validates the complete stored allowlist, and requires the descriptor's exact operation before running route policy or accessing custody. Request data cannot select the operation.

A nonexistent key keeps the existing not-found response and does not disclose whether its operation would have been allowed. These operation denials all return `PolicyDenied` with `signing_operation_not_allowed`:

- `missing_allowlist`: the policy is valid and intentionally denies every operation;
- `operation_mismatch`: the list is valid but lacks the selected operation;
- `invalid_policy_record`: a stored list contains an unknown, malformed, or duplicate entry;
- `invalid_route_descriptor`: the registered descriptor and catalog disagree.

A list containing the selected operation plus other known unique operations permits the selected route. A matching entry does not rescue a corrupted list.

Denials emit best-effort structured audit and metric data containing the validated key reference when available, internal route, registered operation, and category. Request bodies, calldata, transaction values, addresses, signatures, key material, approval metadata, and labels are not logged. Audit failure never turns a denial into permission and never becomes a custody dependency.

Every production policy persistence path validates against this same catalog. Policy administration rejects invalid writes instead of storing them; corruption behavior exists for fail-closed handling of old or externally damaged records.

## Custody boundary

The production call graph has one `MaterialForKey` invocation, inside `SigningService.Execute` after operation and route-policy validation. All Vault signing handlers enter that service; no background job, CLI, migration, administrative utility, raw-hash/message endpoint, or other production service calls a chain signer or `SignDigest` directly. Direct chain-signer calls in the test suite are test-only.

Provisioning uses separate key-management APIs and is intentionally outside this gate. Key generation/import creates or parses material but does not sign; public-key reads return stored metadata; verification and recovery operate on caller-supplied signed artifacts. No rotation endpoint currently exists. A future rotation or administrative custody API needs its own authorization design and is not a signing-route exception.

## Paymaster pause/unpause control key

`pause()` and `unpause()` are ordinary direct EOA contract transactions. Use `v1/evm/contracts/eip1559/sign`; the registered EIP-712 Paymaster-approval schema, ERC-4337 UserOperations, and EIP-7702 authorizations/type-4 transactions are not involved.

Replace the control key's complete policy with all of these restrictions:

```json
{
  "allowed_networks": ["<intended-network>"],
  "allowed_chain_ids": [11155111],
  "allowed_signing_operations": ["evm_contract_call_eip1559"],
  "allowed_contract_destinations": ["<canonical-paymaster-proxy-address>"],
  "allowed_selectors": ["8456cb59", "3f4ba83a"],
  "max_value": "0",
  "max_gas_limit": 100000,
  "max_fee_per_gas": "<reviewed-uint256-cap>",
  "max_priority_fee_per_gas": "<reviewed-uint256-cap>"
}
```

`8456cb59` is `pause()` and `3f4ba83a` is `unpause()`. Both network and chain ID are mandatory defense in depth: network binds the intended application environment, while chain ID is signed into the EVM transaction. CSign does not query RPC to prove their mapping.

The contract-call route rejects a missing or empty `to`, preventing contract creation. Destination comparison binds to the normalized canonical Paymaster proxy address. It does not inspect bytecode or bind the proxy implementation; implementation upgrades remain authorized and require separate governance.

The transaction `value` and policy `max_value` are parsed as unsigned uint256 integers. Malformed, negative, overflowing, or non-zero values are rejected before custody; only mathematical zero satisfies `max_value: "0"`.

Generic policies may omit gas and fee caps, which means unrestricted. The Paymaster deployment profile must reject an absent or zero `max_gas_limit` and absent or unrestricted fee-cap strings before rollout.

### Selector decoding

For ordinary EVM contract calls, surrounding calldata whitespace is trimmed. Hexadecimal may be unprefixed or start with `0x`/`0X`, and uppercase or lowercase digits are accepted. Odd-length, non-hexadecimal, empty, or shorter-than-four-byte decoded calldata is invalid when selector policy is evaluated.

Comparison uses the normalized lowercase first four decoded bytes. Approved selectors with trailing bytes are accepted; this policy does not perform full ABI decoding. Therefore the control policy authorizes any calldata beginning with `pause()` or `unpause()`, even though these functions are argumentless. Exact full-calldata enforcement would require a separate policy feature.

## Replacement, rollout, and rollback

Policy updates replace rather than merge. Before enabling v1.0 enforcement, inventory every deployed key and construct a complete policy containing explicit operations plus every intentional network, chain, destination, selector, value, gas, fee, protocol, delegate, and other restriction.

Treat omitted fields according to their policy meaning:

| Field class | Omitted or empty meaning |
| --- | --- |
| `allowed_signing_operations` | deny all signing |
| required structured-operation allowlists | deny that corresponding operation |
| `allowed_networks`, `allowed_chain_ids` | unrestricted; unacceptable for the control key |
| ordinary destinations and selectors | unrestricted or route fallback; unacceptable for the control key |
| string caps including `max_value` and fee caps | unrestricted |
| numeric `max_gas_limit` | unrestricted when zero |
| boolean grants | disabled when false |

Verify readback semantically: set-like lists are duplicate-free and order-independent; operation and network strings remain exact; addresses compare as normalized 20-byte values; selectors compare as normalized four-byte values; numeric strings compare by integer value. Never treat an omitted security field as equivalent to an explicit restriction.

The v0.7 storage format accepts and preserves every operation identifier in the registry, but verify the actually deployed binary with a canary write/readback before bulk staging. If it does not preserve them, use a storage-compatible intermediate release or a maintenance window. Stage and verify all complete policies before or together with v1.0; there is no permissive fallback.

Do not roll back to an older binary during signing traffic. Older ordinary-route validators ignore `allowed_signing_operations`, which can restore broader signing even while policies remain staged. For emergency rollback, first disable affected keys or revoke Vault ACLs to every signing route, keep signing unavailable through the rollback, and restore mandatory enforcement before re-enabling keys or ACLs. Network, chain, destination, selector, and value restrictions retained by an older binary are not a substitute for operation enforcement.

Terminology in this documentation distinguishes direct EOA transaction signing, typed-data signing, account-abstraction and authorization signing, and TRON transaction/contract-operation signing. “Legacy” is reserved for the EVM legacy transaction type.
