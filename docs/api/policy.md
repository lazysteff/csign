# Policy, ACLs, and custody boundaries

[API index](../API.md)

## Policy definition

The `policy` object is attached to a key and enforced at sign time.

| Field | Type | Applies to | Meaning |
| --- | --- | --- | --- |
| `allowed_networks` | array of string | all | Allowed `network` values. |
| `allowed_chain_ids` | array of int64 | EVM | Allowed `chain_id` values. |
| `max_value` | string | all | Maximum native or token amount. |
| `max_gas_limit` | uint64 | EVM | Maximum gas limit. |
| `max_gas_price` | string | EVM legacy | Maximum legacy gas price. |
| `max_fee_per_gas` | string | EVM EIP-1559, ERC-4337, EIP-7702 type-4 | Maximum fee cap. |
| `max_priority_fee_per_gas` | string | EVM EIP-1559, ERC-4337, EIP-7702 type-4 | Maximum priority fee cap. |
| `max_fee_limit` | int64 | TRON transfers | Maximum TRON fee limit on the existing TRX and TRC-20 routes. |
| `allowed_token_contracts` | array of string | EVM contract calls, EIP-712, TRC-20 | Allowlisted contract addresses, including the EIP-712 verifying token contract. |
| `allowed_selectors` | array of string | EVM contract calls, ERC-4337, EIP-7702 type-4, TRC-20 | Allowlisted first four decoded bytes. For ERC-4337 this applies to the outer account `call_data`, not nested target calldata. |
| `additional_policy_context` | object | deprecated stored records only | Returned for older key records but not enforced. `StructuredPolicy` excludes it, and the policy-update route preserves an existing value without allowing callers to create or modify it. |
| `allowed_signing_operations` | array of string | every signing route | Exact canonical operation allowlist. Missing, nil, or empty is valid deny-all. See the [complete registry](signing-operations.md#canonical-registry). |
| `allowed_eip712_schemas` | array of string | EIP-712 | Required schema allowlist. Current IDs include `eip2612-permit-v1` and `verifying-paymaster-approval-v1`; discover the compiled set through `v1/version`. |
| `allowed_eip712_verifying_contracts` | array of address | registered EIP-712 schemas that use a dedicated verifying-contract policy | Required verifying-contract allowlist for schemas such as Paymaster approvals. |
| `allowed_erc4337_versions` | array of string | ERC-4337 | Required protocol allowlist. Currently `erc4337-v0.9`. |
| `allowed_entry_points` | array of address | ERC-4337 | Required caller-selected EntryPoint allowlist. |
| `allowed_account_implementations` | array of string | ERC-4337 | Required account implementation allowlist. Currently `simple-account`. |
| `allowed_account_signing_schemas` | array of string | ERC-4337 | Required account-signing-schema allowlist. Currently `simple-account-eip712-v1`. |
| `allowed_eip7702_delegates` | array of address | ERC-4337 EIP-7702 context, EIP-7702 | Required non-zero delegate allowlist. |
| `allow_eip7702_revocation` | bool | EIP-7702 | Allows zero-address delegate revocation. Defaults to false. |
| `allow_eip7702_chain_id_zero` | bool | EIP-7702 | Allows wildcard authorization chain ID `"0"`. Defaults to false. |
| `allowed_transaction_types` | array of string | EIP-7702 transaction | Required allowlist. Currently `eip7702-type-4`. |
| `allowed_contract_destinations` | array of address | ordinary EVM contract calls, EIP-712, EIP-7702 transaction | Contract-call/type-4 destination and Permit spender allowlist. |
| `max_authorization_list_entries` | uint64 | EIP-7702 transaction | Required non-zero maximum authorization-list length. Zero denies type-4 signing. |

Current enforcement rules:

- Sign requests fail if the key is disabled.
- `source_address` must match the stored key address.
- TRON owner-based resource, governance, and reward requests use `owner_address`, which must match the stored key address.
- Every key-backed signing request requires its exact registered operation in `allowed_signing_operations`; missing and empty lists deny all signing.
- Operation strings use exact canonical comparison. Policy writes reject unknown, case/whitespace variants, and duplicates. A corrupted stored list denies all signing even if it also contains the matching operation.
- EVM contract calls require a destination and at least four decoded calldata bytes. A missing destination cannot create a contract through this route.
- TRC-20 signing is limited to the `transfer(address,uint256)` selector.
- TRON owner-based routes validate only deterministic structural fields, owner authorization, and signability, not live chain state.
- `VoteWitnessContract` signing enforces the protocol maximum of 30 submitted vote entries and rejects duplicate normalized witness addresses as a deterministic API constraint. It does not enforce witness allowlists or business vote caps.
- Typed-data, account-abstraction, and authorization operations additionally default-deny when `allowed_networks`, `allowed_chain_ids`, or a required operation-specific allowlist is empty. The only chain-ID exception is an EIP-7702 authorization using `"0"` when `allow_eip7702_chain_id_zero` is explicitly true.
- EIP-712 Permit additionally requires the schema, verifying token contract, spender, and value to satisfy policy.
- ERC-4337 additionally requires the protocol, EntryPoint, account implementation, and signing schema to satisfy policy. An EIP-7702 initialization delegate is checked when present. Fee/gas caps cover account, pre-verification, and Paymaster gas fields. When selectors are configured, calldata shorter than four bytes is denied rather than treated as an allowlist bypass.
- EIP-7702 authorization additionally enforces delegate, revocation, and wildcard-chain policy.
- EIP-7702 type-4 signing requires `eip7702-type-4`, an allowed destination, a non-zero authorization-list maximum, allowed delegates, and all configured value/gas/fee/selector caps.
- Policy denials currently return HTTP `400` through Vault, not `403`.

Operation enforcement runs after syntactic key-ID validation and key metadata lookup, but before route-specific validation and any custody-material resolution. See [Signing-operation policy](signing-operations.md) for corruption handling, audit categories, the Paymaster control-key profile, and the forward-only rollout/rollback procedure.

### Complete structured-EVM policy example

```json
{
  "allowed_networks": ["ethereum-sepolia"],
  "allowed_chain_ids": [11155111],
  "allowed_signing_operations": [
    "evm_eip712_typed",
    "evm_erc4337_user_operation",
    "evm_eip7702_authorization",
    "evm_eip7702_transaction"
  ],
  "allowed_eip712_schemas": ["eip2612-permit-v1"],
  "allowed_erc4337_versions": ["erc4337-v0.9"],
  "allowed_entry_points": ["0x433709009b8330fda32311df1c2afa402ed8d009"],
  "allowed_account_implementations": ["simple-account"],
  "allowed_account_signing_schemas": ["simple-account-eip712-v1"],
  "allowed_eip7702_delegates": ["0x5555555555555555555555555555555555555555"],
  "allow_eip7702_revocation": false,
  "allow_eip7702_chain_id_zero": false,
  "allowed_transaction_types": ["eip7702-type-4"],
  "allowed_token_contracts": ["0x2222222222222222222222222222222222222222"],
  "allowed_contract_destinations": [
    "0x3333333333333333333333333333333333333333",
    "0x6666666666666666666666666666666666666666"
  ],
  "allowed_selectors": ["a9059cbb"],
  "max_authorization_list_entries": 4,
  "max_value": "1000000000000000000",
  "max_gas_limit": 500000,
  "max_fee_per_gas": "2000000000",
  "max_priority_fee_per_gas": "1000000000"
}
```

For an existing key, wrap this object in `{"policy": ...}` and submit it to `POST v1/key-policy/:key_id`. Structured policy fields are replaced in full; the operation is not a merge. Deprecated `additional_policy_context` is outside this contract and, if already stored, remains unchanged.

The example intentionally configures `allowed_selectors`, so it denies the empty ERC-4337 and type-4 calldata shown in earlier wire-shape examples. Omit that optional cap or supply an allowed outer selector for those operations.

## Vault ACL examples

Vault maps these POST endpoints to its `update` capability. A signing application can be restricted to discovery and only its approved operation:

```hcl
path "chain-signer/v1/version" {
  capabilities = ["read"]
}

path "chain-signer/v1/evm/erc4337/user-operations/sign" {
  capabilities = ["update"]
}

path "chain-signer/v1/evm/erc4337/user-operations/verify" {
  capabilities = ["update"]
}
```

Policy administration should use a different Vault policy:

```hcl
path "chain-signer/v1/keys/payments-evm" {
  capabilities = ["read"]
}

path "chain-signer/v1/key-policy/payments-evm" {
  capabilities = ["update"]
}
```

Repeat the exact sign or inspection path for each capability a caller needs. Do not grant a wildcard over the mount merely to access one typed signer.

## Custody and live-chain boundaries

All sign routes use the same custody abstraction:

- `mvp` keys are generated or imported by the plugin and stored in its Vault-backed logical storage.
- `pkcs11` key records contain a public key and `external_signer_ref`. The deployment must inject a compatible external resolver; this repository does not ship a turnkey PKCS#11 runtime integration.
- The custody material must expose the public key and return a valid secp256k1 signature for the internally reconstructed 32-byte digest.
- CSign validates the custody public key, canonicalizes low-S output, derives recovery parity, and recovers the final signer before returning.

Private keys and external-signer credentials are never returned by these endpoints. There is no public custody-level `sign(hash)` method.

CSign intentionally does not:

- call an EVM RPC endpoint or query account, token, EntryPoint, Paymaster, nonce, balance, code, or delegation state;
- verify deployed SimpleAccount or EntryPoint bytecode;
- allocate or reserve transaction, authorization, or UserOperation nonces;
- simulate UserOperation validation or a type-4 transaction;
- create a Paymaster signature, manage deposits, or fund a Paymaster;
- install/revoke delegation, broadcast a transaction, or track whether an artifact was consumed;
- accept generic raw hashes, arbitrary bytes, caller-defined EIP-712 schemas, serialized unsigned authorizations, or serialized unsigned transactions.

The caller is responsible for obtaining current chain state, choosing every nonce/gas/fee/deadline, ensuring the selected account and EntryPoint are deployed as expected, submitting artifacts, and handling replay/lifecycle policy. `request_id` is a correlation identifier only and does not create idempotency storage.
