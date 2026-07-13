# EIP-7702 authorization

[EVM index](evm.md) · [API index](../API.md)

Route: `POST v1/evm/eip7702/authorizations/sign`

Request type: `EVMEIP7702AuthorizationSignRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `key_id`, `chain_family`, `network`, `request_id` | string | yes | Custody key, protocol context, and correlation identifier. |
| `authority_address` | address | yes | EOA authority; must match the selected key. |
| `chain_id` | decimal string | yes | uint256. `"0"` is the EIP-7702 wildcard and requires `allow_eip7702_chain_id_zero`. |
| `address` | address | yes | Delegation target. Must be in `allowed_eip7702_delegates`. The zero address is revocation and instead requires `allow_eip7702_revocation`. |
| `nonce` | decimal string | yes | Authorization nonce in the range `0` through `2^64-2`. |
| `authorization_schema` | string | yes | Must be `eip7702-v1`. |

Example request:

```json
{
  "key_id": "payments-evm",
  "chain_family": "evm",
  "network": "ethereum-sepolia",
  "request_id": "authorization-001",
  "authority_address": "0x1111111111111111111111111111111111111111",
  "chain_id": "11155111",
  "address": "0x5555555555555555555555555555555555555555",
  "nonce": "8",
  "authorization_schema": "eip7702-v1"
}
```

Response type: `EVMEIP7702AuthorizationSignResponse`

```json
{
  "data": {
    "api_version": "v1",
    "key_id": "payments-evm",
    "chain_family": "evm",
    "network": "ethereum-sepolia",
    "operation": "evm_eip7702_authorization",
    "signer_address": "0x1111111111111111111111111111111111111111",
    "request_id": "authorization-001",
    "authorization_schema": "eip7702-v1",
    "authority_address": "0x1111111111111111111111111111111111111111",
    "chain_id": "11155111",
    "address": "0x5555555555555555555555555555555555555555",
    "nonce": "8",
    "authorization_hash": "0x...",
    "y_parity": 0,
    "r": "0x...",
    "s": "0x...",
    "serialized_authorization": "0x..."
  }
}
```

The authorization hash is `keccak256(0x05 || rlp([chain_id, address, nonce]))`. These are the canonical `go-ethereum/core/types.SetCodeAuthorization` fields. `serialized_authorization` is the standalone RLP encoding of the signed six-field tuple; the `0x05` signing-domain byte is not included in that standalone serialization.


## `POST v1/evm/eip7702/authorizations/verify`

Request type: `EVMEIP7702AuthorizationVerifyRequest`:

```json
{
  "chain_family": "evm",
  "network": "ethereum-sepolia",
  "request_id": "authorization-verify-001",
  "expected_authority_address": "0x1111111111111111111111111111111111111111",
  "chain_id": "11155111",
  "address": "0x5555555555555555555555555555555555555555",
  "nonce": "8",
  "authorization_schema": "eip7702-v1",
  "y_parity": 0,
  "r": "0x...",
  "s": "0x..."
}
```

Response type: `EVMEIP7702AuthorizationVerifyResponse`. It returns `authorization_hash`, `recovered_authority`, and `authorization_valid`.

```json
{
  "data": {
    "api_version": "v1",
    "chain_family": "evm",
    "network": "ethereum-sepolia",
    "operation": "evm_eip7702_authorization",
    "authorization_hash": "0x...",
    "recovered_authority": "0x1111111111111111111111111111111111111111",
    "authorization_valid": true,
    "request_id": "authorization-verify-001"
  }
}
```
