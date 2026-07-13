# Errors and Go client

[API index](../API.md)

## Error behavior

The adapter maps internal failures to Vault HTTP responses like this:

| Status | When it happens |
| --- | --- |
| `400` | invalid request shape, policy denial, unsupported chain/operation, request/address mismatch, missing `key_id`, malformed payload, or unavailable custody backend |
| `404` | missing key |
| `409` | duplicate key creation |
| `500` | unexpected internal failure |

Classified advanced-operation errors are prefixed in Vault's error string as `[error_code] message`. The Go client preserves the underlying Vault error in `*client.APIError`; call `client.ErrorCode(err)` to extract the typed `v1.ErrorCode`. Compare it with constants such as `v1.ErrorUnsupportedEIP712Schema`; the function returns an empty code for legacy or otherwise unclassified errors.

Codes currently emitted by advanced request decoding, validation, policy enforcement, and artifact inspection include:

- `unsupported_eip712_schema`
- `invalid_eip712_domain`
- `invalid_eip712_message`
- `unsupported_erc4337_version`
- `unsupported_account_implementation`
- `unsupported_account_signing_schema`
- `invalid_user_operation`
- `user_operation_hash_mismatch`
- `invalid_eip7702_authorization`
- `authorization_signer_mismatch`
- `invalid_authorization_list`
- `unsupported_transaction_type`
- `delegate_not_allowed`
- `eip7702_revocation_not_allowed`
- `signing_operation_not_allowed`
- `signature_verification_failed`

The error contract also reserves `type4_transaction_not_supported`. The current type-4 route rejects unsupported transaction identifiers during request validation, so that reserved code is not normally emitted.

HTTP status remains `400` for these validation, unsupported-capability, and policy-denial classes. Always branch on the stable code rather than parsing the human-readable suffix. Not every `400` has a code.

Typical validation and policy errors include messages such as:

- `key_id is required`
- `source address does not match key signer address`
- `network "..." is not allowed`
- `gas_limit exceeds configured cap`
- `token contract is not allowlisted`
- `signing operation is not explicitly allowed`
- `EIP-712 schema is not explicitly allowed`
- `expected_user_operation_hash does not match reconstructed hash`
- `EIP-7702 wildcard chain_id is not allowed`
- `max_authorization_list_entries must explicitly allow type-4 authorization entries`

## Go client mapping

The Go client is organized by capability:

| Area | Methods |
| --- | --- |
| `Client` | `Version` |
| `Client.Keys` | `Create`, `Read`, `List`, `SetActive`, `SetPolicy` |
| `Client.Signing` | `SignEVMLegacyTransfer`, `SignEVMEIP1559Transfer`, `SignEVMContractCall`, `SignEVMEIP712`, `SignEVMUserOperation`, `SignEVMEIP7702Authorization`, `SignEVMEIP7702Transaction`, and the existing TRON signing methods |
| `Client.Payloads` | `Verify`, `Recover`, `VerifyEVMEIP712`, `VerifyEVMUserOperation`, `VerifyEVMEIP7702Authorization`, `RecoverEVMEIP7702Transaction` |

The Go client also includes typed request builders for the owner-based TRON routes:

- `NewTRONOwnerSignRequestBase`
- `NewTRONFreezeBalanceV2Request`
- `NewTRONUnfreezeBalanceV2Request`
- `NewTRONDelegateResourceRequest`
- `NewTRONUndelegateResourceRequest`
- `NewTRONWithdrawExpireUnfreezeRequest`
- `NewTRONVoteWitnessRequest`
- `NewTRONWithdrawBalanceRequest`

Example:

```go
vaultClient, _ := api.NewClient(api.DefaultConfig())
vaultClient.SetAddress(os.Getenv("VAULT_ADDR"))
vaultClient.SetToken(os.Getenv("VAULT_TOKEN"))

client := csclient.NewFromVault(vaultClient, "chain-signer")

resp, err := client.Signing.SignEVMEIP1559Transfer(ctx, v1.EVMEIP1559TransferSignRequest{
	BaseSignRequest: v1.BaseSignRequest{
		KeyID:         "payments-evm",
		ChainFamily:   v1.ChainFamilyEVM,
		Network:       "ethereum-sepolia",
		RequestID:     "req-123",
		SourceAddress: "0xYourSignerAddress",
	},
	ChainID:              11155111,
	To:                   "0x1111111111111111111111111111111111111111",
	Value:                "1",
	Nonce:                7,
	GasLimit:             21000,
	MaxFeePerGas:         "1500",
	MaxPriorityFeePerGas: "100",
})
```
