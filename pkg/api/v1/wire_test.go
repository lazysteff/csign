package v1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAdvancedWireFixturesDecodeIntoStructuredContracts(t *testing.T) {
	var userOperation EVMUserOperationSignRequest
	require.NoError(t, json.Unmarshal([]byte(`{
		"chain_family":"evm","network":"network","request_id":"request","key_id":"key",
		"expected_signer_address":"0x1000000000000000000000000000000000000001","chain_id":"1",
		"entry_point":"0x2000000000000000000000000000000000000002","protocol_version":"erc4337-v0.9",
		"account_implementation":"simple-account","account_implementation_version":"0.9","account_signing_schema":"simple-account-eip712-v1",
		"user_operation":{"sender":"0x3000000000000000000000000000000000000003","nonce":"7","call_data":"0x","call_gas_limit":"1","verification_gas_limit":"2","pre_verification_gas":"3","max_fee_per_gas":"4","max_priority_fee_per_gas":"1"}
	}`), &userOperation))
	require.Equal(t, "key", userOperation.KeyID)
	require.Equal(t, "7", userOperation.UserOperation.Nonce)
	require.Equal(t, ERC4337ProtocolV09, userOperation.ProtocolVersion)

	var authorization EVMEIP7702AuthorizationSignRequest
	require.NoError(t, json.Unmarshal([]byte(`{
		"chain_family":"evm","network":"network","request_id":"request","key_id":"key",
		"chain_id":"1","address":"0x2000000000000000000000000000000000000002","nonce":"7",
		"authority_address":"0x1000000000000000000000000000000000000001","authorization_schema":"eip7702-v1"
	}`), &authorization))
	require.Equal(t, "7", authorization.Nonce)
	require.Equal(t, EIP7702AuthorizationSchemaV1, authorization.AuthorizationSchema)

	var transaction EVMEIP7702TransactionSignRequest
	require.NoError(t, json.Unmarshal([]byte(`{
		"chain_family":"evm","network":"network","request_id":"request","key_id":"key",
		"chain_id":"1","nonce":"8","to":"0x2000000000000000000000000000000000000002","value":"0","gas_limit":"21000",
		"max_fee_per_gas":"4","max_priority_fee_per_gas":"1","data":"0x","access_list":[],
		"source_address":"0x1000000000000000000000000000000000000001",
		"authorization_list":[{"chain_id":"1","address":"0x3000000000000000000000000000000000000003","nonce":"7","y_parity":0,"r":"0x01","s":"0x02"}]
	}`), &transaction))
	require.Equal(t, "8", transaction.Nonce)
	require.Equal(t, "7", transaction.AuthorizationList[0].Nonce)
}

func TestCapabilityWireFixtureUsesNestedTypedRecords(t *testing.T) {
	var response VersionResponse
	require.NoError(t, json.Unmarshal([]byte(`{
		"api_version":"v1","build_version":"v1.0.0",
		"supported_account_implementations":[{"id":"simple-account","version":"0.9","protocol_versions":["erc4337-v0.9"],"signing_schemas":["simple-account-eip712-v1"],"signature_encoding":"rsv-v27"}],
		"supported_eip7702_transaction_types":[{"id":"eip7702-type-4","number":4}]
	}`), &response))
	require.Equal(t, []string{ERC4337ProtocolV09}, response.SupportedAccountImplementations[0].ProtocolVersions)
	require.Equal(t, uint8(4), response.SupportedEIP7702TransactionTypes[0].Number)
}
