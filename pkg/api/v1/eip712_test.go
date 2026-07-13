package v1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEIP712RequestStrictDecodePreservesTypedFields(t *testing.T) {
	payload := `{
		"key_id":"permit-key",
		"chain_family":"evm",
		"network":"ethereum-mainnet",
		"request_id":"request-1",
		"expected_signer_address":"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
		"chain_id":"1",
		"schema_id":"eip2612-permit-v1",
		"schema_version":"1",
		"domain":{
			"name":"Token",
			"version":"1",
			"chain_id":"1",
			"verifying_contract":"0x1111111111111111111111111111111111111111"
		},
		"message":{
			"owner":"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
			"spender":"0x2222222222222222222222222222222222222222",
			"value":"10",
			"nonce":"0",
			"deadline":"100"
		}
	}`

	var request EVMEIP712SignRequest
	require.NoError(t, json.Unmarshal([]byte(payload), &request))
	require.Equal(t, "permit-key", request.KeyID)
	require.Equal(t, "1", request.ChainID)
	require.Equal(t, EIP712SchemaEIP2612Permit, request.SchemaID)
	require.Equal(t, "Token", request.Domain.Name)
	require.Equal(t, "10", request.Message.Value)
}
