package v1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAdvancedRequestsRejectUnknownTopLevelFields(t *testing.T) {
	tests := []struct {
		name string
		new  func() any
	}{
		{name: "EIP-712 sign", new: func() any { return new(EVMEIP712SignRequest) }},
		{name: "EIP-712 verify", new: func() any { return new(EVMEIP712VerifyRequest) }},
		{name: "UserOperation sign", new: func() any { return new(EVMUserOperationSignRequest) }},
		{name: "UserOperation verify", new: func() any { return new(EVMUserOperationVerifyRequest) }},
		{name: "EIP-7702 authorization sign", new: func() any { return new(EVMEIP7702AuthorizationSignRequest) }},
		{name: "EIP-7702 authorization verify", new: func() any { return new(EVMEIP7702AuthorizationVerifyRequest) }},
		{name: "EIP-7702 transaction sign", new: func() any { return new(EVMEIP7702TransactionSignRequest) }},
		{name: "EIP-7702 transaction recover", new: func() any { return new(EVMEIP7702TransactionRecoverRequest) }},
		{name: "key policy update", new: func() any { return new(UpdateKeyPolicyRequest) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := json.Unmarshal([]byte(`{"unexpected":true}`), test.new())
			require.ErrorContains(t, err, `unknown field "unexpected"`)
		})
	}
}

func TestAdvancedSigningRequestsRejectOpaqueMetadata(t *testing.T) {
	requests := []any{
		new(EVMEIP712SignRequest),
		new(EVMUserOperationSignRequest),
		new(EVMEIP7702AuthorizationSignRequest),
		new(EVMEIP7702TransactionSignRequest),
	}
	for _, request := range requests {
		err := json.Unmarshal([]byte(`{"metadata":{"workflow":"opaque"}}`), request)
		require.ErrorContains(t, err, `unknown field "metadata"`)
	}
}

func TestAdvancedRequestsRejectUnknownNestedFields(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		out     any
		field   string
	}{
		{name: "EIP-712 domain salt", payload: `{"domain":{"salt":"0x00"}}`, out: new(EVMEIP712SignRequest), field: "salt"},
		{name: "EIP-712 message field", payload: `{"message":{"witness":"0x00"}}`, out: new(EVMEIP712VerifyRequest), field: "witness"},
		{name: "UserOperation field", payload: `{"user_operation":{"signature":"0x"}}`, out: new(EVMUserOperationSignRequest), field: "signature"},
		{name: "Paymaster field", payload: `{"user_operation":{"paymaster":{"context":"0x"}}}`, out: new(EVMUserOperationVerifyRequest), field: "context"},
		{name: "repeated EIP-7702 data prefix", payload: `{"user_operation":{"eip7702":{"factory_data":"0x"}}}`, out: new(EVMUserOperationSignRequest), field: "factory_data"},
		{name: "access-list field", payload: `{"access_list":[{"address":"0x0000000000000000000000000000000000000000","keys":[]}]}`, out: new(EVMEIP7702TransactionSignRequest), field: "keys"},
		{name: "authorization authority hint", payload: `{"authorization_list":[{"expected_authority_address":"0x0000000000000000000000000000000000000000"}]}`, out: new(EVMEIP7702TransactionSignRequest), field: "expected_authority_address"},
		{name: "repeated authorization nonce prefix", payload: `{"authorization_list":[{"authorization_nonce":"0"}]}`, out: new(EVMEIP7702TransactionSignRequest), field: "authorization_nonce"},
		{name: "custom delegate field", payload: `{"authorization_list":[{"delegate_address":"0x0000000000000000000000000000000000000000"}]}`, out: new(EVMEIP7702TransactionSignRequest), field: "delegate_address"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := json.Unmarshal([]byte(test.payload), test.out)
			require.ErrorContains(t, err, `unknown field "`+test.field+`"`)
		})
	}
}

func TestAdvancedRequestsRejectMalformedJSONTypes(t *testing.T) {
	tests := []struct {
		payload string
		out     any
	}{
		{payload: `{"chain_id":1}`, out: new(EVMEIP712SignRequest)},
		{payload: `{"user_operation":{"call_data":{}}}`, out: new(EVMUserOperationSignRequest)},
		{payload: `{"authorization_list":"none"}`, out: new(EVMEIP7702TransactionSignRequest)},
	}
	for _, test := range tests {
		require.Error(t, json.Unmarshal([]byte(test.payload), test.out))
	}
}

func TestAdvancedRequestsRejectTrailingJSONDocuments(t *testing.T) {
	var request EVMEIP712SignRequest
	require.Error(t, json.Unmarshal([]byte(`{} {}`), &request))
}

func TestStrictRequestsRejectDuplicateFieldsAtAnyDepth(t *testing.T) {
	var topLevel EVMEIP712SignRequest
	err := json.Unmarshal([]byte(`{"chain_id":"1","chain_id":"2"}`), &topLevel)
	require.ErrorContains(t, err, `duplicate JSON field "chain_id"`)

	var nested EVMEIP712SignRequest
	err = json.Unmarshal([]byte(`{"domain":{"chain_id":"1","chain_id":"2"}}`), &nested)
	require.ErrorContains(t, err, `duplicate JSON field "domain.chain_id"`)
}
