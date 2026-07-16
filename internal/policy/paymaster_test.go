package policy

import (
	"math/big"
	"testing"

	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestValidatePaymasterControlContractCall(t *testing.T) {
	signer := testSignerAddress(t, v1.ChainFamilyEVM)
	key := baseEVMKey(t)
	key.Policy.AllowedContractDestinations = []string{testContract}
	key.Policy.AllowedSelectors = []string{"8456cb59", "3f4ba83a"}
	key.Policy.MaxValue = "0"
	request := v1.EVMContractCallSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID: "control-key", ChainFamily: v1.ChainFamilyEVM, Network: testNetwork,
			RequestID: testRequestID, SourceAddress: signer,
		},
		ChainID: testEVMChainID, To: testContract, Value: "0", Data: "0x8456cb59",
		Nonce: 1, GasLimit: 50000, MaxFeePerGas: "1000", MaxPriorityFeePerGas: "100",
	}
	require.NoError(t, ValidateEVMContractCall(key, &request))

	unpause := request
	unpause.Data = "3f4ba83a"
	require.NoError(t, ValidateEVMContractCall(key, &unpause))

	approvedWithTrailingData := request
	approvedWithTrailingData.Data = "  0X8456CB59DEADBEEF  "
	require.NoError(t, ValidateEVMContractCall(key, &approvedWithTrailingData))

	overflow := new(big.Int).Lsh(big.NewInt(1), 256).String()
	tests := []struct {
		name string
		edit func(*v1.EVMContractCallSignRequest)
		kind faults.Kind
	}{
		{name: "missing destination", edit: func(r *v1.EVMContractCallSignRequest) { r.To = "" }, kind: faults.Invalid},
		{name: "wrong destination", edit: func(r *v1.EVMContractCallSignRequest) { r.To = testRecipient }, kind: faults.PolicyDenied},
		{name: "wrong network", edit: func(r *v1.EVMContractCallSignRequest) { r.Network = "ethereum-mainnet" }, kind: faults.PolicyDenied},
		{name: "wrong chain", edit: func(r *v1.EVMContractCallSignRequest) { r.ChainID = 1 }, kind: faults.PolicyDenied},
		{name: "empty calldata", edit: func(r *v1.EVMContractCallSignRequest) { r.Data = "" }, kind: faults.Invalid},
		{name: "short calldata", edit: func(r *v1.EVMContractCallSignRequest) { r.Data = "0x8456" }, kind: faults.Invalid},
		{name: "odd calldata", edit: func(r *v1.EVMContractCallSignRequest) { r.Data = "0x8456c" }, kind: faults.Invalid},
		{name: "malformed calldata", edit: func(r *v1.EVMContractCallSignRequest) { r.Data = "0xnothex" }, kind: faults.Invalid},
		{name: "wrong selector", edit: func(r *v1.EVMContractCallSignRequest) { r.Data = "0xdeadbeef" }, kind: faults.PolicyDenied},
		{name: "nonzero value", edit: func(r *v1.EVMContractCallSignRequest) { r.Value = "1" }, kind: faults.PolicyDenied},
		{name: "negative value", edit: func(r *v1.EVMContractCallSignRequest) { r.Value = "-1" }, kind: faults.Invalid},
		{name: "overflowing value", edit: func(r *v1.EVMContractCallSignRequest) { r.Value = overflow }, kind: faults.Invalid},
		{name: "malformed value", edit: func(r *v1.EVMContractCallSignRequest) { r.Value = "not-a-number" }, kind: faults.Invalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := request
			test.edit(&changed)
			require.Equal(t, test.kind, faults.KindOf(ValidateEVMContractCall(key, &changed)))
		})
	}
}
