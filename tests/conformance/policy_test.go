package conformance_test

import (
	"context"
	"math/big"
	"testing"

	"github.com/chain-signer/chain-signer/internal/policy"
	"github.com/chain-signer/chain-signer/internal/routes"
	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestConformance_AdvancedEVMPolicyOptIn(t *testing.T) {
	fixture, raw := newAdvancedEVMFixture(t, "evm-advanced-policy", false)
	require.NotContains(t, raw, "private_key_hex")
	require.NotContains(t, raw, "policy", "advanced operations must not be implicitly enabled")

	permitRequest := v1.EVMEIP712SignRequest{
		EVMAdvancedSignRequestBase: fixture.base("advanced-permit-denied"),
		EIP712RegisteredPayload:    conformancePermit(fixture.signer, fixture.chainID),
	}
	_, err := handle(t, fixture.ctx, fixture.backend, fixture.storage, logical.UpdateOperation, routes.EVMEIP712Sign, mustMap(t, permitRequest))
	require.Error(t, err)
	require.ErrorContains(t, err, "signing operation is not explicitly allowed")

	_, err = handle(t, fixture.ctx, fixture.backend, fixture.storage, logical.UpdateOperation, routes.KeyPolicyRoot+"/"+fixture.keyID, map[string]interface{}{})
	require.ErrorContains(t, err, "policy is required")
	readBack, _ := readKey(t, fixture.ctx, fixture.backend, fixture.storage, fixture.keyID)
	require.True(t, readBack.Policy.IsZero())

	policy := advancedEVMPolicy()
	response, err := handle(t, fixture.ctx, fixture.backend, fixture.storage, logical.UpdateOperation, routes.KeyPolicyRoot+"/"+fixture.keyID, mustMap(t, v1.UpdateKeyPolicyRequest{Policy: v1.StructuredPolicyFromPolicy(policy)}))
	require.NoError(t, err)
	updated := decodeResponse[v1.KeyResponse](t, response)
	require.Equal(t, policy, updated.Policy)
	require.NotEmpty(t, updated.UpdatedAt)

	readBack, _ = readKey(t, fixture.ctx, fixture.backend, fixture.storage, fixture.keyID)
	require.Equal(t, policy, readBack.Policy)
}

func TestConformance_PaymasterControlPolicyReplacement(t *testing.T) {
	ctx := context.Background()
	backend, storage := newTestBackend(t, nil)
	created, _ := createKey(t, ctx, backend, storage, v1.CreateKeyRequest{
		KeyID: "paymaster-control", ChainFamily: v1.ChainFamilyEVM,
		CustodyMode: v1.CustodyModeMVP, ImportPrivateKey: testPrivHex,
	})
	controlPolicy := v1.Policy{
		AllowedNetworks:             []string{testEVMNetwork},
		AllowedChainIDs:             []int64{testEVMChainID},
		AllowedSigningOperations:    []string{v1.OperationEVMContractEIP1559},
		AllowedContractDestinations: []string{testEVMContract},
		AllowedSelectors:            []string{"8456cb59", "3f4ba83a"},
		MaxValue:                    "0",
		MaxGasLimit:                 100000,
		MaxFeePerGas:                "2000",
		MaxPriorityFeePerGas:        "1000",
	}
	response, err := handle(t, ctx, backend, storage, logical.UpdateOperation, routes.KeyPolicyRoot+"/paymaster-control", mustMap(t, v1.UpdateKeyPolicyRequest{
		Policy: v1.StructuredPolicyFromPolicy(controlPolicy),
	}))
	require.NoError(t, err)
	require.Equal(t, controlPolicy, decodeResponse[v1.KeyResponse](t, response).Policy)
	readBack, _ := readKey(t, ctx, backend, storage, "paymaster-control")
	equal, err := policy.SemanticallyEqual(signingops.Default(), v1.ChainFamilyEVM, controlPolicy, readBack.Policy)
	require.NoError(t, err)
	require.True(t, equal)

	request := v1.EVMContractCallSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID: "paymaster-control", ChainFamily: v1.ChainFamilyEVM,
			Network: testEVMNetwork, RequestID: "pause", SourceAddress: created.SignerAddress,
		},
		ChainID: testEVMChainID, To: testEVMContract, Value: "0", Data: "0x8456cb59",
		Nonce: 1, GasLimit: 50000, MaxFeePerGas: "1000", MaxPriorityFeePerGas: "100",
	}
	pause := signEVMContract(t, ctx, backend, storage, request)
	require.Equal(t, v1.OperationEVMContractEIP1559, pause.Operation)
	request.RequestID = "unpause"
	request.Data = "0X3F4BA83ADEADBEEF"
	unpause := signEVMContract(t, ctx, backend, storage, request)
	require.Equal(t, v1.OperationEVMContractEIP1559, unpause.Operation)

	overflow := new(big.Int).Lsh(big.NewInt(1), 256).String()
	mutations := []struct {
		name string
		edit func(*v1.EVMContractCallSignRequest)
	}{
		{name: "missing destination", edit: func(r *v1.EVMContractCallSignRequest) { r.To = "" }},
		{name: "wrong destination", edit: func(r *v1.EVMContractCallSignRequest) { r.To = testEVMRecipient }},
		{name: "wrong network", edit: func(r *v1.EVMContractCallSignRequest) { r.Network = "ethereum-mainnet" }},
		{name: "wrong chain", edit: func(r *v1.EVMContractCallSignRequest) { r.ChainID = 1 }},
		{name: "wrong selector", edit: func(r *v1.EVMContractCallSignRequest) { r.Data = "0xdeadbeef" }},
		{name: "nonzero value", edit: func(r *v1.EVMContractCallSignRequest) { r.Value = "1" }},
		{name: "negative value", edit: func(r *v1.EVMContractCallSignRequest) { r.Value = "-1" }},
		{name: "overflow value", edit: func(r *v1.EVMContractCallSignRequest) { r.Value = overflow }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := request
			mutation.edit(&changed)
			_, err := handle(t, ctx, backend, storage, logical.UpdateOperation, routes.EVMContractCallSign, mustMap(t, changed))
			require.Error(t, err)
		})
	}

	_, err = handle(t, ctx, backend, storage, logical.UpdateOperation, routes.EVMEIP1559TransferSign, mustMap(t, v1.EVMEIP1559TransferSignRequest{
		BaseSignRequest: request.BaseSignRequest,
		ChainID:         request.ChainID, To: testEVMRecipient, Value: "0", Nonce: 2,
		GasLimit: 21000, MaxFeePerGas: "1000", MaxPriorityFeePerGas: "100",
	}))
	require.ErrorContains(t, err, "signing_operation_not_allowed")
}
