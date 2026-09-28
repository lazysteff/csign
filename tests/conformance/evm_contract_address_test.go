package conformance_test

import (
	"context"
	"testing"

	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestConformance_ContractDestinationPolicyPreservesAddressEncoding(t *testing.T) {
	const destination = "0x534b2f3a21130d7a60830c2df862319e593943a3"
	ctx := context.Background()
	backend, storage := newTestBackend(t, nil)
	policy := v1.Policy{
		AllowedSigningOperations: []string{v1.OperationEVMContractEIP1559},
		AllowedNetworks:          []string{testEVMNetwork},
		AllowedChainIDs:          []int64{testEVMChainID},
		AllowedTokenContracts:    []string{destination},
		AllowedSelectors:         []string{"095ea7b3"},
	}
	created, _ := createKey(t, ctx, backend, storage, v1.CreateKeyRequest{
		KeyID: "contract-address", ChainFamily: v1.ChainFamilyEVM,
		CustodyMode: v1.CustodyModeMVP, ImportPrivateKey: testPrivHex, Policy: policy,
	})
	request := v1.EVMContractCallSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID: created.KeyID, ChainFamily: v1.ChainFamilyEVM,
			Network: testEVMNetwork, RequestID: testRequestID, SourceAddress: created.SignerAddress,
		},
		ChainID: testEVMChainID, To: common.HexToAddress(destination).Hex(), Value: "0",
		Data:  "0x095ea7b300000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000001",
		Nonce: 1, GasLimit: 50000, MaxFeePerGas: "1000", MaxPriorityFeePerGas: "100",
	}
	before := signEVMContract(t, ctx, backend, storage, request)
	policy.AllowedContractDestinations = []string{destination}
	_, err := handle(t, ctx, backend, storage, logical.UpdateOperation, routes.KeyPolicyRoot+"/"+created.KeyID, mustMap(t, v1.UpdateKeyPolicyRequest{
		Policy: v1.StructuredPolicyFromPolicy(policy),
	}))
	require.NoError(t, err)
	after := signEVMContract(t, ctx, backend, storage, request)
	require.Equal(t, before.SignedPayload, after.SignedPayload)
	request.To = destination
	lowercase := signEVMContract(t, ctx, backend, storage, request)
	require.Equal(t, after.SignedPayload, lowercase.SignedPayload)
	raw, err := enc.DecodeHex(after.SignedPayload)
	require.NoError(t, err)
	var transaction types.Transaction
	require.NoError(t, transaction.UnmarshalBinary(raw))
	require.Equal(t, common.HexToAddress(destination), *transaction.To())
}
