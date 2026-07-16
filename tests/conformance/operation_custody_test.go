package conformance_test

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestConformance_OperationDenialDoesNotInvokeExternalCustody(t *testing.T) {
	ctx := context.Background()
	privateKey := mustPrivateKey(t, testPrivHex)
	resolveCalls := 0
	signCalls := 0
	resolver := staticResolver{
		calls: &resolveCalls,
		materials: map[string]custody.Material{"deny-all-hsm": custody.ExternalMaterial{
			Pub: &privateKey.PublicKey,
			SignFunc: func(context.Context, []byte) ([]byte, error) {
				signCalls++
				return nil, nil
			},
		}},
	}
	backend, storage := newTestBackend(t, resolver)
	created, _ := createKey(t, ctx, backend, storage, v1.CreateKeyRequest{
		KeyID:             "deny-all-external",
		ChainFamily:       v1.ChainFamilyEVM,
		CustodyMode:       v1.CustodyModePKCS11,
		PublicKeyHex:      enc.EncodeHex(ethcrypto.FromECDSAPub(&privateKey.PublicKey)),
		ExternalSignerRef: "deny-all-hsm",
	})

	_, err := handle(t, ctx, backend, storage, logical.UpdateOperation, routes.EVMEIP1559TransferSign, mustMap(t, v1.EVMEIP1559TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID: "deny-all-external", ChainFamily: v1.ChainFamilyEVM,
			Network: testEVMNetwork, RequestID: "deny-all", SourceAddress: created.SignerAddress,
		},
		ChainID: testEVMChainID, To: testEVMRecipient, Value: "1", Nonce: 1,
		GasLimit: 21000, MaxFeePerGas: "1000", MaxPriorityFeePerGas: "100",
	}))
	require.ErrorContains(t, err, "signing_operation_not_allowed")
	require.Zero(t, resolveCalls)
	require.Zero(t, signCalls)
}
