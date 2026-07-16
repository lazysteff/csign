package conformance_test

import (
	"context"
	"encoding/json"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestConformance_HierarchicalKeyIDRoundTripsAcrossManagementAndSigning(t *testing.T) {
	ctx := context.Background()
	backend, storage := newTestBackend(t, nil)

	keyID := "foo/status/bar"
	created, _ := createKey(t, ctx, backend, storage, v1.CreateKeyRequest{
		KeyID: keyID, ChainFamily: v1.ChainFamilyEVM,
		CustodyMode: v1.CustodyModeMVP, ImportPrivateKey: testPrivHex,
		Policy: v1.Policy{AllowedSigningOperations: []string{v1.OperationEVMTransferLegacy}},
	})

	read, _ := readKey(t, ctx, backend, storage, keyID)
	require.Equal(t, keyID, read.KeyID)
	require.Equal(t, created.SignerAddress, read.SignerAddress)

	listed, err := handle(t, ctx, backend, storage, logical.ListOperation, "v1/keys", nil)
	require.NoError(t, err)
	var payload struct {
		Keys []string `json:"keys"`
	}
	raw, err := json.Marshal(listed.Data)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &payload))
	require.Contains(t, payload.Keys, keyID)

	_, err = handle(t, ctx, backend, storage, logical.UpdateOperation, "v1/key-status/"+keyID, map[string]interface{}{"active": false})
	require.NoError(t, err)
	_, err = handle(t, ctx, backend, storage, logical.UpdateOperation, "v1/key-status/"+keyID, map[string]interface{}{"active": true})
	require.NoError(t, err)

	signed := signEVMLegacy(t, ctx, backend, storage, v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID: keyID, ChainFamily: v1.ChainFamilyEVM, Network: testEVMNetwork,
			RequestID: testRequestID, SourceAddress: created.SignerAddress,
		},
		ChainID: testEVMChainID, To: testEVMRecipient, Value: "1",
		Nonce: 1, GasLimit: 21000, GasPrice: "1000",
	})
	require.Equal(t, keyID, signed.KeyID)
}
