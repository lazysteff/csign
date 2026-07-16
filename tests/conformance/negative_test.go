package conformance_test

import (
	"context"
	"errors"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestConformance_NegativeCases(t *testing.T) {
	ctx := context.Background()
	backend, storage := newTestBackend(t, nil)

	created, _ := createKey(t, ctx, backend, storage, v1.CreateKeyRequest{
		KeyID: "negatives", ChainFamily: v1.ChainFamilyEVM,
		CustodyMode: v1.CustodyModeMVP, ImportPrivateKey: testPrivHex,
		Policy: v1.Policy{
			AllowedSigningOperations: []string{v1.OperationEVMTransferLegacy},
			AllowedNetworks:          []string{testEVMNetwork},
			AllowedChainIDs:          []int64{testEVMChainID},
			MaxValue:                 "1",
		},
	})

	t.Run("policy denial on cap violation", func(t *testing.T) {
		_, err := handle(t, ctx, backend, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", map[string]interface{}{
			"key_id": "negatives", "chain_family": v1.ChainFamilyEVM, "network": testEVMNetwork,
			"request_id": testRequestID, "source_address": created.SignerAddress,
			"chain_id": testEVMChainID, "to": testEVMRecipient, "value": "2",
			"nonce": 1, "gas_limit": 21000, "gas_price": "1000",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "cap")
	})

	t.Run("address mismatch", func(t *testing.T) {
		_, err := handle(t, ctx, backend, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", map[string]interface{}{
			"key_id": "negatives", "chain_family": v1.ChainFamilyEVM, "network": testEVMNetwork,
			"request_id": testRequestID, "source_address": testEVMRecipient,
			"chain_id": testEVMChainID, "to": testEVMRecipient, "value": "1",
			"nonce": 1, "gas_limit": 21000, "gas_price": "1000",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "source address")
	})

	t.Run("disabled key", func(t *testing.T) {
		_, err := handle(t, ctx, backend, storage, logical.UpdateOperation, "v1/key-status/negatives", map[string]interface{}{"active": false})
		require.NoError(t, err)
		_, err = handle(t, ctx, backend, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", map[string]interface{}{
			"key_id": "negatives", "chain_family": v1.ChainFamilyEVM, "network": testEVMNetwork,
			"request_id": testRequestID, "source_address": created.SignerAddress,
			"chain_id": testEVMChainID, "to": testEVMRecipient, "value": "1",
			"nonce": 1, "gas_limit": 21000, "gas_price": "1000",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "disabled")
	})

	t.Run("malformed request", func(t *testing.T) {
		_, err := handle(t, ctx, backend, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", map[string]interface{}{
			"chain_family": v1.ChainFamilyEVM,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "key_id")
	})

	t.Run("invalid key ids are rejected consistently", func(t *testing.T) {
		_, err := handle(t, ctx, backend, storage, logical.UpdateOperation, "v1/keys", map[string]interface{}{
			"key_id": "", "chain_family": v1.ChainFamilyEVM,
			"custody_mode": v1.CustodyModeMVP, "import_private_key_hex": testPrivHex,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "key_id")

		_, err = handle(t, ctx, backend, storage, logical.UpdateOperation, "v1/keys", map[string]interface{}{
			"key_id": "a//b", "chain_family": v1.ChainFamilyEVM,
			"custody_mode": v1.CustodyModeMVP, "import_private_key_hex": testPrivHex,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "key_id")

		_, err = handle(t, ctx, backend, storage, logical.ReadOperation, "v1/keys/a//b", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key_id")

		_, err = handle(t, ctx, backend, storage, logical.UpdateOperation, "v1/key-status/a/./b", map[string]interface{}{"active": false})
		require.Error(t, err)
		require.Contains(t, err.Error(), "key_id")

		_, err = handle(t, ctx, backend, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", map[string]interface{}{
			"key_id": "a/../b", "chain_family": v1.ChainFamilyEVM, "network": testEVMNetwork,
			"request_id": testRequestID, "source_address": created.SignerAddress,
			"chain_id": testEVMChainID, "to": testEVMRecipient, "value": "1",
			"nonce": 1, "gas_limit": 21000, "gas_price": "1000",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "key_id")
	})

	t.Run("removed legacy status route", func(t *testing.T) {
		_, err := handle(t, ctx, backend, storage, logical.UpdateOperation, "v1/keys/negatives/status", map[string]interface{}{"active": false})
		require.Error(t, err)
		require.True(t, errors.Is(err, logical.ErrUnsupportedPath) || errors.Is(err, logical.ErrUnsupportedOperation))
	})

	t.Run("unsupported operation", func(t *testing.T) {
		_, err := handle(t, ctx, backend, storage, logical.UpdateOperation, "v1/unsupported/sign", map[string]interface{}{})
		require.Error(t, err)
		require.True(t, errors.Is(err, logical.ErrUnsupportedPath) || errors.Is(err, logical.ErrUnsupportedOperation))
	})
}
