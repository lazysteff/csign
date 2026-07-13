package vaultbackend

import (
	"context"
	"errors"
	"testing"

	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestHierarchicalKeyRoutesAcceptGreedyKeyIDs(t *testing.T) {
	ctx := context.Background()
	backend := New(nil)
	require.NoError(t, backend.Setup(ctx, logical.TestBackendConfig()))
	storage := new(logical.InmemStorage)

	createReq := logical.TestRequest(t, logical.UpdateOperation, "v1/keys")
	createReq.Storage = storage
	createReq.Data = map[string]interface{}{
		"key_id":                 "foo/status/bar",
		"chain_family":           "evm",
		"custody_mode":           "mvp",
		"import_private_key_hex": "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad",
	}
	_, err := backend.HandleRequest(ctx, createReq)
	require.NoError(t, err)

	readReq := logical.TestRequest(t, logical.ReadOperation, "v1/keys/foo/status/bar")
	readReq.Storage = storage
	readResp, err := backend.HandleRequest(ctx, readReq)
	require.NoError(t, err)
	require.Equal(t, "foo/status/bar", readResp.Data["key_id"])

	statusReq := logical.TestRequest(t, logical.UpdateOperation, "v1/key-status/foo/status/bar")
	statusReq.Storage = storage
	statusReq.Data = map[string]interface{}{"active": false}
	statusResp, err := backend.HandleRequest(ctx, statusReq)
	require.NoError(t, err)
	require.Equal(t, false, statusResp.Data["active"])

	legacyReq := logical.TestRequest(t, logical.UpdateOperation, "v1/keys/foo/status/bar/status")
	legacyReq.Storage = storage
	legacyReq.Data = map[string]interface{}{"active": true}
	_, err = backend.HandleRequest(ctx, legacyReq)
	require.Error(t, err)
	require.True(t, errors.Is(err, logical.ErrUnsupportedPath) || errors.Is(err, logical.ErrUnsupportedOperation))
}

func TestStructuredPolicyUpdateRejectsOpaqueContextAndPreservesLegacyStoredContext(t *testing.T) {
	ctx := context.Background()
	backend := New(nil)
	require.NoError(t, backend.Setup(ctx, logical.TestBackendConfig()))
	storage := new(logical.InmemStorage)

	createReq := logical.TestRequest(t, logical.UpdateOperation, routes.Keys)
	createReq.Storage = storage
	createReq.Data = map[string]interface{}{
		"key_id":                 "legacy-policy-context",
		"chain_family":           v1.ChainFamilyEVM,
		"custody_mode":           v1.CustodyModeMVP,
		"import_private_key_hex": "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad",
		"policy": map[string]interface{}{
			"allowed_networks":          []interface{}{"old-network"},
			"additional_policy_context": map[string]interface{}{"workflow": "legacy"},
		},
	}
	_, err := backend.HandleRequest(ctx, createReq)
	require.NoError(t, err)

	rejectedReq := logical.TestRequest(t, logical.UpdateOperation, routes.KeyPolicyRoot+"/legacy-policy-context")
	rejectedReq.Storage = storage
	rejectedReq.Data = map[string]interface{}{
		"policy": map[string]interface{}{
			"additional_policy_context": map[string]interface{}{"workflow": "replacement"},
		},
	}
	_, err = backend.HandleRequest(ctx, rejectedReq)
	require.ErrorContains(t, err, `unknown field "additional_policy_context"`)

	updateReq := logical.TestRequest(t, logical.UpdateOperation, routes.KeyPolicyRoot+"/legacy-policy-context")
	updateReq.Storage = storage
	updateReq.Data = map[string]interface{}{
		"policy": map[string]interface{}{
			"allowed_networks": []interface{}{"new-network"},
			"max_gas_limit":    21_000,
		},
	}
	updatedResp, err := backend.HandleRequest(ctx, updateReq)
	require.NoError(t, err)
	var updated v1.KeyResponse
	require.NoError(t, decode(updatedResp.Data, &updated))
	require.Equal(t, []string{"new-network"}, updated.Policy.AllowedNetworks)
	require.Equal(t, uint64(21_000), updated.Policy.MaxGasLimit)
	require.Equal(t, map[string]string{"workflow": "legacy"}, updated.Policy.AdditionalPolicyContext)
}
