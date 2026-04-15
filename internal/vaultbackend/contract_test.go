package vaultbackend

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/chain-signer/chain-signer/internal/routes"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestBackendRoutesAndVerbsStayPinned(t *testing.T) {
	backend := New(nil)

	expected := map[string][]logical.Operation{
		routes.Version + `/?`: {
			logical.ReadOperation,
		},
		routes.Keys + `/?`: {
			logical.UpdateOperation,
			logical.ListOperation,
		},
		routes.KeyStatusRoot + `/` + framework.MatchAllRegex("key_id"): {
			logical.UpdateOperation,
		},
		routes.Keys + `/` + framework.MatchAllRegex("key_id"): {
			logical.ReadOperation,
		},
		routes.EVMLegacyTransferSign: {
			logical.UpdateOperation,
		},
		routes.EVMEIP1559TransferSign: {
			logical.UpdateOperation,
		},
		routes.EVMContractCallSign: {
			logical.UpdateOperation,
		},
		routes.TRXTransferSign: {
			logical.UpdateOperation,
		},
		routes.TRC20TransferSign: {
			logical.UpdateOperation,
		},
		routes.TRONFreezeBalanceV2Sign: {
			logical.UpdateOperation,
		},
		routes.TRONUnfreezeBalanceV2Sign: {
			logical.UpdateOperation,
		},
		routes.TRONDelegateResourceSign: {
			logical.UpdateOperation,
		},
		routes.TRONUndelegateResourceSign: {
			logical.UpdateOperation,
		},
		routes.TRONWithdrawExpireUnfreezeSign: {
			logical.UpdateOperation,
		},
		routes.Verify: {
			logical.UpdateOperation,
		},
		routes.Recover: {
			logical.UpdateOperation,
		},
	}

	require.Len(t, backend.Paths, len(expected))
	for _, path := range backend.Paths {
		ops, ok := expected[path.Pattern]
		require.Truef(t, ok, "unexpected route pattern %q", path.Pattern)
		require.Len(t, path.Operations, len(ops))
		for _, op := range ops {
			_, exists := path.Operations[op]
			require.Truef(t, exists, "route %q missing operation %v", path.Pattern, op)
		}
	}

	legacyStatusPattern := routes.Keys + `/` + framework.GenericNameRegex("key_id") + `/status`
	readPattern := routes.Keys + `/` + framework.MatchAllRegex("key_id")
	statusPattern := routes.KeyStatusRoot + `/` + framework.MatchAllRegex("key_id")
	readIndex := -1
	statusIndex := -1
	for i, path := range backend.Paths {
		require.NotEqual(t, legacyStatusPattern, path.Pattern)
		switch path.Pattern {
		case readPattern:
			readIndex = i
		case statusPattern:
			statusIndex = i
		}
	}
	require.NotEqual(t, -1, readIndex)
	require.NotEqual(t, -1, statusIndex)
	require.Less(t, statusIndex, readIndex)
	for i, path := range backend.Paths {
		if path.Pattern == readPattern {
			continue
		}
		if strings.HasPrefix(path.Pattern, routes.Keys+`/`) {
			require.Less(t, i, readIndex, "more-specific v1/keys routes must be registered before the greedy read route")
		}
	}
}

func TestHierarchicalKeyRoutesAcceptGreedyKeyIDs(t *testing.T) {
	ctx := context.Background()
	backend := New(nil)
	conf := logical.TestBackendConfig()
	require.NoError(t, backend.Setup(ctx, conf))
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
