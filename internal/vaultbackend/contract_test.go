package vaultbackend

import (
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
		routes.Keys + `/` + framework.GenericNameRegex("key_id"): {
			logical.ReadOperation,
		},
		routes.Keys + `/` + framework.GenericNameRegex("key_id") + `/status`: {
			logical.UpdateOperation,
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
}
