package vaultbackend

import (
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
		routes.Version + `/?`: {logical.ReadOperation},
		routes.Keys + `/?`:    {logical.UpdateOperation, logical.ListOperation},
		routes.KeyStatusRoot + `/` + framework.MatchAllRegex("key_id"): {logical.UpdateOperation},
		routes.KeyPolicyRoot + `/` + framework.MatchAllRegex("key_id"): {logical.UpdateOperation},
		routes.Keys + `/` + framework.MatchAllRegex("key_id"):          {logical.ReadOperation},
		routes.EVMLegacyTransferSign:                                   {logical.UpdateOperation},
		routes.EVMEIP1559TransferSign:                                  {logical.UpdateOperation},
		routes.EVMContractCallSign:                                     {logical.UpdateOperation},
		routes.EVMEIP712Sign:                                           {logical.UpdateOperation},
		routes.EVMERC4337UserOperationSign:                             {logical.UpdateOperation},
		routes.EVMEIP7702AuthorizationSign:                             {logical.UpdateOperation},
		routes.EVMEIP7702TransactionSign:                               {logical.UpdateOperation},
		routes.TRXTransferSign:                                         {logical.UpdateOperation},
		routes.TRC20TransferSign:                                       {logical.UpdateOperation},
		routes.TRONFreezeBalanceV2Sign:                                 {logical.UpdateOperation},
		routes.TRONUnfreezeBalanceV2Sign:                               {logical.UpdateOperation},
		routes.TRONDelegateResourceSign:                                {logical.UpdateOperation},
		routes.TRONUndelegateResourceSign:                              {logical.UpdateOperation},
		routes.TRONWithdrawExpireUnfreezeSign:                          {logical.UpdateOperation},
		routes.TRONVoteWitnessSign:                                     {logical.UpdateOperation},
		routes.TRONWithdrawBalanceSign:                                 {logical.UpdateOperation},
		routes.Verify:                                                  {logical.UpdateOperation},
		routes.Recover:                                                 {logical.UpdateOperation},
		routes.EVMEIP712Verify:                                         {logical.UpdateOperation},
		routes.EVMERC4337UserOperationVerify:                           {logical.UpdateOperation},
		routes.EVMEIP7702AuthorizationVerify:                           {logical.UpdateOperation},
		routes.EVMEIP7702TransactionRecover:                            {logical.UpdateOperation},
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
