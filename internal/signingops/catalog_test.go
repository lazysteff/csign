package signingops

import (
	"sync"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestDefaultCatalogIsImmutableAndConcurrentSafe(t *testing.T) {
	catalog, err := Production()
	require.NoError(t, err)
	require.Same(t, catalog, Default())
	original := catalog.Entries()
	require.Len(t, original, 16)

	changed := catalog.Entries()
	changed[0].Route = "mutated"
	changed = append(changed, v1.SigningOperationCapability{Route: "extra", Operation: "extra"})
	require.Len(t, changed, len(original)+1)
	require.Equal(t, original, catalog.Entries())

	var workers sync.WaitGroup
	for range 64 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				for _, entry := range original {
					operation, ok := catalog.OperationForRoute(entry.Route)
					if !ok || operation != entry.Operation || catalog.ValidateAllowlist([]string{entry.Operation}) != nil {
						t.Errorf("catalog changed during concurrent read for route %q", entry.Route)
						return
					}
				}
			}
		}()
	}
	workers.Wait()
}

func TestCatalogValidatesExactUniqueAllowlists(t *testing.T) {
	catalog := Default()
	require.NoError(t, catalog.ValidateAllowlist(nil))
	require.NoError(t, catalog.ValidateAllowlist([]string{}))
	require.NoError(t, catalog.ValidateAllowlist([]string{
		v1.OperationEVMContractEIP1559,
		v1.OperationEVMTransferEIP1559,
	}))

	for _, allowed := range [][]string{
		{"EVM_CONTRACT_CALL_EIP1559"},
		{"evm_contract_call_eip1559 "},
		{"unknown"},
	} {
		require.ErrorIs(t, catalog.ValidateAllowlist(allowed), ErrUnknownOperation)
	}
	require.ErrorIs(t, catalog.ValidateAllowlist([]string{
		v1.OperationEVMContractEIP1559,
		v1.OperationEVMContractEIP1559,
	}), ErrDuplicateOperation)
}

func TestCatalogRejectsInvalidDefinitions(t *testing.T) {
	_, err := New([]v1.SigningOperationCapability{{Route: "route", Operation: "operation"}, {Route: "route", Operation: "other"}})
	require.ErrorIs(t, err, ErrDuplicateRoute)
	_, err = New([]v1.SigningOperationCapability{{Route: "route-a", Operation: "operation"}, {Route: "route-b", Operation: "operation"}})
	require.ErrorIs(t, err, ErrDuplicateOperation)
	_, err = New([]v1.SigningOperationCapability{{Route: "", Operation: "operation"}})
	require.ErrorIs(t, err, ErrUnknownRoute)
	_, err = New([]v1.SigningOperationCapability{{Route: "route", Operation: ""}})
	require.ErrorIs(t, err, ErrUnknownOperation)
}
