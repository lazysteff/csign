package signingops

import (
	"sync"

	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

var (
	defaultCatalogOnce sync.Once
	defaultCatalog     *Catalog
	errDefaultCatalog  error
)

// Production returns the process-wide authoritative catalog and preserves
// construction failures for the service startup path.
func Production() (*Catalog, error) {
	defaultCatalogOnce.Do(func() {
		defaultCatalog, errDefaultCatalog = New([]v1.SigningOperationCapability{
			{Route: routes.EVMLegacyTransferSign, Operation: v1.OperationEVMTransferLegacy},
			{Route: routes.EVMEIP1559TransferSign, Operation: v1.OperationEVMTransferEIP1559},
			{Route: routes.EVMContractCallSign, Operation: v1.OperationEVMContractEIP1559},
			{Route: routes.EVMEIP712Sign, Operation: v1.OperationEVMEIP712Typed},
			{Route: routes.EVMERC4337UserOperationSign, Operation: v1.OperationEVMERC4337UserOperation},
			{Route: routes.EVMEIP7702AuthorizationSign, Operation: v1.OperationEVMEIP7702Authorization},
			{Route: routes.EVMEIP7702TransactionSign, Operation: v1.OperationEVMEIP7702Transaction},
			{Route: routes.TRXTransferSign, Operation: v1.OperationTRXTransfer},
			{Route: routes.TRC20TransferSign, Operation: v1.OperationTRC20Transfer},
			{Route: routes.TRONFreezeBalanceV2Sign, Operation: v1.OperationTRONFreezeBalanceV2},
			{Route: routes.TRONUnfreezeBalanceV2Sign, Operation: v1.OperationTRONUnfreezeBalanceV2},
			{Route: routes.TRONDelegateResourceSign, Operation: v1.OperationTRONDelegateResource},
			{Route: routes.TRONUndelegateResourceSign, Operation: v1.OperationTRONUndelegateResource},
			{Route: routes.TRONWithdrawExpireUnfreezeSign, Operation: v1.OperationTRONWithdrawExpireUnfreeze},
			{Route: routes.TRONVoteWitnessSign, Operation: v1.OperationTRONVoteWitness},
			{Route: routes.TRONWithdrawBalanceSign, Operation: v1.OperationTRONWithdrawBalance},
		})
	})
	return defaultCatalog, errDefaultCatalog
}

// Default returns the production catalog for internal callers that cannot
// recover from a broken compiled registry, primarily tests and pure helpers.
func Default() *Catalog {
	catalog, err := Production()
	if err != nil {
		panic(err)
	}
	return catalog
}
