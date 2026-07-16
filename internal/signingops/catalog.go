package signingops

import (
	"errors"
	"fmt"
	"sync"

	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

var (
	ErrUnknownRoute       = errors.New("unknown signing route")
	ErrDuplicateRoute     = errors.New("duplicate signing route")
	ErrUnknownOperation   = errors.New("unknown signing operation")
	ErrDuplicateOperation = errors.New("duplicate signing operation")
	ErrRouteMismatch      = errors.New("signing route operation mismatch")
)

// Catalog is an immutable signing-operation registry. Construction copies all
// caller-owned state and every accessor returns a copy, so concurrent readers
// cannot mutate or observe changing registry contents.
type Catalog struct {
	entries    []v1.SigningOperationCapability
	byRoute    map[string]string
	operations map[string]struct{}
}

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

func New(entries []v1.SigningOperationCapability) (*Catalog, error) {
	catalog := &Catalog{
		entries:    append([]v1.SigningOperationCapability(nil), entries...),
		byRoute:    make(map[string]string, len(entries)),
		operations: make(map[string]struct{}, len(entries)),
	}
	for _, entry := range catalog.entries {
		if entry.Route == "" {
			return nil, fmt.Errorf("%w: empty route", ErrUnknownRoute)
		}
		if entry.Operation == "" {
			return nil, fmt.Errorf("%w: route %q has an empty operation", ErrUnknownOperation, entry.Route)
		}
		if _, exists := catalog.byRoute[entry.Route]; exists {
			return nil, fmt.Errorf("%w %q", ErrDuplicateRoute, entry.Route)
		}
		if _, exists := catalog.operations[entry.Operation]; exists {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateOperation, entry.Operation)
		}
		catalog.byRoute[entry.Route] = entry.Operation
		catalog.operations[entry.Operation] = struct{}{}
	}
	return catalog, nil
}

func MustNew(entries []v1.SigningOperationCapability) *Catalog {
	catalog, err := New(entries)
	if err != nil {
		panic(err)
	}
	return catalog
}

func (c *Catalog) Entries() []v1.SigningOperationCapability {
	if c == nil {
		return nil
	}
	return append([]v1.SigningOperationCapability(nil), c.entries...)
}

func (c *Catalog) OperationForRoute(route string) (string, bool) {
	if c == nil {
		return "", false
	}
	operation, ok := c.byRoute[route]
	return operation, ok
}

func (c *Catalog) ValidateBinding(route, operation string) error {
	expected, ok := c.OperationForRoute(route)
	if !ok {
		return fmt.Errorf("%w %q", ErrUnknownRoute, route)
	}
	if operation != expected {
		return fmt.Errorf("%w: route %q requires %q, got %q", ErrRouteMismatch, route, expected, operation)
	}
	return nil
}

// ValidateAllowlist accepts nil and empty lists as valid deny-all policies.
// Non-empty entries must be exact, unique canonical operation identifiers.
func (c *Catalog) ValidateAllowlist(allowed []string) error {
	if c == nil {
		return fmt.Errorf("%w: catalog is unavailable", ErrUnknownOperation)
	}
	seen := make(map[string]struct{}, len(allowed))
	for _, operation := range allowed {
		if _, ok := c.operations[operation]; !ok {
			return fmt.Errorf("%w %q", ErrUnknownOperation, operation)
		}
		if _, ok := seen[operation]; ok {
			return fmt.Errorf("%w %q", ErrDuplicateOperation, operation)
		}
		seen[operation] = struct{}{}
	}
	return nil
}

func (c *Catalog) Allows(allowed []string, operation string) bool {
	for _, candidate := range allowed {
		if candidate == operation {
			return true
		}
	}
	return false
}
