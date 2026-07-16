package service

import (
	"context"

	"github.com/chain-signer/chain-signer/internal/chain/evm"
	"github.com/chain-signer/chain-signer/internal/chain/tron"
	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/policy"
	"github.com/chain-signer/chain-signer/internal/routes"
	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

type OperationExecutor func(context.Context, custody.Material, any) (any, error)

type OperationDescriptor struct {
	v1.SigningOperationCapability
	NewRequest func() any
	Validate   policy.Validator
	Execute    OperationExecutor
}

type OperationRegistry interface {
	Lookup(string) (OperationDescriptor, error)
	Routes() []string
	Catalog() *signingops.Catalog
}

type Registry struct {
	catalog *signingops.Catalog
	order   []OperationDescriptor
	byRoute map[string]OperationDescriptor
}

func NewRegistry(catalog *signingops.Catalog, descriptors []OperationDescriptor) (*Registry, error) {
	if catalog == nil {
		return nil, faults.New(faults.Internal, "signing operation catalog is required")
	}
	out := &Registry{
		catalog: catalog,
		order:   make([]OperationDescriptor, 0, len(descriptors)),
		byRoute: make(map[string]OperationDescriptor, len(descriptors)),
	}
	for _, descriptor := range descriptors {
		if descriptor.Route == "" {
			return nil, faults.New(faults.Internal, "operation route is required")
		}
		if err := catalog.ValidateBinding(descriptor.Route, descriptor.Operation); err != nil {
			return nil, faults.Newf(faults.Internal, "invalid signing operation descriptor: %v", err)
		}
		if descriptor.NewRequest == nil || descriptor.Validate == nil || descriptor.Execute == nil {
			return nil, faults.Newf(faults.Internal, "operation %q is missing required callbacks", descriptor.Route)
		}
		if _, err := newOperationRequest(descriptor); err != nil {
			return nil, faults.Newf(faults.Internal, "operation %q has an invalid request factory: %v", descriptor.Route, err)
		}
		if _, exists := out.byRoute[descriptor.Route]; exists {
			return nil, faults.Newf(faults.Internal, "duplicate operation route %q", descriptor.Route)
		}
		out.order = append(out.order, descriptor)
		out.byRoute[descriptor.Route] = descriptor
	}
	catalogEntries := catalog.Entries()
	if len(out.order) != len(catalogEntries) {
		return nil, faults.Newf(faults.Internal, "signing catalog has %d entries but descriptor registry has %d", len(catalogEntries), len(out.order))
	}
	return out, nil
}

func MustNewRegistry(catalog *signingops.Catalog, descriptors []OperationDescriptor) *Registry {
	registry, err := NewRegistry(catalog, descriptors)
	if err != nil {
		panic(err)
	}
	return registry
}

func DefaultOperationDescriptors(catalog *signingops.Catalog) []OperationDescriptor {
	return []OperationDescriptor{
		newOperation(catalog, routes.EVMLegacyTransferSign, policy.ValidateEVMLegacyTransfer, evm.SignLegacyTransfer),
		newOperation(catalog, routes.EVMEIP1559TransferSign, policy.ValidateEVMEIP1559Transfer, evm.SignEIP1559Transfer),
		newOperation(catalog, routes.EVMContractCallSign, policy.ValidateEVMContractCall, evm.SignContractCall),
		newOperation(catalog, routes.EVMEIP712Sign, policy.ValidateEVMEIP712, evm.SignEIP712),
		newOperation(catalog, routes.EVMERC4337UserOperationSign, policy.ValidateEVMUserOperation, evm.SignUserOperation),
		newOperation(catalog, routes.EVMEIP7702AuthorizationSign, policy.ValidateEVMEIP7702Authorization, evm.SignEIP7702Authorization),
		newOperation(catalog, routes.EVMEIP7702TransactionSign, policy.ValidateEVMEIP7702Transaction, evm.SignEIP7702Transaction),
		newOperation(catalog, routes.TRXTransferSign, policy.ValidateTRXTransfer, tron.SignTRXTransfer),
		newOperation(catalog, routes.TRC20TransferSign, policy.ValidateTRC20Transfer, tron.SignTRC20Transfer),
		newOperation(catalog, routes.TRONFreezeBalanceV2Sign, policy.ValidateTRONFreezeBalanceV2, tron.SignTRONFreezeBalanceV2),
		newOperation(catalog, routes.TRONUnfreezeBalanceV2Sign, policy.ValidateTRONUnfreezeBalanceV2, tron.SignTRONUnfreezeBalanceV2),
		newOperation(catalog, routes.TRONDelegateResourceSign, policy.ValidateTRONDelegateResource, tron.SignTRONDelegateResource),
		newOperation(catalog, routes.TRONUndelegateResourceSign, policy.ValidateTRONUndelegateResource, tron.SignTRONUndelegateResource),
		newOperation(catalog, routes.TRONWithdrawExpireUnfreezeSign, policy.ValidateTRONWithdrawExpireUnfreeze, tron.SignTRONWithdrawExpireUnfreeze),
		newOperation(catalog, routes.TRONVoteWitnessSign, policy.ValidateTRONVoteWitness, tron.SignTRONVoteWitness),
		newOperation(catalog, routes.TRONWithdrawBalanceSign, policy.ValidateTRONWithdrawBalance, tron.SignTRONWithdrawBalance),
	}
}

func (r *Registry) Lookup(route string) (OperationDescriptor, error) {
	descriptor, ok := r.byRoute[route]
	if !ok {
		return OperationDescriptor{}, faults.Newf(faults.Unsupported, "unsupported route %q", route)
	}
	return descriptor, nil
}

func (r *Registry) Routes() []string {
	routes := make([]string, 0, len(r.order))
	for _, descriptor := range r.order {
		routes = append(routes, descriptor.Route)
	}
	return routes
}

func (r *Registry) Catalog() *signingops.Catalog {
	return r.catalog
}

func (r *Registry) OperationCapabilities() []v1.SigningOperationCapability {
	return r.catalog.Entries()
}

func newOperation[T any, R any](
	catalog *signingops.Catalog,
	route string,
	validate func(domain.Key, *T) error,
	execute func(context.Context, custody.Material, *T) (*R, error),
) OperationDescriptor {
	operation, _ := catalog.OperationForRoute(route)
	return OperationDescriptor{
		SigningOperationCapability: v1.SigningOperationCapability{Route: route, Operation: operation},
		NewRequest: func() any {
			return new(T)
		},
		Validate: func(key domain.Key, request any) error {
			typed, ok := request.(*T)
			if !ok {
				return faults.Newf(faults.Internal, "unexpected request type for route %q", route)
			}
			return validate(key, typed)
		},
		Execute: func(ctx context.Context, material custody.Material, request any) (any, error) {
			typed, ok := request.(*T)
			if !ok {
				return nil, faults.Newf(faults.Internal, "unexpected request type for route %q", route)
			}
			return execute(ctx, material, typed)
		},
	}
}
