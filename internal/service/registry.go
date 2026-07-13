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
)

type OperationExecutor func(context.Context, custody.Material, any) (any, error)

type OperationDescriptor struct {
	Route      string
	NewRequest func() any
	Validate   policy.Validator
	Execute    OperationExecutor
}

type OperationRegistry interface {
	Lookup(string) (OperationDescriptor, error)
	Routes() []string
}

type Registry struct {
	order   []OperationDescriptor
	byRoute map[string]OperationDescriptor
}

func NewRegistry(descriptors []OperationDescriptor) (*Registry, error) {
	out := &Registry{
		order:   make([]OperationDescriptor, 0, len(descriptors)),
		byRoute: make(map[string]OperationDescriptor, len(descriptors)),
	}
	for _, descriptor := range descriptors {
		if descriptor.Route == "" {
			return nil, faults.New(faults.Internal, "operation route is required")
		}
		if descriptor.NewRequest == nil || descriptor.Validate == nil || descriptor.Execute == nil {
			return nil, faults.Newf(faults.Internal, "operation %q is missing required callbacks", descriptor.Route)
		}
		if _, exists := out.byRoute[descriptor.Route]; exists {
			return nil, faults.Newf(faults.Internal, "duplicate operation route %q", descriptor.Route)
		}
		out.order = append(out.order, descriptor)
		out.byRoute[descriptor.Route] = descriptor
	}
	return out, nil
}

func MustNewRegistry(descriptors []OperationDescriptor) *Registry {
	registry, err := NewRegistry(descriptors)
	if err != nil {
		panic(err)
	}
	return registry
}

func DefaultOperationDescriptors() []OperationDescriptor {
	return []OperationDescriptor{
		newOperation(routes.EVMLegacyTransferSign, policy.ValidateEVMLegacyTransfer, evm.SignLegacyTransfer),
		newOperation(routes.EVMEIP1559TransferSign, policy.ValidateEVMEIP1559Transfer, evm.SignEIP1559Transfer),
		newOperation(routes.EVMContractCallSign, policy.ValidateEVMContractCall, evm.SignContractCall),
		newOperation(routes.EVMEIP712Sign, policy.ValidateEVMEIP712, evm.SignEIP712),
		newOperation(routes.EVMERC4337UserOperationSign, policy.ValidateEVMUserOperation, evm.SignUserOperation),
		newOperation(routes.EVMEIP7702AuthorizationSign, policy.ValidateEVMEIP7702Authorization, evm.SignEIP7702Authorization),
		newOperation(routes.EVMEIP7702TransactionSign, policy.ValidateEVMEIP7702Transaction, evm.SignEIP7702Transaction),
		newOperation(routes.TRXTransferSign, policy.ValidateTRXTransfer, tron.SignTRXTransfer),
		newOperation(routes.TRC20TransferSign, policy.ValidateTRC20Transfer, tron.SignTRC20Transfer),
		newOperation(routes.TRONFreezeBalanceV2Sign, policy.ValidateTRONFreezeBalanceV2, tron.SignTRONFreezeBalanceV2),
		newOperation(routes.TRONUnfreezeBalanceV2Sign, policy.ValidateTRONUnfreezeBalanceV2, tron.SignTRONUnfreezeBalanceV2),
		newOperation(routes.TRONDelegateResourceSign, policy.ValidateTRONDelegateResource, tron.SignTRONDelegateResource),
		newOperation(routes.TRONUndelegateResourceSign, policy.ValidateTRONUndelegateResource, tron.SignTRONUndelegateResource),
		newOperation(routes.TRONWithdrawExpireUnfreezeSign, policy.ValidateTRONWithdrawExpireUnfreeze, tron.SignTRONWithdrawExpireUnfreeze),
		newOperation(routes.TRONVoteWitnessSign, policy.ValidateTRONVoteWitness, tron.SignTRONVoteWitness),
		newOperation(routes.TRONWithdrawBalanceSign, policy.ValidateTRONWithdrawBalance, tron.SignTRONWithdrawBalance),
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

func newOperation[T any, R any](
	route string,
	validate func(domain.Key, *T) error,
	execute func(context.Context, custody.Material, *T) (*R, error),
) OperationDescriptor {
	return OperationDescriptor{
		Route: route,
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
