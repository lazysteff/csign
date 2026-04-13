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
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

type KeyLookup interface {
	GetKey(context.Context, string) (*domain.Key, error)
}

type CustodyResolver interface {
	MaterialForKey(context.Context, domain.Key) (custody.Material, error)
}

type OperationExecutor func(context.Context, custody.Material, any) (*v1.SignResponse, error)

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

type SigningService struct {
	keys     KeyLookup
	policies policy.Evaluator
	custody  CustodyResolver
	registry OperationRegistry
}

func NewSigningService(keys KeyLookup, policies policy.Evaluator, custodyResolver CustodyResolver, registry OperationRegistry) *SigningService {
	return &SigningService{
		keys:     keys,
		policies: policies,
		custody:  custodyResolver,
		registry: registry,
	}
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
		newOperation(routes.TRXTransferSign, policy.ValidateTRXTransfer, tron.SignTRXTransfer),
		newOperation(routes.TRC20TransferSign, policy.ValidateTRC20Transfer, tron.SignTRC20Transfer),
		newOperation(routes.TRONFreezeBalanceV2Sign, policy.ValidateTRONFreezeBalanceV2, tron.SignTRONFreezeBalanceV2),
		newOperation(routes.TRONUnfreezeBalanceV2Sign, policy.ValidateTRONUnfreezeBalanceV2, tron.SignTRONUnfreezeBalanceV2),
		newOperation(routes.TRONDelegateResourceSign, policy.ValidateTRONDelegateResource, tron.SignTRONDelegateResource),
		newOperation(routes.TRONUndelegateResourceSign, policy.ValidateTRONUndelegateResource, tron.SignTRONUndelegateResource),
		newOperation(routes.TRONWithdrawExpireUnfreezeSign, policy.ValidateTRONWithdrawExpireUnfreeze, tron.SignTRONWithdrawExpireUnfreeze),
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

func (s *SigningService) Routes() []string {
	return s.registry.Routes()
}

func (s *SigningService) NewRequest(route string) (any, error) {
	descriptor, err := s.registry.Lookup(route)
	if err != nil {
		return nil, err
	}
	return descriptor.NewRequest(), nil
}

func (s *SigningService) Sign(ctx context.Context, route string, request any) (*v1.SignResponse, error) {
	descriptor, err := s.registry.Lookup(route)
	if err != nil {
		return nil, err
	}
	keyID, err := keyIDFromRequest(request)
	if err != nil {
		return nil, err
	}
	if keyID == "" {
		return nil, faults.New(faults.Invalid, "key_id is required")
	}
	key, err := s.keys.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, faults.Newf(faults.NotFound, "key %q was not found", keyID)
	}
	if err := s.policies.Validate(*key, request, descriptor.Validate); err != nil {
		return nil, err
	}
	material, err := s.custody.MaterialForKey(ctx, *key)
	if err != nil {
		return nil, faults.Wrap(faults.CustodyFailed, err)
	}
	result, err := descriptor.Execute(ctx, material, request)
	if err != nil {
		return nil, faults.Wrap(faults.Invalid, err)
	}
	return result, nil
}

func newOperation[T any](
	route string,
	validate func(domain.Key, *T) error,
	execute func(context.Context, custody.Material, *T) (*v1.SignResponse, error),
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
		Execute: func(ctx context.Context, material custody.Material, request any) (*v1.SignResponse, error) {
			typed, ok := request.(*T)
			if !ok {
				return nil, faults.Newf(faults.Internal, "unexpected request type for route %q", route)
			}
			return execute(ctx, material, typed)
		},
	}
}

func keyIDFromRequest(request any) (string, error) {
	type keyIDCarrier interface {
		GetKeyID() string
	}
	typed, ok := request.(keyIDCarrier)
	if !ok {
		return "", faults.New(faults.Internal, "request does not contain key_id")
	}
	return typed.GetKeyID(), nil
}
