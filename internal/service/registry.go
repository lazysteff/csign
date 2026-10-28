package service

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"slices"
	"strings"

	"github.com/chain-signer/chain-signer/internal/chain/evm"
	"github.com/chain-signer/chain-signer/internal/chain/solana"
	"github.com/chain-signer/chain-signer/internal/chain/tron"
	"github.com/chain-signer/chain-signer/internal/cryptography"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/policy"
	"github.com/chain-signer/chain-signer/internal/routes"
	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

type OperationPreparation func(context.Context, cryptography.Capability, cryptography.PublicKey, any) (*cryptography.Prepared, error)

type OperationDescriptor struct {
	v1.SigningOperationCapability
	NewRequest        func() any
	Validate          policy.Validator
	Normalize         func(any) (any, error)
	CompatibleSchemes []cryptography.Capability
	Protocol          string
	SecurityModel     string
	Prepare           OperationPreparation
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
	schemes *cryptography.Registry
}

func NewRegistry(catalog *signingops.Catalog, descriptors []OperationDescriptor) (*Registry, error) {
	return NewRegistryWithSchemes(catalog, descriptors, cryptography.Default())
}
func NewRegistryWithSchemes(catalog *signingops.Catalog, descriptors []OperationDescriptor, schemes *cryptography.Registry) (*Registry, error) {
	if catalog == nil || schemes == nil {
		return nil, faults.New(faults.Internal, "signing operation catalog is required")
	}
	out := &Registry{
		catalog: catalog,
		schemes: schemes,
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
		if descriptor.NewRequest == nil || descriptor.Validate == nil || descriptor.Normalize == nil || descriptor.Prepare == nil || len(descriptor.CompatibleSchemes) == 0 {
			return nil, faults.Newf(faults.Internal, "operation %q is missing required callbacks", descriptor.Route)
		}
		if _, err := newOperationRequest(descriptor); err != nil {
			return nil, faults.Newf(faults.Internal, "operation %q has an invalid request factory: %v", descriptor.Route, err)
		}
		if _, exists := out.byRoute[descriptor.Route]; exists {
			return nil, faults.Newf(faults.Internal, "duplicate operation route %q", descriptor.Route)
		}
		descriptor.CompatibleSchemes = append([]cryptography.Capability(nil), descriptor.CompatibleSchemes...)
		for _, binding := range descriptor.CompatibleSchemes {
			scheme, ok := schemes.Scheme(binding.Scheme)
			if !ok {
				return nil, faults.New(faults.Internal, "operation references an unknown scheme")
			}
			supported := false
			for _, input := range scheme.Inputs {
				if input == binding.Input {
					supported = true
				}
			}
			if !supported {
				return nil, faults.New(faults.Internal, "operation references unsupported scheme input")
			}
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
		newOperation(catalog, routes.EVMLegacyTransferSign, policy.ValidateEVMLegacyTransfer, evm.PrepareLegacyTransfer),
		newOperation(catalog, routes.EVMEIP1559TransferSign, policy.ValidateEVMEIP1559Transfer, evm.PrepareEIP1559Transfer),
		newOperation(catalog, routes.EVMContractCallSign, policy.ValidateEVMContractCall, evm.PrepareContractCall),
		newOperation(catalog, routes.EVMEIP712Sign, policy.ValidateEVMEIP712, evm.PrepareEIP712),
		newOperation(catalog, routes.EVMERC4337UserOperationSign, policy.ValidateEVMUserOperation, evm.PrepareUserOperation),
		newOperation(catalog, routes.EVMEIP7702AuthorizationSign, policy.ValidateEVMEIP7702Authorization, evm.PrepareEIP7702Authorization),
		newOperation(catalog, routes.EVMEIP7702TransactionSign, policy.ValidateEVMEIP7702Transaction, evm.PrepareEIP7702Transaction),
		newOperation(catalog, routes.TRXTransferSign, policy.ValidateTRXTransfer, tron.PrepareTRXTransfer),
		newOperation(catalog, routes.TRC20TransferSign, policy.ValidateTRC20Transfer, tron.PrepareTRC20Transfer),
		newOperation(catalog, routes.TRONFreezeBalanceV2Sign, policy.ValidateTRONFreezeBalanceV2, tron.PrepareTRONFreezeBalanceV2),
		newOperation(catalog, routes.TRONUnfreezeBalanceV2Sign, policy.ValidateTRONUnfreezeBalanceV2, tron.PrepareTRONUnfreezeBalanceV2),
		newOperation(catalog, routes.TRONDelegateResourceSign, policy.ValidateTRONDelegateResource, tron.PrepareTRONDelegateResource),
		newOperation(catalog, routes.TRONUndelegateResourceSign, policy.ValidateTRONUndelegateResource, tron.PrepareTRONUndelegateResource),
		newOperation(catalog, routes.TRONWithdrawExpireUnfreezeSign, policy.ValidateTRONWithdrawExpireUnfreeze, tron.PrepareTRONWithdrawExpireUnfreeze),
		newOperation(catalog, routes.TRONVoteWitnessSign, policy.ValidateTRONVoteWitness, tron.PrepareTRONVoteWitness),
		newOperation(catalog, routes.TRONWithdrawBalanceSign, policy.ValidateTRONWithdrawBalance, tron.PrepareTRONWithdrawBalance),
		solanaOperation(),
	}
}

func (r *Registry) Lookup(route string) (OperationDescriptor, error) {
	descriptor, ok := r.byRoute[route]
	if !ok {
		return OperationDescriptor{}, faults.Newf(faults.Unsupported, "unsupported route %q", route)
	}
	descriptor.CompatibleSchemes = append([]cryptography.Capability(nil), descriptor.CompatibleSchemes...)
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

func newOperation[T any](
	catalog *signingops.Catalog,
	route string,
	validate func(domain.Key, *T) error,
	prepare func(*ecdsa.PublicKey, *T) (*cryptography.Prepared, error),
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
		Protocol: protocolForRoute(route), SecurityModel: "typed_semantic",
		CompatibleSchemes: []cryptography.Capability{{Scheme: cryptography.ECDSASecp256k1, Input: cryptography.Digest}},
		Normalize: func(request any) (any, error) {
			typed, ok := request.(*T)
			if !ok {
				return nil, faults.New(faults.Internal, "unexpected request type")
			}
			encoded, err := json.Marshal(typed)
			if err != nil {
				return nil, err
			}
			var frozen T
			if err = json.Unmarshal(encoded, &frozen); err != nil {
				return nil, err
			}
			return &frozen, nil
		},
		Prepare: func(ctx context.Context, capability cryptography.Capability, pub cryptography.PublicKey, request any) (*cryptography.Prepared, error) {
			typed, ok := request.(*T)
			if !ok {
				return nil, faults.New(faults.Internal, "unexpected normalized request type")
			}
			p, err := cryptography.ECDSAPublicKey(pub)
			if err != nil {
				return nil, err
			}
			return prepare(p, typed)
		},
	}
}
func protocolForRoute(route string) string {
	if strings.HasPrefix(route, "v1/evm/") {
		return v1.ChainFamilyEVM
	}
	return v1.ChainFamilyTRON
}

func solanaOperation() OperationDescriptor {
	return OperationDescriptor{
		SigningOperationCapability: v1.SigningOperationCapability{Route: routes.SolanaMessageSign, Operation: v1.OperationSolanaMessage},
		Protocol:                   v1.ChainFamilySolana, SecurityModel: "opaque",
		CompatibleSchemes: []cryptography.Capability{{Scheme: cryptography.Ed25519Scheme, Input: cryptography.Message}},
		NewRequest:        func() any { return &v1.SolanaMessageSignRequest{} }, Validate: policy.ValidateSolanaMessage,
		Normalize: func(request any) (any, error) {
			req, ok := request.(*v1.SolanaMessageSignRequest)
			if !ok {
				return nil, faults.New(faults.Invalid, "invalid Solana message request")
			}
			return solana.Normalize(req)
		},
		Prepare: func(_ context.Context, c cryptography.Capability, pub cryptography.PublicKey, input any) (*cryptography.Prepared, error) {
			normalized, ok := input.(solana.Input)
			if !ok {
				return nil, faults.New(faults.Internal, "invalid normalized Solana input")
			}
			return solana.Prepare(c, pub, normalized)
		},
	}
}

func (r *Registry) OperationDetails() []v1.SigningOperationDetail {
	details := make([]v1.SigningOperationDetail, 0, len(r.order))
	for _, d := range r.order {
		detail := v1.SigningOperationDetail{Route: d.Route, Operation: d.Operation, SecurityModel: d.SecurityModel}
		for _, c := range d.CompatibleSchemes {
			if !slices.Contains(detail.SigningSchemes, string(c.Scheme)) {
				detail.SigningSchemes = append(detail.SigningSchemes, string(c.Scheme))
			}
			s, ok := r.schemes.Scheme(c.Scheme)
			if ok {
				for _, kt := range s.KeyTypes {
					if !slices.Contains(detail.CompatibleKeyTypes, string(kt)) {
						detail.CompatibleKeyTypes = append(detail.CompatibleKeyTypes, string(kt))
					}
				}
			}
		}
		detail.SignatureEncodings = []string{"hex"}
		switch d.Protocol {
		case v1.ChainFamilyEVM:
			detail.SignatureEncodings = []string{"rsv-v27"}
			switch d.Operation {
			case v1.OperationEVMEIP7702Authorization:
				detail.SignatureEncodings = []string{"authorization-y-parity-r-s"}
			case v1.OperationEVMEIP7702Transaction, v1.OperationEVMTransferLegacy, v1.OperationEVMTransferEIP1559, v1.OperationEVMContractEIP1559:
				detail.SignatureEncodings = []string{"transaction-r-s-v"}
			}
		case v1.ChainFamilyTRON:
			detail.SignatureEncodings = []string{"recoverable-rsv"}
		}
		details = append(details, detail)
	}
	return details
}

func (r *Registry) Cryptography() *cryptography.Registry { return r.schemes }
