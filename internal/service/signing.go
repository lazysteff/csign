package service

import (
	"context"
	"reflect"

	"github.com/chain-signer/chain-signer/internal/chain"
	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/keyid"
	"github.com/chain-signer/chain-signer/internal/policy"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

type KeyLookup interface {
	GetKey(context.Context, string) (*domain.Key, error)
}

type CustodyResolver interface {
	MaterialForKey(context.Context, domain.Key) (custody.Material, error)
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
	result, err := s.Execute(ctx, route, request)
	if err != nil {
		return nil, err
	}
	typed, ok := result.(*v1.SignResponse)
	if !ok {
		return nil, faults.Newf(faults.Internal, "operation %q did not return a legacy sign response", route)
	}
	return typed, nil
}

func (s *SigningService) Execute(ctx context.Context, route string, request any) (any, error) {
	descriptor, err := s.registry.Lookup(route)
	if err != nil {
		return nil, err
	}
	keyID, err := keyIDFromRequest(request)
	if err != nil {
		return nil, err
	}
	if err := keyid.Validate(keyID); err != nil {
		return nil, err
	}
	key, err := s.keys.GetKey(ctx, keyID)
	if err != nil {
		if isRepositoryKeyNotFound(err) {
			return nil, faults.Newf(faults.NotFound, "key %q was not found", keyID)
		}
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
		return nil, faults.New(faults.CustodyFailed, "custody backend unavailable")
	}
	if material == nil {
		return nil, faults.New(faults.CustodyFailed, "custody backend returned no signing material")
	}
	if key.SignerAddress != "" {
		material, err = custody.Snapshot(material)
		if err != nil {
			return nil, faults.New(faults.CustodyFailed, "custody backend returned an invalid public key")
		}
		materialAddress, err := chain.DeriveSignerAddress(key.ChainFamily, material.PublicKey())
		if err != nil {
			return nil, faults.New(faults.CustodyFailed, "custody backend returned an invalid public key")
		}
		if !chain.EqualAddress(key.ChainFamily, materialAddress, key.SignerAddress) {
			return nil, faults.New(faults.CustodyFailed, "custody public key does not match stored key metadata")
		}
	}
	result, err := descriptor.Execute(ctx, material, request)
	if err != nil {
		if isAdvancedSignRoute(route) {
			return nil, classifyAdvancedExecutionError(err)
		}
		return nil, faults.Wrap(faults.Invalid, err)
	}
	return result, nil
}

func keyIDFromRequest(request any) (string, error) {
	type keyIDCarrier interface {
		GetKeyID() string
	}
	if request == nil || isNilValue(request) {
		return "", faults.New(faults.Internal, "request is required")
	}
	typed, ok := request.(keyIDCarrier)
	if !ok {
		return "", faults.New(faults.Internal, "request does not contain key_id")
	}
	return typed.GetKeyID(), nil
}

func isNilValue(value any) bool {
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
