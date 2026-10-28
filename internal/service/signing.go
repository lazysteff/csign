package service

import (
	"bytes"
	"context"

	"github.com/chain-signer/chain-signer/internal/chain"
	"github.com/chain-signer/chain-signer/internal/cryptography"
	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/keyid"
	"github.com/chain-signer/chain-signer/internal/policy"
	"github.com/chain-signer/chain-signer/internal/routes"
	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

type KeyLookup interface {
	GetKey(context.Context, string) (*domain.Key, error)
}

type CustodyResolver interface {
	DescribeCapabilities(context.Context, domain.Key) ([]cryptography.Capability, error)
	ResolveSigningMaterial(context.Context, domain.Key) (custody.SigningMaterial, error)
}

type SigningService struct {
	keys     KeyLookup
	policies policy.Evaluator
	custody  CustodyResolver
	registry OperationRegistry
	catalog  *signingops.Catalog
	audit    SigningAuditSink
	schemes  *cryptography.Registry
}

func NewSigningService(keys KeyLookup, policies policy.Evaluator, custodyResolver CustodyResolver, registry OperationRegistry, audit SigningAuditSink) *SigningService {
	schemes := cryptography.Default()
	if provider, ok := registry.(interface{ Cryptography() *cryptography.Registry }); ok {
		schemes = provider.Cryptography()
	}
	return &SigningService{
		keys:     keys,
		policies: policies,
		custody:  custodyResolver,
		registry: registry,
		catalog:  registry.Catalog(),
		audit:    audit,
		schemes:  schemes,
	}
}

func (s *SigningService) Routes() []string {
	return s.registry.Routes()
}

func (s *SigningService) NewRequest(ctx context.Context, route string) (any, error) {
	descriptor, err := s.resolveOperationDescriptor(ctx, route)
	if err != nil {
		return nil, err
	}
	request, err := newOperationRequest(descriptor)
	if err != nil {
		s.emitInvalidDescriptor(ctx, route)
		return nil, signingOperationDenied("signing route has an invalid request factory")
	}
	return request, nil
}

func (s *SigningService) Sign(ctx context.Context, route string, request any) (*v1.SignResponse, error) {
	result, err := s.Execute(ctx, route, request)
	if err != nil {
		return nil, err
	}
	typed, ok := result.(*v1.SignResponse)
	if !ok {
		return nil, faults.Newf(faults.Internal, "operation %q did not return a transaction sign response", route)
	}
	return typed, nil
}

func (s *SigningService) Execute(ctx context.Context, route string, request any) (any, error) {
	descriptor, err := s.resolveOperationDescriptor(ctx, route)
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
	key, err := s.loadSigningKey(ctx, keyID, descriptor)
	if err != nil {
		return nil, err
	}
	keySnapshot := key.Clone()
	key = &keySnapshot
	if err := s.authorizeSigningOperation(ctx, keyID, descriptor, key.Policy); err != nil {
		return nil, err
	}
	if !key.Active {
		return nil, faults.Newf(faults.PolicyDenied, "key %q is disabled", key.ID)
	}
	policyKey := key.Clone()
	if policyKey.ChainFamily == "" && descriptor.Protocol != "" {
		policyKey.ChainFamily = descriptor.Protocol
		rawPublic, err := enc.DecodeHex(key.PublicKeyHex)
		if err != nil {
			return nil, faults.New(faults.CustodyFailed, "invalid managed public key")
		}
		pub, err := s.schemes.PublicKey(key.KeyType, rawPublic)
		if err != nil {
			return nil, faults.New(faults.CustodyFailed, "invalid managed public key")
		}
		policyKey.SignerAddress, err = chain.DerivePublicIdentity(descriptor.Protocol, pub)
		if err != nil {
			return nil, faults.New(faults.PolicyDenied, "incompatible protocol identity")
		}
	}
	if err := s.policies.Validate(policyKey, request, descriptor.Validate); err != nil {
		return nil, err
	}
	normalized, err := descriptor.Normalize(request)
	if err != nil {
		return nil, faults.Wrap(faults.Invalid, err)
	}
	if descriptor.Protocol != "" && key.ChainFamily != "" && key.ChainFamily != descriptor.Protocol {
		return nil, faults.New(faults.PolicyDenied, "key protocol binding denies operation")
	}
	capabilities, err := s.custody.DescribeCapabilities(ctx, *key)
	if err != nil {
		return nil, faults.New(faults.CustodyFailed, "custody backend unavailable")
	}
	capability, err := s.schemes.Resolve(descriptor.CompatibleSchemes, key.KeyType, capabilities)
	if err != nil {
		return nil, faults.New(faults.PolicyDenied, "no unique executable signing scheme")
	}
	rawPublic, err := enc.DecodeHex(key.PublicKeyHex)
	if err != nil {
		return nil, faults.New(faults.CustodyFailed, "invalid managed public key")
	}
	pub, err := s.schemes.PublicKey(key.KeyType, rawPublic)
	if err != nil {
		return nil, faults.New(faults.CustodyFailed, "invalid managed public key")
	}
	prepared, err := descriptor.Prepare(ctx, capability, pub.Clone(), normalized)
	if err != nil {
		return nil, s.executionError(route, err)
	}
	if prepared == nil || prepared.Format == nil || prepared.Payload.Kind() != capability.Input {
		return nil, faults.New(faults.PolicyDenied, "operation prepared an incompatible signing payload")
	}
	payload := cryptography.NewPayload(prepared.Payload.Kind(), prepared.Payload.Bytes())
	material, err := s.custody.ResolveSigningMaterial(ctx, *key)
	if err != nil || material == nil || isNilValue(material) {
		return nil, faults.New(faults.CustodyFailed, "custody backend unavailable")
	}
	actual, err := material.CanonicalPublicKey()
	if err != nil || actual.Type != pub.Type || !bytes.Equal(actual.Bytes, pub.Bytes) {
		return nil, faults.New(faults.CustodyFailed, "custody public key does not match stored key metadata")
	}
	if key.SignerAddress != "" {
		identity, err := chain.DerivePublicIdentity(key.ChainFamily, pub)
		if err != nil || !chain.EqualAddress(key.ChainFamily, identity, key.SignerAddress) {
			return nil, faults.New(faults.CustodyFailed, "custody public key does not match stored key metadata")
		}
	}
	raw, err := material.Sign(ctx, capability, payload)
	if err != nil {
		return nil, faults.New(faults.CustodyFailed, "custody signing failed")
	}
	signature, err := s.schemes.Verify(capability, pub, payload, raw)
	if err != nil {
		if route != routes.SolanaMessageSign {
			return nil, s.executionError(route, err)
		}
		return nil, faults.NewCode(faults.Invalid, faults.SignatureVerificationFailed, "signed artifact verification failed")
	}
	result, err := prepared.Format(signature)
	if err != nil {
		return nil, s.executionError(route, err)
	}
	return result, nil
}
func (s *SigningService) executionError(route string, err error) error {
	if isStructuredEVMSignRoute(route) {
		return classifyStructuredEVMExecutionError(err)
	}
	return faults.Wrap(faults.Invalid, err)
}
