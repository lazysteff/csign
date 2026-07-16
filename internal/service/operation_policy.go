package service

import (
	"context"
	"errors"

	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/repository"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

func (s *SigningService) resolveOperationDescriptor(ctx context.Context, route string) (OperationDescriptor, error) {
	descriptor, err := s.registry.Lookup(route)
	if err == nil && s.catalog != nil && descriptor.Route == route && s.catalog.ValidateBinding(descriptor.Route, descriptor.Operation) == nil {
		return descriptor, nil
	}
	s.emitInvalidDescriptor(ctx, route)
	return OperationDescriptor{}, signingOperationDenied("signing route does not have a registered operation")
}

func (s *SigningService) emitInvalidDescriptor(ctx context.Context, route string) {
	capability := v1.SigningOperationCapability{}
	if s.catalog != nil {
		if operation, ok := s.catalog.OperationForRoute(route); ok {
			capability = v1.SigningOperationCapability{Route: route, Operation: operation}
		}
	}
	emitSigningDenial(ctx, s.audit, SigningDenialEvent{
		SigningOperationCapability: capability,
		Category:                   SigningDenialInvalidDescriptor,
	})
}

func signingOperationDenied(message string) error {
	return faults.NewCode(faults.PolicyDenied, faults.SigningOperationNotAllowed, message)
}

func (s *SigningService) loadSigningKey(ctx context.Context, keyID string, descriptor OperationDescriptor) (*domain.Key, error) {
	key, err := s.keys.GetKey(ctx, keyID)
	if errors.Is(err, repository.ErrInvalidPolicyRecord) {
		emitSigningDenial(ctx, s.audit, signingDenial(keyID, descriptor, SigningDenialInvalidPolicyRecord))
		return nil, signingOperationDenied("stored signing operation policy is invalid")
	}
	if err != nil && !isRepositoryKeyNotFound(err) {
		return nil, err
	}
	if err == nil && key != nil {
		return key, nil
	}
	emitSigningDenial(ctx, s.audit, signingDenial(keyID, descriptor, SigningDenialKeyNotFound))
	return nil, faults.Newf(faults.NotFound, "key %q was not found", keyID)
}

func (s *SigningService) authorizeSigningOperation(ctx context.Context, keyID string, descriptor OperationDescriptor, keyPolicy v1.Policy) error {
	allowed := keyPolicy.AllowedSigningOperations
	if len(allowed) == 0 {
		emitSigningDenial(ctx, s.audit, signingDenial(keyID, descriptor, SigningDenialMissingAllowlist))
		return signingOperationDenied("signing operation is not explicitly allowed")
	}
	if err := s.catalog.ValidateAllowlist(allowed); err != nil {
		emitSigningDenial(ctx, s.audit, signingDenial(keyID, descriptor, SigningDenialInvalidPolicyRecord))
		return signingOperationDenied("stored signing operation policy is invalid")
	}
	if !s.catalog.Allows(allowed, descriptor.Operation) {
		emitSigningDenial(ctx, s.audit, signingDenial(keyID, descriptor, SigningDenialOperationMismatch))
		return signingOperationDenied("signing operation is not allowed")
	}
	return nil
}

func signingDenial(keyID string, descriptor OperationDescriptor, category SigningDenialCategory) SigningDenialEvent {
	return SigningDenialEvent{
		SigningOperationCapability: descriptor.SigningOperationCapability,
		KeyID:                      keyID,
		Category:                   category,
	}
}
