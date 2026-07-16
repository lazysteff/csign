package service

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/policy"
	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestSigningServiceOrchestratesValidationAndExecution(t *testing.T) {
	var validated, executed, custodyUsed bool

	_, registry := testOperationRegistry(t, []OperationDescriptor{
		{
			SigningOperationCapability: v1.SigningOperationCapability{Route: "test/route"},
			NewRequest: func() any {
				return &v1.EVMLegacyTransferSignRequest{}
			},
			Validate: func(key domain.Key, request any) error {
				validated = true
				require.Equal(t, "key-1", key.ID)
				typed, ok := request.(*v1.EVMLegacyTransferSignRequest)
				require.True(t, ok)
				require.Equal(t, "key-1", typed.KeyID)
				return nil
			},
			Execute: func(_ context.Context, _ custody.Material, request any) (any, error) {
				executed = true
				typed := request.(*v1.EVMLegacyTransferSignRequest)
				return &v1.SignResponse{KeyID: typed.KeyID}, nil
			},
		},
	})
	service := NewSigningService(
		&fakeKeyLookup{key: allowedTestKey()},
		policy.DefaultEvaluator{},
		fakeCustodyResolver{fn: func(context.Context, domain.Key) (custody.Material, error) {
			custodyUsed = true
			return fakeMaterial{}, nil
		}},
		registry,
		nil,
	)

	result, err := service.Sign(context.Background(), "test/route", &v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{KeyID: "key-1"},
	})
	require.NoError(t, err)
	require.True(t, validated)
	require.True(t, executed)
	require.True(t, custodyUsed)
	require.Equal(t, "key-1", result.KeyID)
}

func TestSigningServiceStopsOnPolicyDenial(t *testing.T) {
	var custodyUsed bool

	_, registry := testOperationRegistry(t, []OperationDescriptor{
		{
			SigningOperationCapability: v1.SigningOperationCapability{Route: "test/route"},
			NewRequest:                 func() any { return &v1.EVMLegacyTransferSignRequest{} },
			Validate: func(domain.Key, any) error {
				return faults.New(faults.PolicyDenied, "denied")
			},
			Execute: func(context.Context, custody.Material, any) (any, error) {
				return &v1.SignResponse{}, nil
			},
		},
	})
	service := NewSigningService(
		&fakeKeyLookup{key: allowedTestKey()},
		policy.DefaultEvaluator{},
		fakeCustodyResolver{fn: func(context.Context, domain.Key) (custody.Material, error) {
			custodyUsed = true
			return fakeMaterial{}, nil
		}},
		registry,
		nil,
	)

	_, err := service.Sign(context.Background(), "test/route", &v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{KeyID: "key-1"},
	})
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.False(t, custodyUsed)
}

func TestSigningServiceWrapsCustodyFailures(t *testing.T) {
	_, registry := testOperationRegistry(t, []OperationDescriptor{
		{
			SigningOperationCapability: v1.SigningOperationCapability{Route: "test/route"},
			NewRequest:                 func() any { return &v1.EVMLegacyTransferSignRequest{} },
			Validate:                   func(domain.Key, any) error { return nil },
			Execute: func(context.Context, custody.Material, any) (any, error) {
				return &v1.SignResponse{}, nil
			},
		},
	})
	service := NewSigningService(
		&fakeKeyLookup{key: allowedTestKey()},
		policy.DefaultEvaluator{},
		fakeCustodyResolver{fn: func(context.Context, domain.Key) (custody.Material, error) {
			return nil, errors.New("hsm offline")
		}},
		registry,
		nil,
	)

	_, err := service.Sign(context.Background(), "test/route", &v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{KeyID: "key-1"},
	})
	require.Equal(t, faults.CustodyFailed, faults.KindOf(err))
	require.EqualError(t, err, "custody backend unavailable")
	require.NotContains(t, err.Error(), "hsm offline")
}

func TestStructuredEVMExecutionErrorsAreSanitizedAndClassified(t *testing.T) {
	custodyError := classifyStructuredEVMExecutionError(errors.New("sign digest: secret HSM detail"))
	require.Equal(t, faults.CustodyFailed, faults.KindOf(custodyError))
	require.EqualError(t, custodyError, "custody signing failed")
	require.NotContains(t, custodyError.Error(), "secret HSM detail")

	verificationError := classifyStructuredEVMExecutionError(errors.New("recovered signer mismatch"))
	require.Equal(t, faults.SignatureVerificationFailed, faults.CodeOf(verificationError))
	require.EqualError(t, verificationError, "signed artifact verification failed")
}

func TestSigningServiceRejectsInvalidKeyIDsBeforeLookup(t *testing.T) {
	_, registry := testOperationRegistry(t, []OperationDescriptor{
		{
			SigningOperationCapability: v1.SigningOperationCapability{Route: "test/route"},
			NewRequest:                 func() any { return &v1.EVMLegacyTransferSignRequest{} },
			Validate:                   func(domain.Key, any) error { return nil },
			Execute: func(context.Context, custody.Material, any) (any, error) {
				return &v1.SignResponse{}, nil
			},
		},
	})
	keys := &fakeKeyLookup{key: &domain.Key{ID: "key-1"}}
	audit := &recordingAudit{}
	service := NewSigningService(
		keys,
		policy.DefaultEvaluator{},
		fakeCustodyResolver{fn: func(context.Context, domain.Key) (custody.Material, error) {
			return fakeMaterial{}, nil
		}},
		registry,
		audit,
	)

	_, err := service.Sign(context.Background(), "test/route", &v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{KeyID: "a//b"},
	})
	require.Equal(t, faults.Invalid, faults.KindOf(err))
	require.Zero(t, keys.calls)
	require.Empty(t, audit.events, "an unvalidated key identifier must not be audited")
}

func TestSigningServiceRejectsTypedNilRequestBeforeLookup(t *testing.T) {
	_, registry := testOperationRegistry(t, []OperationDescriptor{
		{
			SigningOperationCapability: v1.SigningOperationCapability{Route: "test/route"},
			NewRequest:                 func() any { return &v1.EVMLegacyTransferSignRequest{} },
			Validate:                   func(domain.Key, any) error { return nil },
			Execute:                    func(context.Context, custody.Material, any) (any, error) { return &v1.SignResponse{}, nil },
		},
	})
	keys := &fakeKeyLookup{}
	service := NewSigningService(keys, policy.DefaultEvaluator{}, fakeCustodyResolver{}, registry, nil)
	var request *v1.EVMLegacyTransferSignRequest
	_, err := service.Sign(context.Background(), "test/route", request)
	require.Equal(t, faults.Internal, faults.KindOf(err))
	require.ErrorContains(t, err, "request is required")
	require.Zero(t, keys.calls)
}

type fakeKeyLookup struct {
	key   *domain.Key
	err   error
	calls int
}

func testOperationRegistry(t *testing.T, descriptors []OperationDescriptor) (*signingops.Catalog, *Registry) {
	t.Helper()
	entries := make([]v1.SigningOperationCapability, 0, len(descriptors))
	for index := range descriptors {
		descriptors[index].Operation = "test_operation"
		entries = append(entries, descriptors[index].SigningOperationCapability)
	}
	catalog, err := signingops.New(entries)
	require.NoError(t, err)
	registry, err := NewRegistry(catalog, descriptors)
	require.NoError(t, err)
	return catalog, registry
}

func allowedTestKey() *domain.Key {
	return &domain.Key{
		ID: "key-1", CustodyMode: v1.CustodyModeMVP,
		Policy: v1.Policy{AllowedSigningOperations: []string{"test_operation"}},
	}
}

func (f *fakeKeyLookup) GetKey(_ context.Context, _ string) (*domain.Key, error) {
	f.calls++
	return f.key, f.err
}

type fakeCustodyResolver struct {
	fn func(context.Context, domain.Key) (custody.Material, error)
}

func (f fakeCustodyResolver) MaterialForKey(ctx context.Context, key domain.Key) (custody.Material, error) {
	return f.fn(ctx, key)
}

type fakeMaterial struct{}

func (fakeMaterial) PublicKey() *ecdsa.PublicKey                        { return nil }
func (fakeMaterial) SignDigest(context.Context, []byte) ([]byte, error) { return nil, nil }
