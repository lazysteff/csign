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
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestSigningServiceOrchestratesValidationAndExecution(t *testing.T) {
	var validated, executed, custodyUsed bool

	registry, err := NewRegistry([]OperationDescriptor{
		{
			Route: "test/route",
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
			Execute: func(_ context.Context, _ custody.Material, request any) (*v1.SignResponse, error) {
				executed = true
				typed := request.(*v1.EVMLegacyTransferSignRequest)
				return &v1.SignResponse{KeyID: typed.KeyID}, nil
			},
		},
	})
	require.NoError(t, err)

	service := NewSigningService(
		fakeKeyLookup{key: &domain.Key{ID: "key-1", CustodyMode: v1.CustodyModeMVP}},
		policy.DefaultEvaluator{},
		fakeCustodyResolver{fn: func(context.Context, domain.Key) (custody.Material, error) {
			custodyUsed = true
			return fakeMaterial{}, nil
		}},
		registry,
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

	registry, err := NewRegistry([]OperationDescriptor{
		{
			Route:      "test/route",
			NewRequest: func() any { return &v1.EVMLegacyTransferSignRequest{} },
			Validate: func(domain.Key, any) error {
				return faults.New(faults.PolicyDenied, "denied")
			},
			Execute: func(context.Context, custody.Material, any) (*v1.SignResponse, error) {
				return &v1.SignResponse{}, nil
			},
		},
	})
	require.NoError(t, err)

	service := NewSigningService(
		fakeKeyLookup{key: &domain.Key{ID: "key-1"}},
		policy.DefaultEvaluator{},
		fakeCustodyResolver{fn: func(context.Context, domain.Key) (custody.Material, error) {
			custodyUsed = true
			return fakeMaterial{}, nil
		}},
		registry,
	)

	_, err = service.Sign(context.Background(), "test/route", &v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{KeyID: "key-1"},
	})
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.False(t, custodyUsed)
}

func TestSigningServiceWrapsCustodyFailures(t *testing.T) {
	registry, err := NewRegistry([]OperationDescriptor{
		{
			Route:      "test/route",
			NewRequest: func() any { return &v1.EVMLegacyTransferSignRequest{} },
			Validate:   func(domain.Key, any) error { return nil },
			Execute: func(context.Context, custody.Material, any) (*v1.SignResponse, error) {
				return &v1.SignResponse{}, nil
			},
		},
	})
	require.NoError(t, err)

	service := NewSigningService(
		fakeKeyLookup{key: &domain.Key{ID: "key-1"}},
		policy.DefaultEvaluator{},
		fakeCustodyResolver{fn: func(context.Context, domain.Key) (custody.Material, error) {
			return nil, errors.New("hsm offline")
		}},
		registry,
	)

	_, err = service.Sign(context.Background(), "test/route", &v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{KeyID: "key-1"},
	})
	require.Equal(t, faults.CustodyFailed, faults.KindOf(err))
}

type fakeKeyLookup struct {
	key *domain.Key
	err error
}

func (f fakeKeyLookup) GetKey(_ context.Context, _ string) (*domain.Key, error) {
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
