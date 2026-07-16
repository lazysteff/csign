package service

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/policy"
	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestSigningOperationGateCoversEveryCatalogRoute(t *testing.T) {
	catalog := signingops.Default()
	entries := catalog.Entries()
	for index, entry := range entries {
		t.Run(entry.Operation, func(t *testing.T) {
			additional := entries[(index+1)%len(entries)].Operation
			cases := []struct {
				name    string
				allowed []string
				permit  bool
			}{
				{name: "exact singleton", allowed: []string{entry.Operation}, permit: true},
				{name: "matching with additional operation", allowed: []string{entry.Operation, additional}, permit: true},
				{name: "nil deny all", allowed: nil},
				{name: "empty deny all", allowed: []string{}},
				{name: "different operation", allowed: []string{additional}},
			}
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					validated := false
					executed := false
					custodyCalls := 0
					registry := staticOperationRegistry{catalog: catalog, descriptor: genericDescriptor(entry, &validated, &executed)}
					key := &domain.Key{ID: "key-1", Policy: v1.Policy{AllowedSigningOperations: test.allowed}}
					service := NewSigningService(
						&fakeKeyLookup{key: key}, policy.DefaultEvaluator{},
						fakeCustodyResolver{fn: func(context.Context, domain.Key) (custody.Material, error) {
							custodyCalls++
							return fakeMaterial{}, nil
						}},
						registry, nil,
					)

					result, err := service.Execute(context.Background(), entry.Route, v1.BaseSignRequest{KeyID: "key-1"})
					if test.permit {
						require.NoError(t, err)
						require.Equal(t, "ok", result)
						require.True(t, validated)
						require.True(t, executed)
						require.Equal(t, 1, custodyCalls)
						return
					}
					require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
					require.Equal(t, faults.SigningOperationNotAllowed, faults.CodeOf(err))
					require.False(t, validated)
					require.False(t, executed)
					require.Zero(t, custodyCalls)
				})
			}
		})
	}
}

func TestSigningOperationGateDeniesWithoutCustody(t *testing.T) {
	catalog := signingops.Default()
	entry := catalog.Entries()[0]
	other := catalog.Entries()[1].Operation
	tests := []struct {
		name     string
		allowed  []string
		category SigningDenialCategory
	}{
		{name: "nil allowlist", allowed: nil, category: SigningDenialMissingAllowlist},
		{name: "empty allowlist", allowed: []string{}, category: SigningDenialMissingAllowlist},
		{name: "operation mismatch", allowed: []string{other}, category: SigningDenialOperationMismatch},
		{name: "unknown alongside match", allowed: []string{entry.Operation, "unknown"}, category: SigningDenialInvalidPolicyRecord},
		{name: "duplicate alongside match", allowed: []string{entry.Operation, entry.Operation}, category: SigningDenialInvalidPolicyRecord},
		{name: "non canonical alongside match", allowed: []string{entry.Operation, "EVM_TRANSFER_LEGACY"}, category: SigningDenialInvalidPolicyRecord},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validated := false
			executed := false
			custodyCalls := 0
			audit := &recordingAudit{}
			registry := staticOperationRegistry{catalog: catalog, descriptor: genericDescriptor(entry, &validated, &executed)}
			keys := &fakeKeyLookup{key: &domain.Key{ID: "key-1", Policy: v1.Policy{AllowedSigningOperations: test.allowed}}}
			service := NewSigningService(
				keys, policy.DefaultEvaluator{},
				fakeCustodyResolver{fn: func(context.Context, domain.Key) (custody.Material, error) {
					custodyCalls++
					return fakeMaterial{}, nil
				}},
				registry, audit,
			)

			_, err := service.Execute(context.Background(), entry.Route, v1.BaseSignRequest{KeyID: "key-1"})
			require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
			require.Equal(t, faults.SigningOperationNotAllowed, faults.CodeOf(err))
			require.Equal(t, 1, keys.calls)
			require.Zero(t, custodyCalls)
			require.False(t, validated)
			require.False(t, executed)
			require.Equal(t, []SigningDenialEvent{operationDenial(entry, "key-1", test.category)}, audit.events)
		})
	}
}
