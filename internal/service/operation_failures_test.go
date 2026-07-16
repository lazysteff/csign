package service

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/policy"
	"github.com/chain-signer/chain-signer/internal/repository"
	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestSigningOperationGateRejectsInvalidDescriptorBeforeKeyLookup(t *testing.T) {
	catalog := signingops.Default()
	entry := catalog.Entries()[0]
	for _, operation := range []string{"", "unknown"} {
		t.Run(operation, func(t *testing.T) {
			descriptor := genericDescriptor(entry, new(bool), new(bool))
			descriptor.Operation = operation
			keys := &fakeKeyLookup{}
			audit := &recordingAudit{}
			service := NewSigningService(keys, policy.DefaultEvaluator{}, fakeCustodyResolver{}, staticOperationRegistry{catalog: catalog, descriptor: descriptor}, audit)

			_, err := service.Execute(context.Background(), entry.Route, v1.BaseSignRequest{KeyID: "unvalidated"})
			require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
			require.Equal(t, faults.SigningOperationNotAllowed, faults.CodeOf(err))
			require.Zero(t, keys.calls)
			require.Equal(t, []SigningDenialEvent{operationDenial(
				v1.SigningOperationCapability{Route: entry.Route}, "", SigningDenialInvalidRoute,
			)}, audit.events)
		})
	}
}

func TestSigningOperationGatePreservesMissingKeyResponse(t *testing.T) {
	catalog := signingops.Default()
	entry := catalog.Entries()[0]
	audit := &recordingAudit{}
	keys := &fakeKeyLookup{err: repository.ErrKeyNotFound}
	service := NewSigningService(keys, policy.DefaultEvaluator{}, fakeCustodyResolver{}, staticOperationRegistry{catalog: catalog, descriptor: genericDescriptor(entry, new(bool), new(bool))}, audit)

	_, err := service.Execute(context.Background(), entry.Route, v1.BaseSignRequest{KeyID: "missing"})
	require.Equal(t, faults.NotFound, faults.KindOf(err))
	require.Empty(t, faults.CodeOf(err))
	require.NotContains(t, err.Error(), "operation")
	require.Equal(t, []SigningDenialEvent{operationDenial(entry, "missing", SigningDenialKeyNotFound)}, audit.events)
}

func TestSigningOperationGateClassifiesMalformedStoredRecord(t *testing.T) {
	catalog := signingops.Default()
	entry := catalog.Entries()[0]
	audit := &recordingAudit{}
	keys := &fakeKeyLookup{err: repository.ErrInvalidPolicyRecord}
	service := NewSigningService(keys, policy.DefaultEvaluator{}, fakeCustodyResolver{}, staticOperationRegistry{catalog: catalog, descriptor: genericDescriptor(entry, new(bool), new(bool))}, audit)

	_, err := service.Execute(context.Background(), entry.Route, v1.BaseSignRequest{KeyID: "corrupted"})
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.Equal(t, faults.SigningOperationNotAllowed, faults.CodeOf(err))
	require.Equal(t, []SigningDenialEvent{operationDenial(entry, "corrupted", SigningDenialInvalidPolicyRecord)}, audit.events)
}

func TestSigningDenialAuditFailureDoesNotChangeDenial(t *testing.T) {
	catalog := signingops.Default()
	entry := catalog.Entries()[0]
	keys := &fakeKeyLookup{key: &domain.Key{ID: "key-1"}}
	service := NewSigningService(keys, policy.DefaultEvaluator{}, fakeCustodyResolver{}, staticOperationRegistry{catalog: catalog, descriptor: genericDescriptor(entry, new(bool), new(bool))}, panicAudit{})

	_, err := service.Execute(context.Background(), entry.Route, v1.BaseSignRequest{KeyID: "key-1"})
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.Equal(t, faults.SigningOperationNotAllowed, faults.CodeOf(err))
}
