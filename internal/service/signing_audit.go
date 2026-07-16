package service

import (
	"context"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

type SigningDenialCategory string

const (
	SigningDenialMissingAllowlist    SigningDenialCategory = "missing_allowlist"
	SigningDenialOperationMismatch   SigningDenialCategory = "operation_mismatch"
	SigningDenialInvalidPolicyRecord SigningDenialCategory = "invalid_policy_record"
	SigningDenialInvalidRoute        SigningDenialCategory = "invalid_route_descriptor"
	SigningDenialKeyNotFound         SigningDenialCategory = "key_not_found"
)

type SigningDenialEvent struct {
	v1.SigningOperationCapability
	KeyID    string
	Category SigningDenialCategory
}

// SigningAuditSink receives best-effort, payload-free policy denial events.
// Implementations must not be required for an authorization decision.
type SigningAuditSink interface {
	RecordSigningDenial(context.Context, SigningDenialEvent)
}

func emitSigningDenial(ctx context.Context, sink SigningAuditSink, event SigningDenialEvent) {
	if sink == nil {
		return
	}
	// Audit infrastructure is deliberately isolated from signing decisions.
	// A broken sink cannot turn a denial into an allow or fail the request.
	defer func() { _ = recover() }()
	sink.RecordSigningDenial(ctx, event)
}
