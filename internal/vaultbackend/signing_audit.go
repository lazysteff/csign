package vaultbackend

import (
	"context"

	"github.com/chain-signer/chain-signer/internal/service"
	metrics "github.com/hashicorp/go-metrics"
)

type backendSigningAudit struct {
	backend *Backend
}

func (a backendSigningAudit) RecordSigningDenial(_ context.Context, event service.SigningDenialEvent) {
	fields := []any{
		"route", event.Route,
		"operation", event.Operation,
		"category", string(event.Category),
	}
	if event.KeyID != "" {
		fields = append(fields, "key_id", event.KeyID)
	}
	if a.backend != nil && a.backend.Logger() != nil {
		a.backend.Logger().Warn("signing operation denied", fields...)
	}
	metrics.IncrCounter([]string{"chain_signer", "signing_operation_denied", string(event.Category)}, 1)
}
