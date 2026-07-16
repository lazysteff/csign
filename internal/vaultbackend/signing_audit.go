package vaultbackend

import (
	"context"

	"github.com/chain-signer/chain-signer/internal/service"
	"github.com/hashicorp/go-hclog"
	metrics "github.com/hashicorp/go-metrics"
)

type denialAudit struct {
	logger hclog.Logger
}

func (a denialAudit) RecordSigningDenial(_ context.Context, event service.SigningDenialEvent) {
	fields := []any{
		"route", event.Route,
		"operation", event.Operation,
		"category", string(event.Category),
	}
	if event.KeyID != "" {
		fields = append(fields, "key_id", event.KeyID)
	}
	if a.logger != nil {
		a.logger.Warn("signing operation denied", fields...)
	}
	metrics.IncrCounter([]string{"chain_signer", "signing_operation_denied", string(event.Category)}, 1)
}
