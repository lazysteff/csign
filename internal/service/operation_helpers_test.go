package service

import (
	"context"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

type staticOperationRegistry struct {
	catalog    *signingops.Catalog
	descriptor OperationDescriptor
}

func (r staticOperationRegistry) Lookup(route string) (OperationDescriptor, error) {
	if route != r.descriptor.Route {
		return OperationDescriptor{}, faults.New(faults.Unsupported, "unsupported route")
	}
	return r.descriptor, nil
}

func (r staticOperationRegistry) Routes() []string { return []string{r.descriptor.Route} }

func (r staticOperationRegistry) Catalog() *signingops.Catalog { return r.catalog }

func genericDescriptor(entry v1.SigningOperationCapability, validated, executed *bool) OperationDescriptor {
	return OperationDescriptor{
		SigningOperationCapability: entry,
		NewRequest:                 func() any { return &v1.BaseSignRequest{} },
		Validate: func(domain.Key, any) error {
			*validated = true
			return nil
		},
		Execute: func(context.Context, custody.Material, any) (any, error) {
			*executed = true
			return "ok", nil
		},
	}
}

func operationDenial(capability v1.SigningOperationCapability, keyID string, category SigningDenialCategory) SigningDenialEvent {
	return SigningDenialEvent{
		SigningOperationCapability: capability,
		KeyID:                      keyID,
		Category:                   category,
	}
}

type recordingAudit struct{ events []SigningDenialEvent }

func (a *recordingAudit) RecordSigningDenial(_ context.Context, event SigningDenialEvent) {
	a.events = append(a.events, event)
}

type panicAudit struct{}

func (panicAudit) RecordSigningDenial(context.Context, SigningDenialEvent) {
	panic("audit unavailable")
}
