package service

import (
	"context"

	"github.com/lazysteff/csign/v2/internal/cryptography"
	"github.com/lazysteff/csign/v2/internal/domain"
	"github.com/lazysteff/csign/v2/internal/faults"
	"github.com/lazysteff/csign/v2/internal/signingops"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
)

type staticOperationRegistry struct {
	catalog    *signingops.Catalog
	descriptor OperationDescriptor
	lookupErr  error
}

func (r staticOperationRegistry) Lookup(route string) (OperationDescriptor, error) {
	if r.lookupErr != nil {
		return OperationDescriptor{}, r.lookupErr
	}
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
		Normalize: testNormalize, CompatibleSchemes: testCapabilities(),
		Prepare: func(context.Context, cryptography.Capability, cryptography.PublicKey, any) (*cryptography.Prepared, error) {
			return &cryptography.Prepared{Payload: cryptography.NewPayload(cryptography.Digest, make([]byte, 32)), Format: func(_ []byte) (any, error) {
				*executed = true
				return "ok", nil
			}}, nil
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
