package vaultbackend

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/policy"
	"github.com/chain-signer/chain-signer/internal/repository"
	"github.com/chain-signer/chain-signer/internal/service"
	"github.com/chain-signer/chain-signer/internal/version"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type Backend struct {
	*framework.Backend
	policies policy.Evaluator
	custody  custody.Resolver
	registry *service.Registry
	routes   []pathRegistration
	now      func() time.Time
	recovery *service.RecoveryService
}

func New(resolver custody.ExternalResolver) *Backend {
	b := &Backend{
		policies: policy.DefaultEvaluator{},
		custody:  custody.Resolver{External: resolver},
		registry: service.MustNewRegistry(service.DefaultOperationDescriptors()),
		now:      time.Now,
		recovery: service.NewRecoveryService(),
	}
	b.routes = b.routeRegistrations()
	b.Backend = &framework.Backend{
		Help:        "Chain-Signer is a typed signing backend for EVM and TRON workloads.",
		BackendType: logical.TypeLogical,
		Paths:       registeredPaths(b.routes),
	}
	return b
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := New(nil)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *Backend) handleVersion(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return response(v1.VersionResponse{
		APIVersion:      v1.APIVersion,
		BuildVersion:    version.Version,
		SupportedRoutes: registeredPublicRoutes(b.routes),
	}), nil
}

func (b *Backend) handleCreateKey(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.CreateKeyRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, mapError(faults.Wrap(faults.Invalid, err))
	}
	key, err := b.keyService(req.Storage).Create(ctx, payload)
	if err != nil {
		return nil, mapError(err)
	}
	return response(keyResponse(*key)), nil
}

func (b *Backend) handleListKeys(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	ids, err := b.keyService(req.Storage).ListKeyIDs(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	return logical.ListResponse(ids), nil
}

func (b *Backend) handleReadKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	key, err := b.keyService(req.Storage).Read(ctx, fieldString(d, "key_id"))
	if err != nil {
		return nil, mapError(err)
	}
	return response(keyResponse(*key)), nil
}

func (b *Backend) handleUpdateKeyStatus(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var payload v1.UpdateKeyStatusRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, mapError(faults.Wrap(faults.Invalid, err))
	}
	key, err := b.keyService(req.Storage).SetActive(ctx, fieldString(d, "key_id"), payload.Active)
	if err != nil {
		return nil, mapError(err)
	}
	return response(keyResponse(*key)), nil
}

func (b *Backend) handleSign(route string) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
		signing := b.signingService(req.Storage)
		payload, err := signing.NewRequest(route)
		if err != nil {
			return nil, mapError(err)
		}
		if err := decode(req.Data, payload); err != nil {
			return nil, mapError(faults.Wrap(faults.Invalid, err))
		}
		result, err := signing.Sign(ctx, route, payload)
		if err != nil {
			return nil, mapError(err)
		}
		return response(result), nil
	}
}

func (b *Backend) handleVerify(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.VerifyRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, mapError(faults.Wrap(faults.Invalid, err))
	}
	result, err := b.recovery.Verify(payload)
	if err != nil {
		return nil, mapError(err)
	}
	return response(result), nil
}

func (b *Backend) handleRecover(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.VerifyRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, mapError(faults.Wrap(faults.Invalid, err))
	}
	result, err := b.recovery.Recover(payload)
	if err != nil {
		return nil, mapError(err)
	}
	return response(result), nil
}

func (b *Backend) keyService(storage logical.Storage) *service.KeyService {
	return service.NewKeyService(repository.NewVaultKeyRepository(storage), b.now)
}

func (b *Backend) signingService(storage logical.Storage) *service.SigningService {
	return service.NewSigningService(repository.NewVaultKeyRepository(storage), b.policies, b.custody, b.registry)
}

func decode(input map[string]interface{}, out any) error {
	if len(input) == 0 {
		input = map[string]interface{}{}
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func response(payload any) *logical.Response {
	raw, err := json.Marshal(payload)
	if err != nil {
		return logical.ErrorResponse(err.Error())
	}
	out := make(map[string]interface{})
	if err := json.Unmarshal(raw, &out); err != nil {
		return logical.ErrorResponse(err.Error())
	}
	return &logical.Response{Data: out}
}

func keyResponse(key domain.Key) v1.KeyResponse {
	return v1.KeyResponse{
		APIVersion:    v1.APIVersion,
		KeyID:         key.ID,
		ChainFamily:   key.ChainFamily,
		CustodyMode:   key.CustodyMode,
		Active:        key.Active,
		Labels:        key.Labels,
		Policy:        key.Policy,
		SignerAddress: key.SignerAddress,
		PublicKeyHex:  key.PublicKeyHex,
		CreatedAt:     key.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt:     key.UpdatedAt.Format(time.RFC3339Nano),
	}
}

func fieldString(d *framework.FieldData, name string) string {
	value := d.Get(name)
	if value == nil {
		return ""
	}
	asString, _ := value.(string)
	return asString
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, logical.ErrUnsupportedPath) || errors.Is(err, logical.ErrUnsupportedOperation) {
		return err
	}
	switch faults.KindOf(err) {
	case faults.Invalid, faults.PolicyDenied, faults.CustodyFailed, faults.Unsupported:
		return logical.CodedError(http.StatusBadRequest, err.Error())
	case faults.NotFound:
		return logical.CodedError(http.StatusNotFound, err.Error())
	case faults.Conflict:
		return logical.CodedError(http.StatusConflict, err.Error())
	default:
		return logical.CodedError(http.StatusInternalServerError, err.Error())
	}
}
