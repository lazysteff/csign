package vaultbackend

import (
	"context"
	"time"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/policy"
	"github.com/chain-signer/chain-signer/internal/repository"
	"github.com/chain-signer/chain-signer/internal/service"
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

func (b *Backend) keyService(storage logical.Storage) *service.KeyService {
	return service.NewKeyService(repository.NewVaultKeyRepository(storage), b.now)
}

func (b *Backend) signingService(storage logical.Storage) *service.SigningService {
	return service.NewSigningService(repository.NewVaultKeyRepository(storage), b.policies, b.custody, b.registry)
}
