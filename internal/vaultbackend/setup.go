package vaultbackend

import (
	"context"
	"time"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/policy"
	"github.com/chain-signer/chain-signer/internal/repository"
	"github.com/chain-signer/chain-signer/internal/service"
	"github.com/chain-signer/chain-signer/internal/signingops"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type Backend struct {
	*framework.Backend
	policies policy.Evaluator
	custody  custody.Resolver
	registry *service.Registry
	catalog  *signingops.Catalog
	routes   []pathRegistration
	now      func() time.Time
	recovery *service.RecoveryService
}

func New(resolver custody.ExternalResolver) *Backend {
	b, err := newBackend(resolver)
	if err != nil {
		panic(err)
	}
	return b
}

func newBackend(resolver custody.ExternalResolver) (*Backend, error) {
	catalog, err := signingops.Production()
	if err != nil {
		return nil, err
	}
	return newBackendWithCatalog(resolver, catalog)
}

// newBackendWithCatalog exists for startup-integrity tests. Production always
// calls newBackend and therefore always uses the sealed default catalog.
func newBackendWithCatalog(resolver custody.ExternalResolver, catalog *signingops.Catalog) (*Backend, error) {
	registry, err := service.NewRegistry(catalog, service.DefaultOperationDescriptors(catalog))
	if err != nil {
		return nil, err
	}
	b := &Backend{
		policies: policy.DefaultEvaluator{},
		custody:  custody.Resolver{External: resolver},
		registry: registry,
		catalog:  catalog,
		now:      time.Now,
		recovery: service.NewRecoveryService(),
	}
	b.routes = b.routeRegistrations()
	b.Backend = &framework.Backend{
		Help:        "Chain-Signer is a typed signing backend for EVM and TRON workloads.",
		BackendType: logical.TypeLogical,
		Paths:       registeredPaths(b.routes),
	}
	return b, nil
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend(nil)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *Backend) keyService(storage logical.Storage) *service.KeyService {
	return service.NewKeyService(repository.NewVaultKeyRepository(storage, b.catalog), b.catalog, b.now)
}

func (b *Backend) signingService(storage logical.Storage) *service.SigningService {
	return service.NewSigningService(repository.NewVaultKeyRepository(storage, b.catalog), b.policies, b.custody, b.registry, denialAudit{logger: b.Logger()})
}
