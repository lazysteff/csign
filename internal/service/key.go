package service

import (
	"context"
	"maps"
	"time"

	"github.com/chain-signer/chain-signer/internal/chain"
	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/keyid"
	"github.com/chain-signer/chain-signer/internal/policy"
	"github.com/chain-signer/chain-signer/internal/repository"
	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

type KeyService struct {
	repo    repository.KeyRepository
	catalog *signingops.Catalog
	now     func() time.Time
}

func NewKeyService(repo repository.KeyRepository, catalog *signingops.Catalog, now func() time.Time) *KeyService {
	if now == nil {
		now = time.Now
	}
	return &KeyService{
		repo:    repo,
		catalog: catalog,
		now:     now,
	}
}

func (s *KeyService) Create(ctx context.Context, req v1.CreateKeyRequest) (*domain.Key, error) {
	if err := policy.ValidateCreateKeyRequest(req); err != nil {
		return nil, err
	}
	if err := policy.ValidateStoredPolicy(s.catalog, req.Policy); err != nil {
		return nil, err
	}

	keyID := req.KeyID
	switch {
	case keyID != "":
		if err := keyid.Validate(keyID); err != nil {
			return nil, err
		}
	case req.HasKeyID():
		return nil, keyid.Validate(keyID)
	default:
		var err error
		keyID, err = domain.GenerateKeyID()
		if err != nil {
			return nil, err
		}
	}

	existing, err := s.repo.GetKey(ctx, keyID)
	if err != nil {
		if !isRepositoryKeyNotFound(err) {
			return nil, err
		}
	}
	if existing != nil {
		return nil, faults.Newf(faults.Conflict, "key %q already exists", keyID)
	}

	provisioned, err := custody.ProvisionCreateRequest(req)
	if err != nil {
		return nil, faults.Wrap(faults.Invalid, err)
	}

	chainFamily := domain.NormalizeChainFamily(req.ChainFamily)
	signerAddress, err := chain.DeriveSignerAddress(chainFamily, provisioned.PublicKey)
	if err != nil {
		return nil, faults.Wrap(faults.Invalid, err)
	}

	now := s.now().UTC()
	key := domain.Key{
		ID:                keyID,
		ChainFamily:       chainFamily,
		CustodyMode:       provisioned.CustodyMode,
		Active:            true,
		Labels:            maps.Clone(req.Labels),
		Policy:            req.Policy.Clone(),
		SignerAddress:     signerAddress,
		PublicKeyHex:      provisioned.PublicKeyHex,
		PrivateKeyHex:     provisioned.PrivateKeyHex,
		ExternalSignerRef: provisioned.ExternalSignerRef,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.repo.PutKey(ctx, key.Clone()); err != nil {
		return nil, err
	}
	clone := key.Clone()
	return &clone, nil
}

func (s *KeyService) Read(ctx context.Context, keyID string) (*domain.Key, error) {
	if err := keyid.Validate(keyID); err != nil {
		return nil, err
	}
	return s.readValidated(ctx, keyID)
}

func (s *KeyService) readValidated(ctx context.Context, keyID string) (*domain.Key, error) {
	key, err := s.repo.GetKey(ctx, keyID)
	if err != nil {
		if isRepositoryKeyNotFound(err) {
			return nil, faults.Newf(faults.NotFound, "key %q was not found", keyID)
		}
		return nil, err
	}
	if key == nil {
		return nil, faults.Newf(faults.NotFound, "key %q was not found", keyID)
	}
	clone := key.Clone()
	return &clone, nil
}

func (s *KeyService) ListKeyIDs(ctx context.Context) ([]string, error) {
	return s.repo.ListKeyIDs(ctx)
}

func (s *KeyService) SetActive(ctx context.Context, keyID string, active bool) (*domain.Key, error) {
	if err := keyid.Validate(keyID); err != nil {
		return nil, err
	}

	key, err := s.readValidated(ctx, keyID)
	if err != nil {
		return nil, err
	}
	key.Active = active
	key.UpdatedAt = s.now().UTC()
	if err := s.repo.PutKey(ctx, key.Clone()); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *KeyService) SetPolicy(ctx context.Context, keyID string, newPolicy v1.Policy) (*domain.Key, error) {
	if err := keyid.Validate(keyID); err != nil {
		return nil, err
	}
	if err := policy.ValidateStoredPolicy(s.catalog, newPolicy); err != nil {
		return nil, err
	}
	key, err := s.readValidated(ctx, keyID)
	if err != nil {
		return nil, err
	}
	// The structured update protocol cannot set deprecated opaque context. Preserve
	// any context already stored on older keys while replacing enforced fields.
	newPolicy = newPolicy.Clone()
	newPolicy.AdditionalPolicyContext = maps.Clone(key.Policy.AdditionalPolicyContext)
	key.Policy = newPolicy
	key.UpdatedAt = s.now().UTC()
	if err := s.repo.PutKey(ctx, key.Clone()); err != nil {
		return nil, err
	}
	return key, nil
}
