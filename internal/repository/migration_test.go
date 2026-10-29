package repository

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lazysteff/csign/v2/internal/chain"
	"github.com/lazysteff/csign/v2/internal/custody"
	"github.com/lazysteff/csign/v2/internal/domain"
	"github.com/lazysteff/csign/v2/internal/signingops"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestLegacyRecordStatusMutationIsSemanticallyNeutral(t *testing.T) {
	ctx := context.Background()
	storage := new(logical.InmemStorage)
	repo := NewVaultKeyRepository(storage, signingops.Default())
	legacy := repositoryTestKey(t, "owner/legacy")
	pub, err := custody.CanonicalPublicKey(domain.Key{KeyType: "secp256k1", PublicKeyHex: legacy.PublicKeyHex})
	require.NoError(t, err)
	p, err := ethcrypto.DecompressPubkey(pub.Bytes)
	require.NoError(t, err)
	legacy.PublicKeyHex = custody.PublicKeyHex(p)
	legacy.Active = true
	legacy.Labels = map[string]string{"owner": "original", "purpose": "control"}
	legacy.CreatedAt = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	legacy.UpdatedAt = legacy.CreatedAt
	legacy.Policy = v1.Policy{AllowedNetworks: []string{"network"}, AllowedSigningOperations: []string{v1.OperationEVMTransferLegacy}, MaxValue: "12", AdditionalPolicyContext: map[string]string{"historical": "preserved"}}
	entry, err := logical.StorageEntryJSON(keyPath(legacy.ID), legacy)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))
	first, err := repo.GetKey(ctx, legacy.ID)
	require.NoError(t, err)
	require.Equal(t, custody.RecordVersion, first.RecordVersion)
	require.Len(t, pub.Bytes, 33)
	unchanged, err := storage.Get(ctx, keyPath(legacy.ID))
	require.NoError(t, err)
	require.Equal(t, entry.Value, unchanged.Value, "read must not rewrite legacy storage")
	expected := first.Clone()
	expected.Active = false
	expected.UpdatedAt = expected.UpdatedAt.Add(time.Hour)
	require.NoError(t, repo.PutKey(ctx, expected))
	decoded, err := repo.GetKey(ctx, legacy.ID)
	require.NoError(t, err)
	require.Equal(t, expected, *decoded)
	require.Equal(t, legacy.ID, decoded.ID)
	require.Equal(t, legacy.PrivateKeyHex, decoded.PrivateKeyHex)
	require.Equal(t, legacy.Policy, decoded.Policy)
	require.Equal(t, legacy.Labels, decoded.Labels)
	require.Equal(t, legacy.SignerAddress, decoded.SignerAddress)
	require.Equal(t, legacy.ChainFamily, decoded.ChainFamily)
	require.Equal(t, legacy.CreatedAt, decoded.CreatedAt)
	rewritten, err := storage.Get(ctx, keyPath(legacy.ID))
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rewritten.Value, &fields))
	require.Contains(t, fields, "schema_version")
	require.Contains(t, fields, "key_type")
	require.NotContains(t, fields, "supported_schemes")
	require.NotContains(t, fields, "input_capabilities")
}
func TestLegacyRecordsRejectInconsistentMetadata(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*domain.Key)
	}{
		{"material public mismatch", func(k *domain.Key) { other := repositoryTestKey(t, "other"); k.PublicKeyHex = other.PublicKeyHex }},
		{"protocol identity mismatch", func(k *domain.Key) { k.SignerAddress = "0x1111111111111111111111111111111111111111" }},
		{"mixed custody", func(k *domain.Key) { k.ExternalSignerRef = "external" }},
		{"invalid operation authorization", func(k *domain.Key) { k.Policy.AllowedSigningOperations = []string{"unknown"} }},
		{"ambiguous legacy type", func(k *domain.Key) { k.KeyType = "ed25519" }},
		{"storage identity mismatch", func(k *domain.Key) { k.ID = "different" }},
		{"unknown schema", func(k *domain.Key) { k.RecordVersion = 999 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			storage := new(logical.InmemStorage)
			repo := NewVaultKeyRepository(storage, signingops.Default())
			key := repositoryTestKey(t, "legacy")
			test.change(&key)
			entry, err := logical.StorageEntryJSON(keyPath("legacy"), key)
			require.NoError(t, err)
			require.NoError(t, storage.Put(ctx, entry))
			_, err = repo.GetKey(ctx, "legacy")
			require.ErrorIs(t, err, ErrInvalidPolicyRecord)
			preserved, err := storage.Get(ctx, keyPath("legacy"))
			require.NoError(t, err)
			require.Equal(t, entry.Value, preserved.Value)
		})
	}
}
func TestLegacyExternalCustodyRoundTrip(t *testing.T) {
	ctx := context.Background()
	storage := new(logical.InmemStorage)
	repo := NewVaultKeyRepository(storage, signingops.Default())
	key := repositoryTestKey(t, "external")
	key.CustodyMode = v1.CustodyModePKCS11
	key.PrivateKeyHex = ""
	key.ExternalSignerRef = "original-ref"
	key.Active = true
	entry, err := logical.StorageEntryJSON(keyPath(key.ID), key)
	require.NoError(t, err)
	require.NoError(t, storage.Put(ctx, entry))
	decoded, err := repo.GetKey(ctx, key.ID)
	require.NoError(t, err)
	decoded.Active = false
	require.NoError(t, repo.PutKey(ctx, *decoded))
	again, err := repo.GetKey(ctx, key.ID)
	require.NoError(t, err)
	require.Equal(t, "original-ref", again.ExternalSignerRef)
	require.Empty(t, again.PrivateKeyHex)
	require.Empty(t, again.MaterialFormat)
	require.Equal(t, *decoded, *again)
}

func TestStoredRecordsRejectAmbiguousJSON(t *testing.T) {
	key := repositoryTestKey(t, "legacy")
	raw, err := json.Marshal(key)
	require.NoError(t, err)
	for name, value := range map[string]string{
		"duplicate field": strings.TrimSuffix(string(raw), "}") + `,"active":false}`,
		"unknown field":   strings.TrimSuffix(string(raw), "}") + `,"unknown":true}`,
		"trailing record": string(raw) + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			storage := new(logical.InmemStorage)
			entry := &logical.StorageEntry{Key: keyPath(key.ID), Value: []byte(value)}
			require.NoError(t, storage.Put(ctx, entry))
			repo := NewVaultKeyRepository(storage, signingops.Default())
			_, err := repo.GetKey(ctx, key.ID)
			require.ErrorIs(t, err, ErrInvalidPolicyRecord)
			preserved, err := storage.Get(ctx, entry.Key)
			require.NoError(t, err)
			require.Equal(t, entry.Value, preserved.Value)
		})
	}
}

type migrationCountingStorage struct {
	logical.Storage
	writes int
}

func (s *migrationCountingStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	s.writes++
	return s.Storage.Put(ctx, entry)
}

func TestLegacyMigrationPreservesEVMAndTRONSigningMaterial(t *testing.T) {
	for _, family := range []string{v1.ChainFamilyEVM, v1.ChainFamilyTRON} {
		t.Run(family, func(t *testing.T) {
			ctx := context.Background()
			storage := &migrationCountingStorage{Storage: new(logical.InmemStorage)}
			repo := NewVaultKeyRepository(storage, signingops.Default())
			legacy := repositoryTestKey(t, "legacy/"+family)
			legacy.ChainFamily = family
			public, err := custody.CanonicalPublicKey(domain.Key{KeyType: "secp256k1", PublicKeyHex: legacy.PublicKeyHex})
			require.NoError(t, err)
			legacy.SignerAddress, err = chain.DerivePublicIdentity(family, public)
			require.NoError(t, err)
			legacy.Active = true
			legacy.CustodyMode = "" // Historical managed custody default.
			legacy.CreatedAt = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
			legacy.UpdatedAt = legacy.CreatedAt
			entry, err := logical.StorageEntryJSON(keyPath(legacy.ID), legacy)
			require.NoError(t, err)
			require.NoError(t, storage.Put(ctx, entry))
			storage.writes = 0
			digest := make([]byte, 32)
			digest[0] = 1
			originalMaterial, err := (custody.Resolver{}).MaterialForKey(ctx, legacy)
			require.NoError(t, err)
			originalSignature, err := custody.RecoverableSignature(ctx, originalMaterial, digest)
			require.NoError(t, err)
			decoded, err := repo.GetKey(ctx, legacy.ID)
			require.NoError(t, err)
			require.Zero(t, storage.writes)
			corrupted := decoded.Clone()
			corrupted.PrivateKeyHex = repositoryTestKey(t, "other").PrivateKeyHex
			require.ErrorIs(t, repo.PutKey(ctx, corrupted), ErrInvalidPolicyRecord)
			require.Zero(t, storage.writes, "invalid material must fail before writing")
			preserved, err := storage.Get(ctx, entry.Key)
			require.NoError(t, err)
			require.Equal(t, entry.Value, preserved.Value)
			decoded.Active = false
			decoded.UpdatedAt = decoded.UpdatedAt.Add(time.Hour)
			require.NoError(t, repo.PutKey(ctx, *decoded))
			require.Equal(t, 1, storage.writes)
			reloaded, err := repo.GetKey(ctx, legacy.ID)
			require.NoError(t, err)
			require.Equal(t, *decoded, *reloaded)
			require.Equal(t, legacy.PrivateKeyHex, reloaded.PrivateKeyHex)
			reloadedMaterial, err := (custody.Resolver{}).MaterialForKey(ctx, *reloaded)
			require.NoError(t, err)
			reloadedSignature, err := custody.RecoverableSignature(ctx, reloadedMaterial, digest)
			require.NoError(t, err)
			require.Equal(t, originalSignature, reloadedSignature)
			require.Equal(t, 1, storage.writes, "read and cryptographic checks must not migrate records")
		})
	}
}
