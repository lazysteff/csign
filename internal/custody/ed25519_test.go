package custody

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lazysteff/csign/v2/internal/cryptography"
	"github.com/lazysteff/csign/v2/internal/domain"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

const edSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
const edPub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

func TestEd25519RFC8032AndImportForms(t *testing.T) {
	for _, material := range []string{edSeed, edSeed + edPub} {
		p, err := ProvisionCreateRequest(v1.CreateKeyRequest{KeyType: "ed25519", ImportPrivateKey: material})
		require.NoError(t, err)
		require.Equal(t, "0x"+edSeed, p.PrivateKeyHex)
		require.Equal(t, "0x"+edPub, p.PublicKeyHex)
		key := domain.Key{RecordVersion: RecordVersion, ID: "key", KeyType: p.KeyType, CustodyMode: p.CustodyMode, MaterialFormat: p.MaterialFormat, PublicKeyHex: p.PublicKeyHex, PrivateKeyHex: p.PrivateKeyHex}
		key, err = NormalizeRecord(key)
		require.NoError(t, err)
		m, err := (Resolver{}).ResolveSigningMaterial(context.Background(), key)
		require.NoError(t, err)
		payload := cryptography.NewPayload(cryptography.Message, nil)
		sig, err := m.Sign(context.Background(), ed25519Capability, payload)
		require.NoError(t, err)
		require.Equal(t, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", hex.EncodeToString(sig))
		pub, err := m.CanonicalPublicKey()
		require.NoError(t, err)
		verified, err := cryptography.Default().Verify(ed25519Capability, pub, payload, sig)
		require.NoError(t, err)
		require.Equal(t, sig, verified)
		// Generic Ed25519 accepts empty bytes cryptographically; the opaque operation
		// independently imposes its API resource constraints.
	}
}
func TestEd25519MaterialValidation(t *testing.T) {
	for _, bad := range []string{"not-hex", "00", strings.Repeat("00", 31), strings.Repeat("00", 33), edSeed + strings.Repeat("00", 32)} {
		_, err := ProvisionCreateRequest(v1.CreateKeyRequest{KeyType: "ed25519", ImportPrivateKey: bad})
		require.Error(t, err)
		require.NotContains(t, err.Error(), edSeed)
	}
	_, err := ProvisionCreateRequest(v1.CreateKeyRequest{KeyType: "ed25519", CustodyMode: "pkcs11", PublicKeyHex: edPub, ExternalSignerRef: "hsm"})
	require.Error(t, err)
	_, err = ProvisionCreateRequest(v1.CreateKeyRequest{ChainFamily: "solana"})
	require.ErrorContains(t, err, "key_type is required")
	generated, err := ProvisionCreateRequest(v1.CreateKeyRequest{KeyType: "ed25519"})
	require.NoError(t, err)
	require.Len(t, generated.CanonicalPublic.Bytes, 32)
	key := domain.Key{RecordVersion: RecordVersion, KeyType: generated.KeyType, CustodyMode: generated.CustodyMode, MaterialFormat: generated.MaterialFormat, PublicKeyHex: generated.PublicKeyHex, PrivateKeyHex: generated.PrivateKeyHex}
	key.PublicKeyHex = edPub
	_, err = NormalizeRecord(key)
	require.Error(t, err)
}
func TestGenericEd25519SnapshotsAndNoProtocolMetadata(t *testing.T) {
	seed, err := parseEd25519Seed(edSeed)
	require.NoError(t, err)
	m := ed25519Material{private: ed25519.NewKeyFromSeed(seed)}
	pub, err := m.CanonicalPublicKey()
	require.NoError(t, err)
	pub.Bytes[0] ^= 1
	again, err := m.CanonicalPublicKey()
	require.NoError(t, err)
	require.Equal(t, edPub, hex.EncodeToString(again.Bytes))
	payload := cryptography.NewPayload(cryptography.Message, []byte{1, 2})
	sig, err := m.Sign(context.Background(), ed25519Capability, payload)
	require.NoError(t, err)
	_, err = cryptography.Default().Verify(ed25519Capability, again, cryptography.NewPayload(cryptography.Message, []byte{1, 3}), sig)
	require.Error(t, err)
	_, err = m.Sign(context.Background(), ecdsaCapability, payload)
	require.Error(t, err)
	response := v1.KeyResponse{KeyType: "ed25519", PublicKeyHex: "0x" + edPub}
	encoded, err := json.Marshal(response)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), edSeed)
	require.NotContains(t, string(encoded), "private_key")
}

func TestExplicitManagedKeyCreationRejectsConflictingPublicMaterial(t *testing.T) {
	for _, keyType := range []string{"secp256k1", "ed25519"} {
		_, err := ProvisionCreateRequest(v1.CreateKeyRequest{KeyType: keyType, PublicKeyHex: edPub})
		require.Error(t, err)
	}
	key, err := ProvisionCreateRequest(v1.CreateKeyRequest{KeyType: "ed25519", CustodyMode: " MVP ", ImportPrivateKey: edSeed})
	require.NoError(t, err)
	require.Equal(t, "mvp", key.CustodyMode)
}
