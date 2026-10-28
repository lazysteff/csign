package cryptography

import (
	"fmt"
	"math/big"
	"slices"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestIndependentCompatibilityIntersections(t *testing.T) {
	verify := func(_ PublicKey, _ Payload, signature []byte) ([]byte, error) { return slices.Clone(signature), nil }
	r, err := NewRegistry([]Scheme{
		{ID: "test_a", KeyTypes: []KeyType{"shared"}, Inputs: []InputKind{Digest}, Verify: verify},
		{ID: "test_b", KeyTypes: []KeyType{"shared", "alternative"}, Inputs: []InputKind{Message}, Verify: verify},
		{ID: "test_new", KeyTypes: []KeyType{"new_type"}, Inputs: []InputKind{Message}, Verify: verify},
	})
	require.NoError(t, err)
	a := Capability{"test_a", Digest}
	b := Capability{"test_b", Message}
	fresh := Capability{"test_new", Message}
	for _, test := range []struct {
		name      string
		operation []Capability
		key       KeyType
		custody   []Capability
		expected  Capability
		denied    bool
	}{
		{"same type first scheme", []Capability{a}, "shared", []Capability{a, b}, a, false},
		{"same type second scheme", []Capability{b}, "shared", []Capability{a, b}, b, false},
		{"multi-scheme operation", []Capability{a, b}, "alternative", []Capability{a, b}, b, false},
		{"new cryptography additive", []Capability{fresh}, "new_type", []Capability{fresh}, fresh, false},
		{"unknown scheme", []Capability{{"unknown", Message}}, "shared", []Capability{a, b}, Capability{}, true},
		{"key type mismatch", []Capability{a}, "alternative", []Capability{a}, Capability{}, true},
		{"input mismatch", []Capability{{"test_a", Message}}, "shared", []Capability{{"test_a", Message}}, Capability{}, true},
		{"custody mismatch", []Capability{b}, "shared", []Capability{a}, Capability{}, true},
		{"operation mismatch", []Capability{a}, "alternative", []Capability{b}, Capability{}, true},
		{"ambiguous", []Capability{a, b}, "shared", []Capability{b, a}, Capability{}, true},
		{"ambiguous reversed registration", []Capability{b, a}, "shared", []Capability{a, b}, Capability{}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, err := r.Resolve(test.operation, test.key, test.custody)
			if test.denied {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expected, c)
			}
		})
	}
}
func TestPayloadAndRegistrySnapshots(t *testing.T) {
	bytes := []byte{1, 2}
	payload := NewPayload(Message, bytes)
	bytes[0] = 9
	copy := payload.Bytes()
	copy[0] = 8
	require.Equal(t, []byte{1, 2}, payload.Bytes())
	r := Default()
	s, ok := r.Scheme(Ed25519Scheme)
	require.True(t, ok)
	s.KeyTypes[0] = "changed"
	again, _ := r.Scheme(Ed25519Scheme)
	require.Equal(t, Ed25519Key, again.KeyTypes[0])
	_, err := r.Verify(Capability{Ed25519Scheme, Digest}, PublicKey{Type: Ed25519Key, Bytes: make([]byte, 32)}, NewPayload(Digest, bytes), nil)
	require.Error(t, err)
}
func TestTestOnlyNewKeyDefinition(t *testing.T) {
	r, err := NewRegistryWithKeys([]Scheme{{ID: "test_new", KeyTypes: []KeyType{"test_new_material"}, Inputs: []InputKind{Message}, Verify: func(_ PublicKey, _ Payload, s []byte) ([]byte, error) { return s, nil }}}, []KeyDefinition{{Type: "test_new_material", Canonicalize: func(raw []byte) (PublicKey, error) {
		if len(raw) != 2 {
			return PublicKey{}, fmt.Errorf("bad synthetic public key")
		}
		return PublicKey{Type: "test_new_material", Bytes: raw}, nil
	}}})
	require.NoError(t, err)
	p, err := r.PublicKey("test_new_material", []byte{1, 2})
	require.NoError(t, err)
	require.Equal(t, KeyType("test_new_material"), p.Type)
	_, registered := Default().Scheme("test_new")
	require.False(t, registered)
}

func TestNormalizeLowSAndSignatureBytes(t *testing.T) {
	s := new(big.Int).Sub(ethcrypto.S256().Params().N, big.NewInt(1))
	normalized := normalizeLowS(s)
	require.Equal(t, big.NewInt(1), normalized)
	require.True(t, normalized.Cmp(s) < 0)
	out := signatureBytes(big.NewInt(1), big.NewInt(2))
	require.Len(t, out, 64)
	require.Equal(t, byte(1), out[31])
	require.Equal(t, byte(2), out[63])
}
