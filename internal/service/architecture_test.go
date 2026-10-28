package service

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/chain-signer/chain-signer/internal/cryptography"
	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/policy"
	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

type architectureCustody struct {
	capabilities    []cryptography.Capability
	material        custody.SigningMaterial
	events          *[]string
	resolves, signs int
}

func (c *architectureCustody) DescribeCapabilities(context.Context, domain.Key) ([]cryptography.Capability, error) {
	*c.events = append(*c.events, "capabilities")
	return c.capabilities, nil
}
func (c *architectureCustody) ResolveSigningMaterial(context.Context, domain.Key) (custody.SigningMaterial, error) {
	c.resolves++
	*c.events = append(*c.events, "material")
	return c.material, nil
}

type architectureMaterial struct {
	pub     cryptography.PublicKey
	custody *architectureCustody
}

func (m architectureMaterial) CanonicalPublicKey() (cryptography.PublicKey, error) {
	return m.pub.Clone(), nil
}
func (m architectureMaterial) Sign(_ context.Context, _ cryptography.Capability, p cryptography.Payload) ([]byte, error) {
	m.custody.signs++
	*m.custody.events = append(*m.custody.events, "sign")
	return p.Bytes(), nil
}
func TestGeneralizedExecutionAndFailClosedIntersections(t *testing.T) {
	for _, test := range []struct {
		name    string
		allowed []cryptography.Capability
		key     cryptography.KeyType
		custody []cryptography.Capability
		payload cryptography.InputKind
		deny    bool
	}{
		{"new type through unchanged authorization", []cryptography.Capability{{Scheme: "synthetic", Input: cryptography.Message}}, "new_key", []cryptography.Capability{{Scheme: "synthetic", Input: cryptography.Message}}, cryptography.Message, false},
		{"key compatibility", []cryptography.Capability{{Scheme: "synthetic", Input: cryptography.Message}}, "secp256k1", []cryptography.Capability{{Scheme: "synthetic", Input: cryptography.Message}}, cryptography.Message, true},
		{"operation scheme", []cryptography.Capability{{Scheme: cryptography.ECDSASecp256k1, Input: cryptography.Digest}}, "new_key", []cryptography.Capability{{Scheme: "synthetic", Input: cryptography.Message}}, cryptography.Message, true},
		{"scheme input", []cryptography.Capability{{Scheme: "synthetic", Input: cryptography.Digest}}, "new_key", []cryptography.Capability{{Scheme: "synthetic", Input: cryptography.Digest}}, cryptography.Digest, true},
		{"custody support", []cryptography.Capability{{Scheme: "synthetic", Input: cryptography.Message}}, "new_key", []cryptography.Capability{{Scheme: cryptography.ECDSASecp256k1, Input: cryptography.Digest}}, cryptography.Message, true},
		{"payload preparation mismatch", []cryptography.Capability{{Scheme: "synthetic", Input: cryptography.Message}}, "new_key", []cryptography.Capability{{Scheme: "synthetic", Input: cryptography.Message}}, cryptography.Digest, true},
		{"ambiguous schemes", []cryptography.Capability{{Scheme: "synthetic", Input: cryptography.Message}, {Scheme: "second", Input: cryptography.Message}}, "new_key", []cryptography.Capability{{Scheme: "synthetic", Input: cryptography.Message}, {Scheme: "second", Input: cryptography.Message}}, cryptography.Message, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := []string{}
			verify := func(_ cryptography.PublicKey, p cryptography.Payload, s []byte) ([]byte, error) {
				events = append(events, "verify")
				require.Equal(t, []byte{1, 2}, p.Bytes())
				return s, nil
			}
			schemes, err := cryptography.NewRegistryWithKeys([]cryptography.Scheme{{ID: "synthetic", KeyTypes: []cryptography.KeyType{"new_key"}, Inputs: []cryptography.InputKind{cryptography.Message}, Verify: verify}, {ID: "second", KeyTypes: []cryptography.KeyType{"new_key"}, Inputs: []cryptography.InputKind{cryptography.Message}, Verify: verify}}, []cryptography.KeyDefinition{{Type: "new_key", Canonicalize: func(raw []byte) (cryptography.PublicKey, error) {
				return cryptography.PublicKey{Type: "new_key", Bytes: raw}, nil
			}}})
			require.NoError(t, err)
			capability := v1.SigningOperationCapability{Route: "test/sign", Operation: "test_operation"}
			catalog := signingops.MustNew([]v1.SigningOperationCapability{capability})
			descriptor := OperationDescriptor{SigningOperationCapability: capability, CompatibleSchemes: test.allowed, NewRequest: func() any { return &v1.BaseSignRequest{} }, Validate: func(domain.Key, any) error { events = append(events, "authorize"); return nil }, Normalize: func(r any) (any, error) { events = append(events, "normalize"); return r, nil }, Prepare: func(_ context.Context, c cryptography.Capability, p cryptography.PublicKey, r any) (*cryptography.Prepared, error) {
				events = append(events, "prepare")
				require.Equal(t, cryptography.SchemeID("synthetic"), c.Scheme)
				return &cryptography.Prepared{Payload: cryptography.NewPayload(test.payload, []byte{1, 2}), Format: func(s []byte) (any, error) { events = append(events, "format"); return s, nil }}, nil
			}}
			// Runtime guard is independently tested with a deliberately malformed mock
			// registry; production registry also rejects invalid bindings at startup.
			var registry OperationRegistry = staticOperationRegistry{catalog: catalog, descriptor: descriptor}
			if !test.deny {
				registry, err = NewRegistryWithSchemes(catalog, []OperationDescriptor{descriptor}, schemes)
				require.NoError(t, err)
			}
			c := &architectureCustody{capabilities: test.custody, events: &events}
			c.material = architectureMaterial{pub: cryptography.PublicKey{Type: test.key, Bytes: []byte{3, 4}}, custody: c}
			key := &domain.Key{ID: "key", KeyType: test.key, PublicKeyHex: "0304", Active: true, Labels: map[string]string{"owner": "team"}, Policy: v1.Policy{AllowedSigningOperations: []string{"test_operation"}}}
			before, err := json.Marshal(key)
			require.NoError(t, err)
			s := NewSigningService(&fakeKeyLookup{key: key}, policy.DefaultEvaluator{}, c, registry, nil)
			s.schemes = schemes
			_, err = s.Execute(context.Background(), "test/sign", &v1.BaseSignRequest{KeyID: "key"})
			if test.deny {
				require.Error(t, err)
				require.Zero(t, c.signs)
				require.Zero(t, c.resolves)
			} else {
				require.NoError(t, err)
				require.Equal(t, []string{"authorize", "normalize", "capabilities", "prepare", "material", "sign", "verify", "format"}, events)
				require.Equal(t, 1, c.signs)
			}
			after, err := json.Marshal(key)
			require.NoError(t, err)
			require.Equal(t, string(before), string(after))
			require.NotContains(t, string(after), "supported_schemes")
		})
	}
}

type boundaryEd25519Material struct {
	private ed25519.PrivateKey
	mode    string
	custody *architectureCustody
}

func (m boundaryEd25519Material) CanonicalPublicKey() (cryptography.PublicKey, error) {
	pub := m.private.Public().(ed25519.PublicKey)
	if m.mode == "identity mismatch" {
		pub[0] ^= 1
	}
	return cryptography.CanonicalEd25519(pub)
}

func (m boundaryEd25519Material) Sign(_ context.Context, _ cryptography.Capability, p cryptography.Payload) ([]byte, error) {
	m.custody.signs++
	copyOfBytes := p.Bytes()
	copyOfBytes[0] ^= 1
	if m.mode == "signed mutated bytes" {
		return ed25519.Sign(m.private, copyOfBytes), nil
	}
	sig := ed25519.Sign(m.private, p.Bytes())
	if m.mode == "invalid signature" {
		sig[0] ^= 1
	}
	return sig, nil
}

func TestSolanaCryptographicBoundary(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := private.Public().(ed25519.PublicKey)
	for _, mode := range []string{"immutable payload", "identity mismatch", "signed mutated bytes", "invalid signature", "disabled key", "other operation permission", "typed nil material"} {
		t.Run(mode, func(t *testing.T) {
			events := []string{}
			c := &architectureCustody{capabilities: []cryptography.Capability{{Scheme: cryptography.Ed25519Scheme, Input: cryptography.Message}}, events: &events}
			c.material = boundaryEd25519Material{private: private, mode: mode, custody: c}
			if mode == "typed nil material" {
				var material *boundaryEd25519Material
				c.material = material
			}
			key := &domain.Key{ID: "ed", KeyType: cryptography.Ed25519Key, PublicKeyHex: hex.EncodeToString(pub), Active: mode != "disabled key", Policy: v1.Policy{AllowedSigningOperations: []string{v1.OperationSolanaMessage}}}
			if mode == "other operation permission" {
				key.Policy.AllowedSigningOperations = []string{"other_ed25519_operation"}
			}
			catalog := signingops.Default()
			registry, err := NewRegistry(catalog, DefaultOperationDescriptors(catalog))
			require.NoError(t, err)
			s := NewSigningService(&fakeKeyLookup{key: key}, policy.DefaultEvaluator{}, c, registry, nil)
			request := &v1.SolanaMessageSignRequest{KeyID: "ed", ChainFamily: "solana", Network: "devnet", RequestID: "r", MessageHex: "010203"}
			result, err := s.Execute(context.Background(), "v1/solana/messages/sign", request)
			if mode == "immutable payload" {
				require.NoError(t, err)
				response := result.(*v1.SolanaMessageSignResponse)
				sig, err := enc.DecodeHex(response.SignatureHex)
				require.NoError(t, err)
				require.True(t, ed25519.Verify(pub, []byte{1, 2, 3}, sig))
				require.Equal(t, 1, c.signs)
			} else {
				require.Error(t, err)
				require.Nil(t, result)
				require.NotContains(t, err.Error(), hex.EncodeToString(private.Seed()))
				if mode == "signed mutated bytes" || mode == "invalid signature" {
					require.Equal(t, faults.SignatureVerificationFailed, faults.CodeOf(err))
					require.Equal(t, 1, c.signs)
				} else {
					require.Zero(t, c.signs)
				}
			}
			require.Equal(t, "010203", request.MessageHex)
		})
	}
}
func TestEd25519KeyWithECDSAOnlyCustodyDeniesBeforeMaterial(t *testing.T) {
	events := []string{}
	c := &architectureCustody{capabilities: testCapabilities(), events: &events}
	key := &domain.Key{ID: "ed", KeyType: cryptography.Ed25519Key, PublicKeyHex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", Active: true, Policy: v1.Policy{AllowedSigningOperations: []string{v1.OperationSolanaMessage}}}
	catalog := signingops.Default()
	registry, err := NewRegistry(catalog, DefaultOperationDescriptors(catalog))
	require.NoError(t, err)
	s := NewSigningService(&fakeKeyLookup{key: key}, policy.DefaultEvaluator{}, c, registry, nil)
	_, err = s.Execute(context.Background(), "v1/solana/messages/sign", &v1.SolanaMessageSignRequest{KeyID: "ed", ChainFamily: "solana", Network: "devnet", RequestID: "r", MessageHex: "01"})
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.Zero(t, c.resolves)
	require.Zero(t, c.signs)
}
func TestRegistryRejectsUnsupportedPreparationBinding(t *testing.T) {
	d := testDescriptor("test/sign")
	d.CompatibleSchemes = []cryptography.Capability{{Scheme: cryptography.Ed25519Scheme, Input: cryptography.Digest}}
	catalog := signingops.MustNew([]v1.SigningOperationCapability{d.SigningOperationCapability})
	_, err := NewRegistry(catalog, []OperationDescriptor{d})
	require.Error(t, err)
	d.CompatibleSchemes = []cryptography.Capability{{Scheme: "unsupported", Input: cryptography.Message}}
	_, err = NewRegistry(catalog, []OperationDescriptor{d})
	require.Error(t, err)
}
