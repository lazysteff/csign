// Package cryptography defines reusable cryptographic capabilities. It has no
// protocol, network, authorization, or custody-storage responsibilities.
package cryptography

import (
	"fmt"
	"slices"
)

type KeyType string
type SchemeID string
type InputKind string

const (
	Secp256k1      KeyType   = "secp256k1"
	ECDSASecp256k1 SchemeID  = "ecdsa_secp256k1"
	Digest         InputKind = "digest"
	Message        InputKind = "message"
)

type PublicKey struct {
	Type  KeyType
	Bytes []byte
}

func (p PublicKey) Clone() PublicKey { return PublicKey{Type: p.Type, Bytes: slices.Clone(p.Bytes)} }

type Capability struct {
	Scheme SchemeID
	Input  InputKind
}

// Payload owns its bytes; neither custody nor formatters can mutate them.
type Payload struct {
	kind InputKind
	data []byte
}

func NewPayload(kind InputKind, data []byte) Payload {
	return Payload{kind: kind, data: slices.Clone(data)}
}
func (p Payload) Kind() InputKind { return p.kind }
func (p Payload) Bytes() []byte   { return slices.Clone(p.data) }

type Prepared struct {
	Payload Payload
	Format  func([]byte) (any, error)
}

// Scheme describes compatibility and verifies/canonicalizes a custody result.
// Verification returns a canonical signature (e.g. low-S recoverable ECDSA).
type Scheme struct {
	ID       SchemeID
	KeyTypes []KeyType
	Inputs   []InputKind
	Verify   func(PublicKey, Payload, []byte) ([]byte, error)
}

// Registry owns immutable copies of compatibility declarations.
type KeyDefinition struct {
	Type         KeyType
	Canonicalize func([]byte) (PublicKey, error)
}
type Registry struct {
	schemes map[SchemeID]Scheme
	keys    map[KeyType]KeyDefinition
}

func NewRegistry(schemes []Scheme) (*Registry, error) {
	return NewRegistryWithKeys(schemes, []KeyDefinition{{Type: Secp256k1, Canonicalize: CanonicalSecp256k1}, {Type: Ed25519Key, Canonicalize: CanonicalEd25519}})
}
func NewRegistryWithKeys(schemes []Scheme, keys []KeyDefinition) (*Registry, error) {
	r := &Registry{schemes: make(map[SchemeID]Scheme), keys: make(map[KeyType]KeyDefinition)}
	for _, key := range keys {
		if key.Type == "" || key.Canonicalize == nil {
			return nil, fmt.Errorf("incomplete key definition")
		}
		if _, exists := r.keys[key.Type]; exists {
			return nil, fmt.Errorf("duplicate key definition")
		}
		r.keys[key.Type] = key
	}
	for _, s := range schemes {
		if s.ID == "" || len(s.KeyTypes) == 0 || len(s.Inputs) == 0 || s.Verify == nil {
			return nil, fmt.Errorf("incomplete cryptographic scheme")
		}
		if _, ok := r.schemes[s.ID]; ok {
			return nil, fmt.Errorf("duplicate cryptographic scheme")
		}
		s.KeyTypes = slices.Clone(s.KeyTypes)
		s.Inputs = slices.Clone(s.Inputs)
		r.schemes[s.ID] = s
	}
	return r, nil
}
func (r *Registry) Scheme(id SchemeID) (Scheme, bool) {
	s, ok := r.schemes[id]
	s.KeyTypes = slices.Clone(s.KeyTypes)
	s.Inputs = slices.Clone(s.Inputs)
	return s, ok
}
func (r *Registry) Resolve(allowed []Capability, keyType KeyType, custody []Capability) (Capability, error) {
	matches := make(map[Capability]struct{})
	for _, c := range allowed {
		s, ok := r.Scheme(c.Scheme)
		if ok && slices.Contains(s.KeyTypes, keyType) && slices.Contains(s.Inputs, c.Input) && slices.Contains(custody, c) {
			matches[c] = struct{}{}
		}
	}
	if len(matches) != 1 {
		return Capability{}, fmt.Errorf("expected exactly one executable signing scheme, got %d", len(matches))
	}
	for c := range matches {
		return c, nil
	}
	panic("unreachable")
}
func (r *Registry) Verify(c Capability, pub PublicKey, payload Payload, raw []byte) ([]byte, error) {
	s, ok := r.Scheme(c.Scheme)
	if !ok || payload.Kind() != c.Input || !slices.Contains(s.Inputs, c.Input) || !slices.Contains(s.KeyTypes, pub.Type) {
		return nil, fmt.Errorf("incompatible signature verification capability")
	}
	return s.Verify(pub.Clone(), NewPayload(payload.Kind(), payload.Bytes()), slices.Clone(raw))
}
func Default() *Registry {
	r, err := NewRegistry(productionSchemes())
	if err != nil {
		panic(err)
	}
	return r
}

func (r *Registry) PublicKey(keyType KeyType, raw []byte) (PublicKey, error) {
	definition, ok := r.keys[keyType]
	if !ok {
		return PublicKey{}, fmt.Errorf("unsupported key type")
	}
	pub, err := definition.Canonicalize(slices.Clone(raw))
	if err != nil {
		return PublicKey{}, err
	}
	if pub.Type != keyType {
		return PublicKey{}, fmt.Errorf("key definition returned incompatible public key")
	}
	return pub.Clone(), nil
}
