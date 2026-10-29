package custody

import (
	"context"
	"fmt"

	"github.com/lazysteff/csign/v2/internal/cryptography"
	"github.com/lazysteff/csign/v2/internal/domain"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
)

type Resolver struct {
	External ExternalResolver
}

func (r Resolver) MaterialForKey(ctx context.Context, key domain.Key) (Material, error) {
	switch domain.NormalizeCustodyMode(key.CustodyMode) {
	case "", v1.CustodyModeMVP:
		privateKey, err := parsePrivateKeyHex(key.PrivateKeyHex)
		if err != nil {
			return nil, err
		}
		return localMaterial{privateKey: privateKey}, nil
	case v1.CustodyModePKCS11:
		if r.External == nil {
			return nil, fmt.Errorf("pkcs11 mode requested for key %q but no external signer resolver is configured", key.ID)
		}
		// Preserve the historical external callback's uncompressed public-key
		// representation while records and generalized custody remain canonical.
		key = key.Clone()
		if key.KeyType == cryptography.Secp256k1 {
			pub, err := CanonicalPublicKey(key)
			if err != nil {
				return nil, err
			}
			legacyPublic, err := cryptography.ECDSAPublicKey(pub)
			if err != nil {
				return nil, err
			}
			key.PublicKeyHex = PublicKeyHex(legacyPublic)
		}
		return r.External.ResolveExternal(ctx, key)
	default:
		return nil, fmt.Errorf("unsupported custody mode %q", key.CustodyMode)
	}
}
