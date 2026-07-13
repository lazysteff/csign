package custody

import (
	"context"
	"fmt"

	"github.com/chain-signer/chain-signer/internal/domain"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
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
		return r.External.ResolveExternal(ctx, key)
	default:
		return nil, fmt.Errorf("unsupported custody mode %q", key.CustodyMode)
	}
}
