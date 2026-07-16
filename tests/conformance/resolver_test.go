package conformance_test

import (
	"context"
	"errors"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
)

type staticResolver struct {
	materials map[string]custody.Material
	calls     *int
}

func (r staticResolver) ResolveExternal(_ context.Context, key domain.Key) (custody.Material, error) {
	if r.calls != nil {
		(*r.calls)++
	}
	material, ok := r.materials[key.ExternalSignerRef]
	if !ok {
		return nil, errors.New("external signer not found")
	}
	return material, nil
}
