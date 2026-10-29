package conformance_test

import (
	"context"
	"errors"

	"github.com/lazysteff/csign/v2/internal/custody"
	"github.com/lazysteff/csign/v2/internal/domain"
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
