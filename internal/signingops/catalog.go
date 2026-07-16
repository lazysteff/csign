package signingops

import (
	"errors"
	"fmt"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

var (
	ErrUnknownRoute       = errors.New("unknown signing route")
	ErrDuplicateRoute     = errors.New("duplicate signing route")
	ErrUnknownOperation   = errors.New("unknown signing operation")
	ErrDuplicateOperation = errors.New("duplicate signing operation")
	ErrRouteMismatch      = errors.New("signing route operation mismatch")
)

// Catalog is an immutable signing-operation registry. Construction copies all
// caller-owned state and every accessor returns a copy, so concurrent readers
// cannot mutate or observe changing registry contents.
type Catalog struct {
	entries    []v1.SigningOperationCapability
	byRoute    map[string]string
	operations map[string]struct{}
}

func New(entries []v1.SigningOperationCapability) (*Catalog, error) {
	catalog := &Catalog{
		entries:    append([]v1.SigningOperationCapability(nil), entries...),
		byRoute:    make(map[string]string, len(entries)),
		operations: make(map[string]struct{}, len(entries)),
	}
	for _, entry := range catalog.entries {
		if entry.Route == "" {
			return nil, fmt.Errorf("%w: empty route", ErrUnknownRoute)
		}
		if entry.Operation == "" {
			return nil, fmt.Errorf("%w: route %q has an empty operation", ErrUnknownOperation, entry.Route)
		}
		if _, exists := catalog.byRoute[entry.Route]; exists {
			return nil, fmt.Errorf("%w %q", ErrDuplicateRoute, entry.Route)
		}
		if _, exists := catalog.operations[entry.Operation]; exists {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateOperation, entry.Operation)
		}
		catalog.byRoute[entry.Route] = entry.Operation
		catalog.operations[entry.Operation] = struct{}{}
	}
	return catalog, nil
}

func MustNew(entries []v1.SigningOperationCapability) *Catalog {
	catalog, err := New(entries)
	if err != nil {
		panic(err)
	}
	return catalog
}

func (c *Catalog) Entries() []v1.SigningOperationCapability {
	if c == nil {
		return nil
	}
	return append([]v1.SigningOperationCapability(nil), c.entries...)
}

func (c *Catalog) OperationForRoute(route string) (string, bool) {
	if c == nil {
		return "", false
	}
	operation, ok := c.byRoute[route]
	return operation, ok
}

func (c *Catalog) ValidateBinding(route, operation string) error {
	expected, ok := c.OperationForRoute(route)
	if !ok {
		return fmt.Errorf("%w %q", ErrUnknownRoute, route)
	}
	if operation != expected {
		return fmt.Errorf("%w: route %q requires %q, got %q", ErrRouteMismatch, route, expected, operation)
	}
	return nil
}
