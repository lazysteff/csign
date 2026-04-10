package faults

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWrapNilAndExistingError(t *testing.T) {
	require.NoError(t, Wrap(Invalid, nil))

	existing := New(NotFound, "missing")
	require.Same(t, existing, Wrap(Invalid, existing))
}

func TestNewAndNewf(t *testing.T) {
	err := New(Conflict, "duplicate")
	require.Equal(t, Conflict, KindOf(err))
	require.EqualError(t, err, "duplicate")

	err = Newf(PolicyDenied, "denied: %s", "cap")
	require.Equal(t, PolicyDenied, KindOf(err))
	require.EqualError(t, err, "denied: cap")
}

func TestKindOfReturnsInternalForUntypedErrors(t *testing.T) {
	require.Equal(t, Internal, KindOf(errors.New("boom")))
}
