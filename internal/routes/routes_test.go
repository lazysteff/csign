package routes_test

import (
	"testing"

	"github.com/chain-signer/chain-signer/internal/routes"
	"github.com/stretchr/testify/require"
)

func TestKeyHelpers(t *testing.T) {
	require.Equal(t, "v1/keys/key-1", routes.Key("key-1"))
	require.Equal(t, "v1/keys/key-1/status", routes.KeyStatus("key-1"))
}
