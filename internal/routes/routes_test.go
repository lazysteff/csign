package routes_test

import (
	"testing"

	"github.com/chain-signer/chain-signer/internal/routes"
	"github.com/stretchr/testify/require"
)

func TestKeyHelpers(t *testing.T) {
	readPath, err := routes.Key("orgs/123/key-1")
	require.NoError(t, err)
	require.Equal(t, "v1/keys/orgs/123/key-1", readPath)

	statusPath, err := routes.KeyStatus("orgs/123/key-1")
	require.NoError(t, err)
	require.Equal(t, "v1/key-status/orgs/123/key-1", statusPath)
}

func TestKeyHelpersRejectInvalidKeyIDs(t *testing.T) {
	_, err := routes.Key("a//b")
	require.ErrorContains(t, err, "key_id")

	_, err = routes.KeyStatus("/key-1")
	require.ErrorContains(t, err, "key_id")
}
