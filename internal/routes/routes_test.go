package routes

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyHelpers(t *testing.T) {
	require.Equal(t, "v1/keys/key-1", Key("key-1"))
	require.Equal(t, "v1/keys/key-1/status", KeyStatus("key-1"))
}
