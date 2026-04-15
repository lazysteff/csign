package keyid

import (
	"testing"

	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	t.Run("valid ids", func(t *testing.T) {
		for _, keyID := range []string{
			"a",
			"a/b",
			"gateway/tron/main/hot",
			"status/foo",
			"foo/status",
			"foo/status/bar",
		} {
			require.NoError(t, Validate(keyID), keyID)
		}
	})

	t.Run("invalid ids", func(t *testing.T) {
		cases := map[string]string{
			"":       "required",
			"/a":     "must not start",
			"a/":     "must not end",
			"a//b":   "empty path segments",
			".":      "'.' path segments",
			"..":     "'..' path segments",
			"a/./b":  "'.' path segments",
			"a/../b": "'..' path segments",
		}

		for keyID, msg := range cases {
			err := Validate(keyID)
			require.Error(t, err, keyID)
			require.Equal(t, faults.Invalid, faults.KindOf(err), keyID)
			require.Contains(t, err.Error(), msg, keyID)
		}
	})
}

func TestEscapePathEscapesPerSegment(t *testing.T) {
	escaped, err := EscapePath("orgs/123/signing team/%2F")
	require.NoError(t, err)
	require.Equal(t, "orgs/123/signing%20team/%252F", escaped)
}
