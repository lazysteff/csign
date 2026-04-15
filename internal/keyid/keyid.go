package keyid

import (
	"net/url"
	"strings"

	"github.com/chain-signer/chain-signer/internal/faults"
)

// Validate enforces the shared logical key_id contract on decoded values.
func Validate(keyID string) error {
	if keyID == "" {
		return faults.New(faults.Invalid, "key_id is required")
	}
	if strings.HasPrefix(keyID, "/") {
		return faults.New(faults.Invalid, "key_id must not start with '/'")
	}
	if strings.HasSuffix(keyID, "/") {
		return faults.New(faults.Invalid, "key_id must not end with '/'")
	}

	for _, segment := range strings.Split(keyID, "/") {
		switch segment {
		case "":
			return faults.New(faults.Invalid, "key_id must not contain empty path segments")
		case ".":
			return faults.New(faults.Invalid, "key_id must not contain '.' path segments")
		case "..":
			return faults.New(faults.Invalid, "key_id must not contain '..' path segments")
		}
	}

	return nil
}

// EscapePath validates a logical key_id and escapes each path segment separately.
func EscapePath(keyID string) (string, error) {
	if err := Validate(keyID); err != nil {
		return "", err
	}

	segments := strings.Split(keyID, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/"), nil
}
