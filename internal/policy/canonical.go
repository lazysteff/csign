package policy

import (
	"fmt"
	"maps"
	"strings"

	"github.com/chain-signer/chain-signer/internal/chain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
)

func equalStringSets(field string, left, right []string, normalize func(string) (string, error)) (bool, error) {
	leftSet, err := canonicalStringSet(field, left, normalize)
	if err != nil {
		return false, fmt.Errorf("expected %s: %w", field, err)
	}
	rightSet, err := canonicalStringSet(field, right, normalize)
	if err != nil {
		return false, fmt.Errorf("actual %s: %w", field, err)
	}
	return maps.Equal(leftSet, rightSet), nil
}

func canonicalStringSet(field string, values []string, normalize func(string) (string, error)) (map[string]struct{}, error) {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		canonical, err := normalize(value)
		if err != nil {
			return nil, err
		}
		if _, exists := out[canonical]; exists {
			return nil, fmt.Errorf("%s contains duplicate value %q", field, value)
		}
		out[canonical] = struct{}{}
	}
	return out, nil
}

func exactValue(value string) (string, error) {
	return value, nil
}

func normalizeAddress(chainFamily string) func(string) (string, error) {
	return func(value string) (string, error) {
		return chain.NormalizeAddress(chainFamily, value)
	}
}

func normalizeSelector(value string) (string, error) {
	decoded, err := enc.DecodeHex(value)
	if err != nil || len(decoded) != 4 {
		return "", fmt.Errorf("selector %q must contain exactly four hexadecimal bytes", value)
	}
	return enc.EncodeHex(decoded), nil
}

func equalInt64Sets(field string, left, right []int64) (bool, error) {
	leftSet, err := canonicalInt64Set(field, left)
	if err != nil {
		return false, fmt.Errorf("expected %s: %w", field, err)
	}
	rightSet, err := canonicalInt64Set(field, right)
	if err != nil {
		return false, fmt.Errorf("actual %s: %w", field, err)
	}
	return maps.Equal(leftSet, rightSet), nil
}

func canonicalInt64Set(field string, values []int64) (map[int64]struct{}, error) {
	out := make(map[int64]struct{}, len(values))
	for _, value := range values {
		if _, exists := out[value]; exists {
			return nil, fmt.Errorf("%s contains duplicate value %d", field, value)
		}
		out[value] = struct{}{}
	}
	return out, nil
}

func equalNumericCaps(field, left, right string) (bool, error) {
	leftOmitted := strings.TrimSpace(left) == ""
	rightOmitted := strings.TrimSpace(right) == ""
	if leftOmitted || rightOmitted {
		return leftOmitted == rightOmitted, nil
	}
	leftValue, err := enc.ParseEVMUint256(left)
	if err != nil {
		return false, fmt.Errorf("expected %s: %w", field, err)
	}
	rightValue, err := enc.ParseEVMUint256(right)
	if err != nil {
		return false, fmt.Errorf("actual %s: %w", field, err)
	}
	return leftValue.Cmp(rightValue) == 0, nil
}
