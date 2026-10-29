package policy

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/lazysteff/csign/v2/internal/chain"
	"github.com/lazysteff/csign/v2/internal/domain"
	enc "github.com/lazysteff/csign/v2/internal/encoding"
	"github.com/lazysteff/csign/v2/internal/faults"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
)

func enforceTokenContractAllowlist(policy v1.Policy, chainFamily, contract string) error {
	if len(policy.AllowedTokenContracts) == 0 {
		return nil
	}
	normalized, err := chain.NormalizeAddress(chainFamily, contract)
	if err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	for _, allowed := range policy.AllowedTokenContracts {
		candidate, err := chain.NormalizeAddress(chainFamily, allowed)
		if err != nil {
			continue
		}
		if candidate == normalized {
			return nil
		}
	}
	return faults.New(faults.PolicyDenied, "token contract is not allowlisted")
}

func enforceSelectorAllowlist(policy v1.Policy, selector string) error {
	if len(policy.AllowedSelectors) == 0 {
		return nil
	}
	selector = domain.NormalizeSelector(selector)
	for _, allowed := range policy.AllowedSelectors {
		if domain.NormalizeSelector(allowed) == selector {
			return nil
		}
	}
	return faults.Newf(faults.PolicyDenied, "selector %q is not allowlisted", selector)
}

func selectorFromHexData(data string) (string, error) {
	raw, err := enc.DecodeHex(data)
	if err != nil {
		return "", err
	}
	if len(raw) < 4 {
		return "", fmt.Errorf("call data must include a 4-byte selector")
	}
	return strings.ToLower(hex.EncodeToString(raw[:4])), nil
}
