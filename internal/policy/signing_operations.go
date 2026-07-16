package policy

import (
	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/signingops"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

// ValidateStoredPolicy validates policy invariants required before persistence.
// An empty operation allowlist is valid and intentionally denies all signing.
func ValidateStoredPolicy(catalog *signingops.Catalog, value v1.Policy) error {
	if catalog == nil {
		return faults.New(faults.Internal, "signing operation catalog is required")
	}
	if err := catalog.ValidateAllowlist(value.AllowedSigningOperations); err != nil {
		return faults.Newf(faults.Invalid, "invalid allowed_signing_operations: %v", err)
	}
	return nil
}
