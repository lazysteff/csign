package policy

import (
	"github.com/lazysteff/csign/v2/internal/faults"
	"github.com/lazysteff/csign/v2/internal/signingops"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
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
