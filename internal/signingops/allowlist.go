package signingops

import "fmt"

// ValidateAllowlist accepts nil and empty lists as valid deny-all policies.
// Non-empty entries must be exact, unique canonical operation identifiers.
func (c *Catalog) ValidateAllowlist(allowed []string) error {
	if c == nil {
		return fmt.Errorf("%w: catalog is unavailable", ErrUnknownOperation)
	}
	seen := make(map[string]struct{}, len(allowed))
	for _, operation := range allowed {
		if _, ok := c.operations[operation]; !ok {
			return fmt.Errorf("%w %q", ErrUnknownOperation, operation)
		}
		if _, ok := seen[operation]; ok {
			return fmt.Errorf("%w %q", ErrDuplicateOperation, operation)
		}
		seen[operation] = struct{}{}
	}
	return nil
}

func (c *Catalog) Allows(allowed []string, operation string) bool {
	for _, candidate := range allowed {
		if candidate == operation {
			return true
		}
	}
	return false
}
