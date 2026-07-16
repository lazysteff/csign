package vaultbackend

import (
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/stretchr/testify/require"
)

func TestSigningRegistrationValidationFailsClosed(t *testing.T) {
	backend := New(nil)
	registrations := backend.routeRegistrations()

	t.Run("missing handler", func(t *testing.T) {
		changed := append([]pathRegistration(nil), registrations...)
		for index, registration := range changed {
			if registration.Signing {
				changed = append(changed[:index], changed[index+1:]...)
				break
			}
		}
		require.ErrorContains(t, validateRouteRegistrations(backend.catalog, changed), "has no signing handler")
	})

	t.Run("extra handler", func(t *testing.T) {
		changed := append([]pathRegistration(nil), registrations...)
		changed = append(changed, pathRegistration{
			PublicRoute: "v1/rogue/sign",
			Signing:     true,
			Path:        &framework.Path{Pattern: "v1/rogue/sign"},
		})
		require.ErrorContains(t, validateRouteRegistrations(backend.catalog, changed), "missing from the operation catalog")
	})

	t.Run("mismatched handler identity", func(t *testing.T) {
		changed := cloneRegistrations(registrations)
		for index := range changed {
			if changed[index].Signing {
				changed[index].Path.Pattern = "v1/mismatched/sign"
				break
			}
		}
		require.ErrorContains(t, validateRouteRegistrations(backend.catalog, changed), "uses pattern")
	})
}

func cloneRegistrations(registrations []pathRegistration) []pathRegistration {
	clone := make([]pathRegistration, len(registrations))
	for index, registration := range registrations {
		clone[index] = registration
		if registration.Path != nil {
			path := *registration.Path
			clone[index].Path = &path
		}
	}
	return clone
}
