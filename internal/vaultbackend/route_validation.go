package vaultbackend

import (
	"errors"
	"fmt"

	"github.com/chain-signer/chain-signer/internal/signingops"
)

func validateRouteRegistrations(catalog *signingops.Catalog, registrations []pathRegistration) error {
	if catalog == nil {
		return errors.New("signing operation catalog is required")
	}

	publicRoutes := make(map[string]struct{}, len(registrations))
	patterns := make(map[string]struct{}, len(registrations))
	signingRoutes := make(map[string]struct{}, len(catalog.Entries()))
	for _, registration := range registrations {
		if registration.PublicRoute == "" || registration.Path == nil || registration.Path.Pattern == "" {
			return errors.New("route registration is incomplete")
		}
		if _, exists := publicRoutes[registration.PublicRoute]; exists {
			return fmt.Errorf("duplicate public route %q", registration.PublicRoute)
		}
		publicRoutes[registration.PublicRoute] = struct{}{}

		if _, exists := patterns[registration.Path.Pattern]; exists {
			return fmt.Errorf("duplicate route pattern %q", registration.Path.Pattern)
		}
		patterns[registration.Path.Pattern] = struct{}{}

		if !registration.Signing {
			continue
		}
		if registration.PublicRoute != registration.Path.Pattern {
			return fmt.Errorf("signing route %q uses pattern %q", registration.PublicRoute, registration.Path.Pattern)
		}
		if _, ok := catalog.OperationForRoute(registration.PublicRoute); !ok {
			return fmt.Errorf("signing route %q is missing from the operation catalog", registration.PublicRoute)
		}
		signingRoutes[registration.PublicRoute] = struct{}{}
	}

	entries := catalog.Entries()
	for _, entry := range entries {
		if _, ok := signingRoutes[entry.Route]; !ok {
			return fmt.Errorf("operation catalog route %q has no signing handler", entry.Route)
		}
	}
	if len(signingRoutes) != len(entries) {
		return fmt.Errorf(
			"operation catalog has %d routes but handler registry has %d signing routes",
			len(entries),
			len(signingRoutes),
		)
	}
	return nil
}
