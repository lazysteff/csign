package vaultbackend

import (
	"fmt"
	"sort"

	"github.com/chain-signer/chain-signer/internal/routes"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type pathRegistration struct {
	PublicRoute      string
	SigningOperation string
	Path             *framework.Path
}

func (b *Backend) routeRegistrations() ([]pathRegistration, error) {
	keyID := map[string]*framework.FieldSchema{
		"key_id": {Type: framework.TypeString},
	}

	registrations := []pathRegistration{
		{
			PublicRoute: routes.Version,
			Path: &framework.Path{
				Pattern:             routes.Version + `/?`,
				TakesArbitraryInput: true,
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: b.handleVersion,
						Summary:  "Read API version and structured protocol capabilities.",
					},
				},
			},
		},
		{
			PublicRoute: routes.Keys,
			Path: &framework.Path{
				Pattern:             routes.Keys + `/?`,
				TakesArbitraryInput: true,
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: b.handleCreateKey,
						Summary:  "Create or import a chain-bound signing key.",
					},
					logical.ListOperation: &framework.PathOperation{
						Callback: b.handleListKeys,
						Summary:  "List configured key IDs.",
					},
				},
			},
		},
		{
			PublicRoute: routes.KeyStatusPath,
			Path: &framework.Path{
				Pattern:             routes.KeyStatusRoot + `/` + framework.MatchAllRegex("key_id"),
				Fields:              keyID,
				TakesArbitraryInput: true,
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: b.handleUpdateKeyStatus,
						Summary:  "Enable or disable a key.",
					},
				},
			},
		},
		{
			PublicRoute: routes.KeyPolicyPath,
			Path: &framework.Path{
				Pattern:             routes.KeyPolicyRoot + `/` + framework.MatchAllRegex("key_id"),
				Fields:              keyID,
				TakesArbitraryInput: true,
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: b.handleUpdateKeyPolicy,
						Summary:  "Replace the policy attached to a signing key.",
					},
				},
			},
		},
		{
			PublicRoute: routes.KeyPath,
			Path: &framework.Path{
				Pattern:             routes.Keys + `/` + framework.MatchAllRegex("key_id"),
				Fields:              keyID,
				TakesArbitraryInput: true,
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: b.handleReadKey,
						Summary:  "Read key metadata.",
					},
				},
			},
		},
		{
			PublicRoute: routes.Verify,
			Path: &framework.Path{
				Pattern:             routes.Verify,
				TakesArbitraryInput: true,
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: b.handleVerify,
						Summary:  "Verify a signed payload and expected signer metadata.",
					},
				},
			},
		},
		{
			PublicRoute: routes.Recover,
			Path: &framework.Path{
				Pattern:             routes.Recover,
				TakesArbitraryInput: true,
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: b.handleRecover,
						Summary:  "Recover signer metadata from a signed payload.",
					},
				},
			},
		},
		{
			PublicRoute: routes.EVMEIP712Verify,
			Path:        inspectionPath(routes.EVMEIP712Verify, "Verify a constrained EIP-712 signature.", b.handleVerifyEVMEIP712),
		},
		{
			PublicRoute: routes.EVMERC4337UserOperationVerify,
			Path:        inspectionPath(routes.EVMERC4337UserOperationVerify, "Verify an ERC-4337 account signature.", b.handleVerifyEVMUserOperation),
		},
		{
			PublicRoute: routes.EVMEIP7702AuthorizationVerify,
			Path:        inspectionPath(routes.EVMEIP7702AuthorizationVerify, "Verify an EIP-7702 authorization tuple.", b.handleVerifyEVMEIP7702Authorization),
		},
		{
			PublicRoute: routes.EVMEIP7702TransactionRecover,
			Path:        inspectionPath(routes.EVMEIP7702TransactionRecover, "Recover and decode an EIP-7702 type-4 transaction.", b.handleRecoverEVMEIP7702Transaction),
		},
	}

	for _, route := range b.registry.Routes() {
		operation, ok := b.catalog.OperationForRoute(route)
		if !ok {
			return nil, fmt.Errorf("signing route %q is missing from the operation catalog", route)
		}
		registrations = append(registrations, pathRegistration{
			PublicRoute:      route,
			SigningOperation: operation,
			Path:             b.signPath(route),
		})
	}

	return registrations, nil
}

func registeredPaths(registrations []pathRegistration) []*framework.Path {
	paths := make([]*framework.Path, 0, len(registrations))
	for _, registration := range registrations {
		paths = append(paths, registration.Path)
	}
	return paths
}

func registeredPublicRoutes(registrations []pathRegistration) []string {
	routes := make([]string, 0, len(registrations))
	for _, registration := range registrations {
		if registration.PublicRoute == "" {
			continue
		}
		routes = append(routes, registration.PublicRoute)
	}
	sort.Strings(routes)
	return routes
}

func (b *Backend) signPath(route string) *framework.Path {
	return &framework.Path{
		Pattern:             route,
		TakesArbitraryInput: true,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleSign(route),
				Summary:  "Handle a typed signing request.",
			},
		},
	}
}

func inspectionPath(route, summary string, callback framework.OperationFunc) *framework.Path {
	return &framework.Path{
		Pattern:             route,
		TakesArbitraryInput: true,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: callback,
				Summary:  summary,
			},
		},
	}
}
