package vaultbackend

import (
	"context"

	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedregistry"
	"github.com/chain-signer/chain-signer/internal/version"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *Backend) handleVersion(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	schemas, protocols, accounts, signingSchemas, authorizationSchemas, transactionTypes := advancedregistry.Default().Capabilities()
	return response(v1.VersionResponse{
		APIVersion:                           v1.APIVersion,
		BuildVersion:                         version.Version,
		SupportedRoutes:                      registeredPublicRoutes(b.routes),
		SupportedSigningOperations:           b.registry.OperationCapabilities(),
		SupportedEIP712Schemas:               schemas,
		SupportedERC4337ProtocolVersions:     protocols,
		SupportedAccountImplementations:      accounts,
		SupportedAccountSigningSchemas:       signingSchemas,
		SupportedEIP7702AuthorizationSchemas: authorizationSchemas,
		SupportedEIP7702TransactionTypes:     transactionTypes,
		SupportedTRONMemoCapabilities: []v1.TRONMemoCapability{{
			Encoding:            v1.TRONMemoEncodingHex,
			MaxTransactionBytes: v1.TRONMaxTransactionBytes,
			SigningOperations:   []string{v1.OperationTRXTransfer, v1.OperationTRC20Transfer},
		}},
	}), nil
}
