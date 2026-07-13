package advancedregistry

import (
	"fmt"
	"math/big"

	"github.com/chain-signer/chain-signer/internal/chain/evm/eip712"
	"github.com/chain-signer/chain-signer/internal/chain/evm/eip7702"
	"github.com/chain-signer/chain-signer/internal/chain/evm/erc4337"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
)

type EIP712Schema struct {
	ID                string
	Version           string
	PrimaryType       string
	SignatureEncoding string
	HashPermit        func(eip712.Domain, eip712.PermitMessage) (eip712.Hashes, error)
}

type AccountAdapter struct {
	ID                string
	Version           string
	ProtocolVersion   string
	SigningSchema     string
	SignatureEncoding string
	HashUserOperation func(erc4337.UserOperation, common.Address, *big.Int, *common.Address) (common.Hash, error)
}

type Registry struct {
	eip712Schemas        map[string]EIP712Schema
	accountAdapters      map[string]AccountAdapter
	authorizationSchemas map[string]struct{}
	transactionTypes     map[string]uint8
}

var defaultRegistry = newDefault()

func Default() *Registry {
	return &defaultRegistry
}

func newDefault() Registry {
	schema := EIP712Schema{
		ID:                eip712.SchemaID,
		Version:           eip712.SchemaVersion,
		PrimaryType:       eip712.PrimaryType,
		SignatureEncoding: eip712.SignatureEncoding,
		HashPermit:        eip712.HashPermit,
	}
	account := AccountAdapter{
		ID:                erc4337.SimpleAccountImplementation,
		Version:           erc4337.SimpleAccountImplementationVersion,
		ProtocolVersion:   erc4337.ProtocolID,
		SigningSchema:     erc4337.SimpleAccountSigningSchema,
		SignatureEncoding: erc4337.SimpleAccountSignatureEncoding,
		HashUserOperation: func(operation erc4337.UserOperation, entryPoint common.Address, chainID *big.Int, delegate *common.Address) (common.Hash, error) {
			return operation.UserOperationHash(entryPoint, chainID, delegate)
		},
	}
	return Registry{
		eip712Schemas:        map[string]EIP712Schema{schemaKey(schema.ID, schema.Version): schema},
		accountAdapters:      map[string]AccountAdapter{accountKey(account.ProtocolVersion, account.ID, account.Version, account.SigningSchema): account},
		authorizationSchemas: map[string]struct{}{eip7702.AuthorizationSchemaV1: {}},
		transactionTypes:     map[string]uint8{v1.EIP7702TransactionTypeV1: eip7702.TransactionType},
	}
}

func (r Registry) EIP712Schema(id, version string) (EIP712Schema, error) {
	schema, ok := r.eip712Schemas[schemaKey(id, version)]
	if !ok {
		return EIP712Schema{}, &UnsupportedError{
			Dimension: UnsupportedEIP712Schema,
			Message:   fmt.Sprintf("unsupported EIP-712 schema %q version %q", id, version),
		}
	}
	return schema, nil
}

func (r Registry) AccountAdapter(protocolVersion, id, version, signingSchema string) (AccountAdapter, error) {
	adapter, ok := r.accountAdapters[accountKey(protocolVersion, id, version, signingSchema)]
	if !ok {
		if !r.hasAccountImplementation(id, version) {
			return AccountAdapter{}, &UnsupportedError{
				Dimension: UnsupportedAccountImplementation,
				Message:   fmt.Sprintf("unsupported account implementation %q version %q", id, version),
			}
		}
		if !r.hasAccountProtocol(id, version, protocolVersion) {
			return AccountAdapter{}, &UnsupportedError{
				Dimension: UnsupportedERC4337Protocol,
				Message:   fmt.Sprintf("unsupported ERC-4337 protocol version %q", protocolVersion),
			}
		}
		return AccountAdapter{}, &UnsupportedError{
			Dimension: UnsupportedAccountSigningSchema,
			Message:   fmt.Sprintf("unsupported account signing schema %q", signingSchema),
		}
	}
	return adapter, nil
}

func (r Registry) AuthorizationSchema(id string) error {
	if _, ok := r.authorizationSchemas[id]; !ok {
		return fmt.Errorf("unsupported EIP-7702 authorization schema %q", id)
	}
	return nil
}

func (r Registry) hasAccountImplementation(id, version string) bool {
	for _, adapter := range r.accountAdapters {
		if adapter.ID == id && adapter.Version == version {
			return true
		}
	}
	return false
}

func (r Registry) hasAccountProtocol(id, version, protocol string) bool {
	for _, adapter := range r.accountAdapters {
		if adapter.ID == id && adapter.Version == version && adapter.ProtocolVersion == protocol {
			return true
		}
	}
	return false
}

func schemaKey(id, version string) string {
	return id + "\x00" + version
}

func accountKey(protocol, id, version, signingSchema string) string {
	return protocol + "\x00" + id + "\x00" + version + "\x00" + signingSchema
}
