package advancedregistry

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/chain-signer/chain-signer/internal/chain/evm/eip712"
	"github.com/chain-signer/chain-signer/internal/chain/evm/eip7702"
	"github.com/chain-signer/chain-signer/internal/chain/evm/erc4337"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
)

type EIP712Schema struct {
	ID                string
	Version           string
	PrimaryType       string
	SignatureEncoding string
	DefinitionHash    string
	HashMessage       func(eip712.Domain, json.RawMessage) (eip712.Hashes, error)
	ValidateSigner    func(common.Address, json.RawMessage) error
	ValidatePolicy    func(v1.Policy, json.RawMessage) error
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
	permitSchema := EIP712Schema{
		ID:                eip712.SchemaID,
		Version:           eip712.SchemaVersion,
		PrimaryType:       eip712.PrimaryType,
		SignatureEncoding: eip712.SignatureEncoding,
		DefinitionHash:    eip712.PermitDefinitionHash(),
		HashMessage:       eip712.HashPermitRaw,
		ValidateSigner:    eip712.ValidatePermitSigner,
	}
	approvalSchema := EIP712Schema{
		ID:                eip712.VerifyingPaymasterApprovalSchemaID,
		Version:           eip712.VerifyingPaymasterApprovalSchemaVersion,
		PrimaryType:       eip712.VerifyingPaymasterApprovalPrimaryType,
		SignatureEncoding: eip712.VerifyingPaymasterApprovalSignatureFormat,
		DefinitionHash:    eip712.VerifyingPaymasterApprovalDefinitionHash(),
		HashMessage:       eip712.HashVerifyingPaymasterApprovalRaw,
		ValidateSigner:    func(common.Address, json.RawMessage) error { return nil },
		ValidatePolicy:    eip712.ValidateVerifyingPaymasterApprovalPolicy,
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
	schemas := make(map[string]EIP712Schema, 2)
	mustRegisterEIP712Schema(schemas, permitSchema)
	mustRegisterEIP712Schema(schemas, approvalSchema)
	return Registry{
		eip712Schemas:        schemas,
		accountAdapters:      map[string]AccountAdapter{accountKey(account.ProtocolVersion, account.ID, account.Version, account.SigningSchema): account},
		authorizationSchemas: map[string]struct{}{eip7702.AuthorizationSchemaV1: {}},
		transactionTypes:     map[string]uint8{v1.EIP7702TransactionTypeV1: eip7702.TransactionType},
	}
}

func registerEIP712Schema(schemas map[string]EIP712Schema, schema EIP712Schema) error {
	if schema.ID == "" || schema.Version == "" || schema.PrimaryType == "" || schema.SignatureEncoding == "" || schema.DefinitionHash == "" || schema.HashMessage == nil || schema.ValidateSigner == nil {
		return faults.New(faults.Invalid, "registered EIP-712 schema is incomplete")
	}
	key := schemaKey(schema.ID, schema.Version)
	if existing, ok := schemas[key]; ok {
		if existing.DefinitionHash != schema.DefinitionHash || existing.PrimaryType != schema.PrimaryType || existing.SignatureEncoding != schema.SignatureEncoding {
			return faults.Newf(faults.Conflict, "EIP-712 schema %q version %q is already registered with a different immutable definition", schema.ID, schema.Version)
		}
		return faults.Newf(faults.Conflict, "EIP-712 schema %q version %q is already registered", schema.ID, schema.Version)
	}
	schemas[key] = schema
	return nil
}

func mustRegisterEIP712Schema(schemas map[string]EIP712Schema, schema EIP712Schema) {
	if err := registerEIP712Schema(schemas, schema); err != nil {
		panic(err)
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
