package conformance_test

import (
	"context"
	"strings"
	"testing"

	"github.com/chain-signer/chain-signer/internal/vaultbackend"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const testEIP7702Delegate = "0x3333333333333333333333333333333333333333"

type advancedEVMFixture struct {
	ctx     context.Context
	backend *vaultbackend.Backend
	storage logical.Storage
	keyID   string
	signer  string
	chainID string
}

func newAdvancedEVMFixture(t *testing.T, keyID string, withPolicy bool) (advancedEVMFixture, map[string]interface{}) {
	t.Helper()
	ctx := context.Background()
	backend, storage := newTestBackend(t, nil)
	request := v1.CreateKeyRequest{
		KeyID:            keyID,
		ChainFamily:      v1.ChainFamilyEVM,
		CustodyMode:      v1.CustodyModeMVP,
		ImportPrivateKey: testPrivHex,
	}
	if withPolicy {
		request.Policy = advancedEVMPolicy()
	}
	created, raw := createKey(t, ctx, backend, storage, request)
	return advancedEVMFixture{
		ctx:     ctx,
		backend: backend,
		storage: storage,
		keyID:   keyID,
		signer:  strings.ToLower(created.SignerAddress),
		chainID: "11155111",
	}, raw
}

func (f advancedEVMFixture) base(requestID string) v1.EVMAdvancedSignRequestBase {
	return v1.EVMAdvancedSignRequestBase{
		EVMKeyRequestContext: f.keyContext(requestID),
		EVMSignerExpectation: v1.EVMSignerExpectation{
			ExpectedSignerAddress: f.signer,
			ChainID:               f.chainID,
		},
	}
}

func (f advancedEVMFixture) keyContext(requestID string) v1.EVMKeyRequestContext {
	return v1.EVMKeyRequestContext{
		EVMRequestContext: advancedEVMRequestContext(requestID),
		KeyID:             f.keyID,
	}
}

func advancedEVMRequestContext(requestID string) v1.EVMRequestContext {
	return v1.EVMRequestContext{
		ChainFamily: v1.ChainFamilyEVM,
		Network:     testEVMNetwork,
		RequestID:   requestID,
	}
}

func advancedEVMPolicy() v1.Policy {
	return v1.Policy{
		AllowedNetworks:      []string{testEVMNetwork},
		AllowedChainIDs:      []int64{testEVMChainID},
		MaxValue:             "100",
		MaxGasLimit:          500000,
		MaxFeePerGas:         "2000",
		MaxPriorityFeePerGas: "1000",
		AllowedTokenContracts: []string{
			testEVMContract,
		},
		AllowedSigningOperations: []string{
			v1.OperationEVMEIP712Typed,
			v1.OperationEVMERC4337UserOperation,
			v1.OperationEVMEIP7702Authorization,
			v1.OperationEVMEIP7702Transaction,
		},
		AllowedEIP712Schemas:          []string{v1.EIP712SchemaEIP2612Permit},
		AllowedERC4337Versions:        []string{v1.ERC4337ProtocolV09},
		AllowedEntryPoints:            []string{v1.ERC4337EntryPointV09},
		AllowedAccountImplementations: []string{v1.ERC4337AccountSimpleAccount},
		AllowedAccountSigningSchemas:  []string{v1.ERC4337SimpleAccountSigningSchema},
		AllowedEIP7702Delegates:       []string{testEIP7702Delegate},
		AllowedTransactionTypes:       []string{v1.EIP7702TransactionTypeV1},
		AllowedContractDestinations:   []string{testEVMRecipient},
		MaxAuthorizationListEntries:   1,
	}
}

func writeAdvanced[T any](t *testing.T, ctx context.Context, backend logical.Backend, storage logical.Storage, route string, payload any) T {
	t.Helper()
	request := logical.TestRequest(t, logical.UpdateOperation, route)
	request.Storage = storage
	request.Data = mustMap(t, payload)
	response, err := backend.HandleRequest(ctx, request)
	require.NoError(t, err)
	return decodeResponse[T](t, response)
}

func twoDigitHex(value uint8) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[value>>4], digits[value&0x0f]})
}
