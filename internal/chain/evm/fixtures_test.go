package evm

import (
	"context"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

const (
	advancedPrivateKey = "0x0000000000000000000000000000000000000000000000000000000000000001"
	advancedSigner     = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
)

func advancedPermitRequest() v1.EVMEIP712SignRequest {
	return v1.EVMEIP712SignRequest{
		EVMAdvancedSignRequestBase: v1.EVMAdvancedSignRequestBase{
			EVMKeyRequestContext: v1.EVMKeyRequestContext{
				EVMRequestContext: v1.EVMRequestContext{
					ChainFamily: v1.ChainFamilyEVM,
					Network:     "ethereum-mainnet",
					RequestID:   "permit-request",
				},
				KeyID: "advanced-key",
			},
			EVMSignerExpectation: v1.EVMSignerExpectation{
				ExpectedSignerAddress: advancedSigner,
				ChainID:               "1",
			},
		},
		EIP712PermitPayload: v1.EIP712PermitPayload{
			SchemaID:      v1.EIP712SchemaEIP2612Permit,
			SchemaVersion: v1.EIP712SchemaEIP2612PermitVersion,
			Domain: v1.EIP712Domain{
				Name:              "Token",
				Version:           "1",
				ChainID:           "1",
				VerifyingContract: "0x1111111111111111111111111111111111111111",
			},
			Message: v1.EIP2612PermitMessage{
				Owner:    advancedSigner,
				Spender:  "0x2222222222222222222222222222222222222222",
				Value:    "10",
				Nonce:    "0",
				Deadline: "100",
			},
		},
	}
}

func advancedUserOperationRequest() v1.EVMUserOperationSignRequest {
	return v1.EVMUserOperationSignRequest{
		EVMAdvancedSignRequestBase: v1.EVMAdvancedSignRequestBase{
			EVMKeyRequestContext: v1.EVMKeyRequestContext{
				EVMRequestContext: v1.EVMRequestContext{
					ChainFamily: v1.ChainFamilyEVM,
					Network:     "ethereum-mainnet",
					RequestID:   "user-operation-request",
				},
				KeyID: "advanced-key",
			},
			EVMSignerExpectation: v1.EVMSignerExpectation{
				ExpectedSignerAddress: advancedSigner,
				ChainID:               "1",
			},
		},
		ERC4337OperationDescriptor: v1.ERC4337OperationDescriptor{
			EntryPoint:                   v1.ERC4337EntryPointV09,
			ProtocolVersion:              v1.ERC4337ProtocolV09,
			AccountImplementation:        v1.ERC4337AccountSimpleAccount,
			AccountImplementationVersion: v1.ERC4337AccountSimpleAccountVersion,
			AccountSigningSchema:         v1.ERC4337SimpleAccountSigningSchema,
		},
		UserOperation: v1.ERC4337UserOperationV09{
			Sender:               "0x3333333333333333333333333333333333333333",
			Nonce:                "7",
			CallData:             "0xaabb",
			CallGasLimit:         "100000",
			VerificationGasLimit: "200000",
			PreVerificationGas:   "50000",
			MaxFeePerGas:         "100",
			MaxPriorityFeePerGas: "2",
		},
	}
}

func mustAdvancedMaterial(t *testing.T) custody.Material {
	t.Helper()
	material, err := custody.Resolver{}.MaterialForKey(context.Background(), domain.Key{
		ID:            "advanced-key",
		CustodyMode:   v1.CustodyModeMVP,
		PrivateKeyHex: advancedPrivateKey,
	})
	require.NoError(t, err)
	return material
}
