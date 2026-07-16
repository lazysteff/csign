package conformance_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestConformance_ExternalAdvancedEVMOperations(t *testing.T) {
	ctx := context.Background()
	privateKey := mustPrivateKey(t, testPrivHex)
	resolver := staticResolver{materials: map[string]custody.Material{
		"advanced-hsm": custody.ExternalMaterial{
			Pub: &privateKey.PublicKey,
			SignFunc: func(_ context.Context, digest []byte) ([]byte, error) {
				r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
				if err != nil {
					return nil, err
				}
				return sig64(r, s), nil
			},
		},
	}}
	backend, storage := newTestBackend(t, resolver)
	created, _ := createKey(t, ctx, backend, storage, v1.CreateKeyRequest{
		KeyID:             "evm-advanced-external",
		ChainFamily:       v1.ChainFamilyEVM,
		CustodyMode:       v1.CustodyModePKCS11,
		PublicKeyHex:      enc.EncodeHex(ethcrypto.FromECDSAPub(&privateKey.PublicKey)),
		ExternalSignerRef: "advanced-hsm",
		Policy:            advancedEVMPolicy(),
	})
	signer := strings.ToLower(created.SignerAddress)
	chainID := "11155111"
	fixture := advancedEVMFixture{ctx: ctx, backend: backend, storage: storage, keyID: "evm-advanced-external", signer: signer, chainID: chainID}

	permit := writeAdvanced[v1.EVMEIP712SignResponse](t, ctx, backend, storage, routes.EVMEIP712Sign, v1.EVMEIP712SignRequest{
		EVMAdvancedSignRequestBase: fixture.base("external-permit"),
		EIP712RegisteredPayload:    conformancePermit(signer, chainID),
	})
	require.Equal(t, signer, permit.SignerAddress)

	userOperation := writeAdvanced[v1.EVMUserOperationSignResponse](t, ctx, backend, storage, routes.EVMERC4337UserOperationSign, v1.EVMUserOperationSignRequest{
		EVMAdvancedSignRequestBase: fixture.base("external-user-operation"),
		ERC4337OperationDescriptor: v1.ERC4337OperationDescriptor{
			EntryPoint:                   v1.ERC4337EntryPointV09,
			ProtocolVersion:              v1.ERC4337ProtocolV09,
			AccountImplementation:        v1.ERC4337AccountSimpleAccount,
			AccountImplementationVersion: v1.ERC4337AccountSimpleAccountVersion,
			AccountSigningSchema:         v1.ERC4337SimpleAccountSigningSchema,
		},
		UserOperation: v1.ERC4337UserOperationV09{
			Sender: testEVMRecipient, Nonce: "0", CallData: "0x", CallGasLimit: "100000",
			VerificationGasLimit: "150000", PreVerificationGas: "21000", MaxFeePerGas: "1000", MaxPriorityFeePerGas: "100",
		},
	})
	require.Equal(t, signer, userOperation.SignerAddress)

	authorization := writeAdvanced[v1.EVMEIP7702AuthorizationSignResponse](t, ctx, backend, storage, routes.EVMEIP7702AuthorizationSign, v1.EVMEIP7702AuthorizationSignRequest{
		EIP7702Authorization: v1.EIP7702Authorization{ChainID: chainID, Address: testEIP7702Delegate, Nonce: "0"},
		EVMKeyRequestContext: fixture.keyContext("external-authorization"),
		AuthorityAddress:     signer,
		AuthorizationSchema:  v1.EIP7702AuthorizationSchemaV1,
	})
	require.Equal(t, signer, authorization.AuthorityAddress)

	type4 := writeAdvanced[v1.EVMEIP7702TransactionSignResponse](t, ctx, backend, storage, routes.EVMEIP7702TransactionSign, v1.EVMEIP7702TransactionSignRequest{
		EVMKeyRequestContext: fixture.keyContext("external-type4"),
		EIP7702TransactionFields: v1.EIP7702TransactionFields{
			ChainID: chainID, Nonce: "1", To: testEVMRecipient, Value: "1", GasLimit: "150000",
			MaxFeePerGas: "1000", MaxPriorityFeePerGas: "100", Data: "0x", AccessList: []v1.EVMAccessTuple{},
		},
		SourceAddress: signer,
		AuthorizationList: []v1.EIP7702SignedAuthorization{{
			EIP7702Authorization: authorization.EIP7702Authorization,
			YParity:              authorization.YParity,
			R:                    authorization.R,
			S:                    authorization.S,
		}},
	})
	require.Equal(t, signer, type4.SignerAddress)
	require.True(t, strings.HasPrefix(type4.SignedPayload, "0x04"))
}
