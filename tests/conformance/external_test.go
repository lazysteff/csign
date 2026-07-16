package conformance_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestConformance_PKCS11StyleExternalSigner(t *testing.T) {
	ctx := context.Background()
	privateKey := mustPrivateKey(t, testPrivHex)
	resolver := staticResolver{
		materials: map[string]custody.Material{
			"hsm-1": custody.ExternalMaterial{
				Pub: &privateKey.PublicKey,
				SignFunc: func(_ context.Context, digest []byte) ([]byte, error) {
					r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
					if err != nil {
						return nil, err
					}
					return sig64(r, s), nil
				},
			},
		},
	}
	backend, storage := newTestBackend(t, resolver)

	created, raw := createKey(t, ctx, backend, storage, v1.CreateKeyRequest{
		KeyID:             "evm-pkcs11",
		ChainFamily:       v1.ChainFamilyEVM,
		CustodyMode:       v1.CustodyModePKCS11,
		PublicKeyHex:      enc.EncodeHex(ethcrypto.FromECDSAPub(&privateKey.PublicKey)),
		ExternalSignerRef: "hsm-1",
		Policy: v1.Policy{
			AllowedSigningOperations: []string{v1.OperationEVMTransferEIP1559},
		},
	})
	require.NotContains(t, raw, "private_key_hex")

	signed := signEVMEIP1559(t, ctx, backend, storage, v1.EVMEIP1559TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID: "evm-pkcs11", ChainFamily: v1.ChainFamilyEVM, Network: testEVMNetwork,
			RequestID: testRequestID, SourceAddress: created.SignerAddress,
		},
		ChainID: testEVMChainID, To: testEVMRecipient, Value: "1", Nonce: 7,
		GasLimit: 21000, MaxFeePerGas: "1000", MaxPriorityFeePerGas: "100",
	})
	verification := verifyPayload(t, ctx, backend, storage, v1.VerifyRequest{
		ChainFamily: v1.ChainFamilyEVM, Network: testEVMNetwork,
		Operation: v1.OperationEVMTransferEIP1559, SignedPayload: signed.SignedPayload,
		ExpectedSignerAddress: created.SignerAddress,
	})
	require.True(t, verification.MatchesExpected)
}
