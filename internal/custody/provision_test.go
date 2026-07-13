package custody

import (
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestProvisionCreateRequest(t *testing.T) {
	provisioned, err := ProvisionCreateRequest(v1.CreateKeyRequest{
		ChainFamily:      v1.ChainFamilyEVM,
		CustodyMode:      v1.CustodyModeMVP,
		ImportPrivateKey: testPrivHex,
	})
	require.NoError(t, err)
	require.Equal(t, v1.CustodyModeMVP, provisioned.CustodyMode)
	require.NotEmpty(t, provisioned.PrivateKeyHex)
	require.NotNil(t, provisioned.PublicKey)

	generated, err := ProvisionCreateRequest(v1.CreateKeyRequest{ChainFamily: v1.ChainFamilyEVM})
	require.NoError(t, err)
	require.Equal(t, v1.CustodyModeMVP, generated.CustodyMode)
	require.NotEmpty(t, generated.PrivateKeyHex)

	privateKey := mustPrivateKey(t)
	external, err := ProvisionCreateRequest(v1.CreateKeyRequest{
		ChainFamily:       v1.ChainFamilyEVM,
		CustodyMode:       v1.CustodyModePKCS11,
		PublicKeyHex:      PublicKeyHex(&privateKey.PublicKey),
		ExternalSignerRef: "hsm-1",
	})
	require.NoError(t, err)
	require.Equal(t, v1.CustodyModePKCS11, external.CustodyMode)
	require.Equal(t, "hsm-1", external.ExternalSignerRef)
	require.Empty(t, external.PrivateKeyHex)

	_, err = ProvisionCreateRequest(v1.CreateKeyRequest{CustodyMode: "unknown"})
	require.ErrorContains(t, err, "unsupported custody mode")
}
