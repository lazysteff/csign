package policy

import (
	"testing"

	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestValidateCreateKeyRequest(t *testing.T) {
	require.NoError(t, ValidateCreateKeyRequest(v1.CreateKeyRequest{ChainFamily: v1.ChainFamilyEVM}))
	require.NoError(t, ValidateCreateKeyRequest(v1.CreateKeyRequest{
		ChainFamily: v1.ChainFamilyEVM, CustodyMode: v1.CustodyModePKCS11,
		PublicKeyHex: testPublicKeyHex(t), ExternalSignerRef: "hsm-1",
	}))

	require.Equal(t, faults.Invalid, faults.KindOf(ValidateCreateKeyRequest(v1.CreateKeyRequest{
		ChainFamily: "unknown",
	})))
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateCreateKeyRequest(v1.CreateKeyRequest{
		ChainFamily: v1.ChainFamilyEVM, ExternalSignerRef: "hsm-1",
	})))
	require.Equal(t, faults.Invalid, faults.KindOf(ValidateCreateKeyRequest(v1.CreateKeyRequest{
		ChainFamily: v1.ChainFamilyEVM, CustodyMode: v1.CustodyModePKCS11,
	})))
}
