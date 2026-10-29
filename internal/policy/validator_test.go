package policy

import (
	"testing"

	"github.com/lazysteff/csign/v2/internal/faults"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
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
