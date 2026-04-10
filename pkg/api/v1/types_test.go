package v1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateKeyRequestOmitsEmptyOptionalFields(t *testing.T) {
	raw, err := json.Marshal(CreateKeyRequest{
		ChainFamily: ChainFamilyEVM,
	})
	require.NoError(t, err)

	require.Contains(t, string(raw), `"chain_family":"evm"`)
	require.NotContains(t, string(raw), "custody_mode")
	require.NotContains(t, string(raw), "import_private_key_hex")
	require.NotContains(t, string(raw), "public_key_hex")
	require.NotContains(t, string(raw), "external_signer_ref")
	require.NotContains(t, string(raw), "policy")
}

func TestVerifyRequestOmitsOptionalFields(t *testing.T) {
	raw, err := json.Marshal(VerifyRequest{
		ChainFamily:   ChainFamilyEVM,
		Network:       "ethereum-sepolia",
		SignedPayload: "0x1234",
	})
	require.NoError(t, err)

	require.Contains(t, string(raw), `"chain_family":"evm"`)
	require.Contains(t, string(raw), `"signed_payload":"0x1234"`)
	require.NotContains(t, string(raw), "operation")
	require.NotContains(t, string(raw), "expected_signer_address")
}
