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

func TestTRONResourceRequestRejectsUnsupportedFields(t *testing.T) {
	var req TRONFreezeBalanceV2SignRequest
	err := json.Unmarshal([]byte(`{
		"key_id":"tron-key",
		"chain_family":"tron",
		"network":"tron-nile",
		"request_id":"req-1",
		"owner_address":"TSvT6Bg3siokv3dbdtt9o4oM1CTXmymGn1",
		"ref_block_bytes":"a1b2",
		"ref_block_hash":"0102030405060708",
		"ref_block_num":1,
		"timestamp":1710000000000,
		"expiration":1710000060000,
		"resource":"ENERGY",
		"amount":10
	}`), &req)
	require.ErrorContains(t, err, "ref_block_num")
}

func TestTRONResourceRequestOmitsUnsetFeeLimit(t *testing.T) {
	raw, err := json.Marshal(TRONWithdrawExpireUnfreezeSignRequest{
		TRONOwnerSignRequestBase: TRONOwnerSignRequestBase{
			KeyID:        "tron-key",
			ChainFamily:  ChainFamilyTRON,
			Network:      "tron-nile",
			RequestID:    "req-1",
			OwnerAddress: "TSvT6Bg3siokv3dbdtt9o4oM1CTXmymGn1",
		},
		TRONRawDataEnvelope: TRONRawDataEnvelope{
			RefBlockBytes: "a1b2",
			RefBlockHash:  "0102030405060708",
			Timestamp:     1710000000000,
			Expiration:    1710000060000,
		},
	})
	require.NoError(t, err)
	require.NotContains(t, string(raw), "fee_limit")
}
