package vaultbackend

import (
	"errors"
	"testing"
	"time"

	"github.com/chain-signer/chain-signer/internal/domain"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestMapError(t *testing.T) {
	require.Equal(t, logical.ErrUnsupportedPath, mapError(logical.ErrUnsupportedPath))

	assertCode := func(err error, code int) {
		t.Helper()
		coded, ok := err.(interface{ Code() int })
		require.True(t, ok)
		require.Equal(t, code, coded.Code())
	}

	assertCode(mapError(faults.New(faults.Invalid, "bad")), 400)
	assertCode(mapError(faults.New(faults.PolicyDenied, "denied")), 400)
	assertCode(mapError(faults.New(faults.CustodyFailed, "custody")), 400)
	assertCode(mapError(faults.New(faults.Unsupported, "unsupported")), 400)
	assertCode(mapError(faults.New(faults.NotFound, "missing")), 404)
	assertCode(mapError(faults.New(faults.Conflict, "duplicate")), 409)
	internal := mapError(errors.New("secret Vault storage detail"))
	assertCode(internal, 500)
	require.EqualError(t, internal, "internal error")
	require.NotContains(t, internal.Error(), "secret Vault storage detail")

	coded := mapError(faults.NewCode(faults.Invalid, faults.InvalidUserOperation, "bad UserOperation"))
	assertCode(coded, 400)
	require.Contains(t, coded.Error(), "[invalid_user_operation] bad UserOperation")
}

func TestAdvancedDecodeErrorUsesStableRouteCode(t *testing.T) {
	err := structuredDecodeError("v1/evm/erc4337/user-operations/sign", errors.New(`json: unknown field "raw_hash"`))
	require.Equal(t, faults.Invalid, faults.KindOf(err))
	require.Equal(t, faults.InvalidUserOperation, faults.CodeOf(err))

	direct := structuredDecodeError("v1/evm/transfers/legacy/sign", errors.New("bad direct request"))
	require.Empty(t, faults.CodeOf(direct))
}

func TestDecodeResponseKeyResponseAndFieldString(t *testing.T) {
	var payload struct {
		KeyID string `json:"key_id"`
	}
	require.NoError(t, decode(map[string]interface{}{"key_id": "key-1"}, &payload))
	require.Equal(t, "key-1", payload.KeyID)

	resp := response(v1.VersionResponse{APIVersion: v1.APIVersion, BuildVersion: "v0.2.0"})
	require.Equal(t, v1.APIVersion, resp.Data["api_version"])

	now := time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC)
	keyResp := keyResponse(domain.Key{
		ID:            "key-1",
		ChainFamily:   v1.ChainFamilyEVM,
		CustodyMode:   v1.CustodyModeMVP,
		Active:        true,
		SignerAddress: "0x1",
		PublicKeyHex:  "0x2",
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	require.Equal(t, "key-1", keyResp.KeyID)
	require.Equal(t, now.Format(time.RFC3339Nano), keyResp.CreatedAt)

	fields := &framework.FieldData{Raw: map[string]interface{}{"key_id": "key-1"}, Schema: map[string]*framework.FieldSchema{
		"key_id":  {Type: framework.TypeString},
		"missing": {Type: framework.TypeString},
	}}
	require.Equal(t, "key-1", fieldString(fields, "key_id"))
	require.Equal(t, "", fieldString(fields, "missing"))
}
