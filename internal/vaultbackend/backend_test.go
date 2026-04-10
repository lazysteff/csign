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
	assertCode(mapError(errors.New("boom")), 500)
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
