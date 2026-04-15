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

func TestHandleVersionIncludesSupportedRoutes(t *testing.T) {
	backend := New(nil)
	resp, err := backend.handleVersion(nil, nil, nil)
	require.NoError(t, err)

	var payload v1.VersionResponse
	require.NoError(t, decode(resp.Data, &payload))
	require.Equal(t, registeredPublicRoutes(backend.routes), payload.SupportedRoutes)
	require.Equal(t, []string{
		"v1/evm/contracts/eip1559/sign",
		"v1/evm/transfers/eip1559/sign",
		"v1/evm/transfers/legacy/sign",
		"v1/key-status/{key_id}",
		"v1/keys",
		"v1/keys/{key_id}",
		"v1/recover",
		"v1/tron/resources/delegate/sign",
		"v1/tron/resources/freeze_v2/sign",
		"v1/tron/resources/undelegate/sign",
		"v1/tron/resources/unfreeze_v2/sign",
		"v1/tron/resources/withdraw_expire_unfreeze/sign",
		"v1/tron/transfers/trc20/sign",
		"v1/tron/transfers/trx/sign",
		"v1/verify",
		"v1/version",
	}, payload.SupportedRoutes)
}
