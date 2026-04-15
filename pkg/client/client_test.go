package client

import (
	"context"
	"errors"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func TestVersionDecodesTypedResponse(t *testing.T) {
	logical := &fakeLogical{
		readSecret: &api.Secret{
			Data: map[string]interface{}{
				"api_version":      v1.APIVersion,
				"build_version":    "v0.3.0",
				"supported_routes": []interface{}{"v1/version", "v1/verify"},
			},
		},
	}

	client := New(logical, "chain-signer")
	resp, err := client.Version(context.Background())
	require.NoError(t, err)
	require.Equal(t, v1.APIVersion, resp.APIVersion)
	require.Equal(t, "v0.3.0", resp.BuildVersion)
	require.Equal(t, []string{"v1/version", "v1/verify"}, resp.SupportedRoutes)
}

func TestKeysListDecodesVaultListShape(t *testing.T) {
	logical := &fakeLogical{
		listSecret: &api.Secret{
			Data: map[string]interface{}{
				"keys": []interface{}{"key-a", "key-b"},
			},
		},
	}

	client := New(logical, "chain-signer")
	keys, err := client.Keys.List(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"key-a", "key-b"}, keys)
}

func TestVersionFailsOnEmptyResponse(t *testing.T) {
	client := New(&fakeLogical{}, "chain-signer")
	_, err := client.Version(context.Background())
	require.ErrorContains(t, err, "vault returned an empty response")
}

func TestKeyHelpersUseCanonicalHierarchicalPaths(t *testing.T) {
	logical := &fakeLogical{
		readSecret: &api.Secret{
			Data: map[string]interface{}{
				"api_version": v1.APIVersion,
				"key_id":      "orgs/123/main signer",
			},
		},
		writeSecret: &api.Secret{
			Data: map[string]interface{}{
				"api_version": v1.APIVersion,
				"key_id":      "orgs/123/main signer",
			},
		},
	}

	client := New(logical, "chain-signer")
	_, err := client.Keys.Read(context.Background(), "orgs/123/main signer")
	require.NoError(t, err)
	require.Equal(t, "chain-signer/v1/keys/orgs/123/main%20signer", logical.lastReadPath)

	_, err = client.Keys.SetActive(context.Background(), "orgs/123/main signer", false)
	require.NoError(t, err)
	require.Equal(t, "chain-signer/v1/key-status/orgs/123/main%20signer", logical.lastWritePath)
}

func TestKeyHelpersRejectInvalidKeyIDsBeforeTransport(t *testing.T) {
	logical := &fakeLogical{}
	client := New(logical, "chain-signer")

	_, err := client.Keys.Read(context.Background(), "a//b")
	require.ErrorContains(t, err, "key_id")
	require.Empty(t, logical.lastReadPath)

	_, err = client.Keys.SetActive(context.Background(), "/bad", true)
	require.ErrorContains(t, err, "key_id")
	require.Empty(t, logical.lastWritePath)
}

func TestSigningPropagatesTransportErrors(t *testing.T) {
	client := New(&fakeLogical{writeErr: errors.New("boom")}, "chain-signer")
	_, err := client.Signing.SignEVMLegacyTransfer(context.Background(), v1.EVMLegacyTransferSignRequest{})
	require.ErrorContains(t, err, "boom")
}

func TestTRONResourceSigningUsesExpectedRoute(t *testing.T) {
	logical := &fakeLogical{
		writeSecret: &api.Secret{
			Data: map[string]interface{}{
				"api_version": v1.APIVersion,
				"key_id":      "tron-key",
			},
		},
	}
	client := New(logical, "chain-signer")
	_, err := client.Signing.SignTRONFreezeBalanceV2(context.Background(), v1.TRONFreezeBalanceV2SignRequest{
		TRONOwnerSignRequestBase: NewTRONOwnerSignRequestBase("tron-key", "tron-nile", "req-1", "TQ3f6xYfQudrM1J8XG2k6wN1KQkPqM7g7d"),
		TRONRawDataEnvelope: v1.TRONRawDataEnvelope{
			RefBlockBytes: "a1b2",
			RefBlockHash:  "0102030405060708",
			Timestamp:     1710000000000,
			Expiration:    1710000060000,
		},
		Resource: v1.TRONResourceEnergy,
		Amount:   1,
	})
	require.NoError(t, err)
	require.Equal(t, "chain-signer/v1/tron/resources/freeze_v2/sign", logical.lastWritePath)
}

func TestTRONRequestBuildersDefaultChainFamily(t *testing.T) {
	base := NewTRONOwnerSignRequestBase("tron-key", "tron-nile", "req-1", "TP4XxLr5K8NvL8nRc1rER6S1PqrgQ4QXbQ")
	req := NewTRONDelegateResourceRequest(base, v1.TRONRawDataEnvelope{
		RefBlockBytes: "a1b2",
		RefBlockHash:  "0102030405060708",
		Timestamp:     1710000000000,
		Expiration:    1710000060000,
	}, "TSvT6Bg3siokv3dbdtt9o4oM1CTXmymGn1", v1.TRONResourceBandwidth, 10, false, 0)
	require.Equal(t, v1.ChainFamilyTRON, req.ChainFamily)
	require.Equal(t, int64(10), req.Amount)
}

type fakeLogical struct {
	readSecret    *api.Secret
	listSecret    *api.Secret
	writeSecret   *api.Secret
	writeErr      error
	lastReadPath  string
	lastWritePath string
}

func (f *fakeLogical) ReadWithContext(_ context.Context, path string) (*api.Secret, error) {
	f.lastReadPath = path
	return f.readSecret, nil
}

func (f *fakeLogical) WriteWithContext(_ context.Context, path string, _ map[string]interface{}) (*api.Secret, error) {
	f.lastWritePath = path
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	return f.writeSecret, nil
}

func (f *fakeLogical) ListWithContext(context.Context, string) (*api.Secret, error) {
	return f.listSecret, nil
}
