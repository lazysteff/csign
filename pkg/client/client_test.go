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
				"api_version":   v1.APIVersion,
				"build_version": "v0.2.0",
			},
		},
	}

	client := New(logical, "chain-signer")
	resp, err := client.Version(context.Background())
	require.NoError(t, err)
	require.Equal(t, v1.APIVersion, resp.APIVersion)
	require.Equal(t, "v0.2.0", resp.BuildVersion)
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

func TestSigningPropagatesTransportErrors(t *testing.T) {
	client := New(&fakeLogical{writeErr: errors.New("boom")}, "chain-signer")
	_, err := client.Signing.SignEVMLegacyTransfer(context.Background(), v1.EVMLegacyTransferSignRequest{})
	require.ErrorContains(t, err, "boom")
}

type fakeLogical struct {
	readSecret  *api.Secret
	listSecret  *api.Secret
	writeSecret *api.Secret
	writeErr    error
}

func (f *fakeLogical) ReadWithContext(context.Context, string) (*api.Secret, error) {
	return f.readSecret, nil
}

func (f *fakeLogical) WriteWithContext(context.Context, string, map[string]interface{}) (*api.Secret, error) {
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	return f.writeSecret, nil
}

func (f *fakeLogical) ListWithContext(context.Context, string) (*api.Secret, error) {
	return f.listSecret, nil
}
