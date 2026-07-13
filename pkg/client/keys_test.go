package client

import (
	"context"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

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
