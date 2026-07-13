package client

import (
	"context"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func TestVersionDecodesTypedResponse(t *testing.T) {
	logical := &fakeLogical{
		readSecret: &api.Secret{
			Data: map[string]interface{}{
				"api_version":                             v1.APIVersion,
				"build_version":                           "v0.3.0",
				"supported_routes":                        []interface{}{"v1/version", "v1/verify"},
				"supported_erc4337_protocol_versions":     []interface{}{v1.ERC4337ProtocolV09},
				"supported_account_signing_schemas":       []interface{}{v1.ERC4337SimpleAccountSigningSchema},
				"supported_eip7702_authorization_schemas": []interface{}{v1.EIP7702AuthorizationSchemaV1},
				"supported_account_implementations": []interface{}{map[string]interface{}{
					"id": v1.ERC4337AccountSimpleAccount, "version": v1.ERC4337AccountSimpleAccountVersion,
					"protocol_versions": []interface{}{v1.ERC4337ProtocolV09}, "signing_schemas": []interface{}{v1.ERC4337SimpleAccountSigningSchema},
					"signature_encoding": v1.SignatureEncodingRSV27,
				}},
			},
		},
	}

	client := New(logical, "chain-signer")
	resp, err := client.Version(context.Background())
	require.NoError(t, err)
	require.Equal(t, v1.APIVersion, resp.APIVersion)
	require.Equal(t, "v0.3.0", resp.BuildVersion)
	require.Equal(t, []string{"v1/version", "v1/verify"}, resp.SupportedRoutes)
	require.Equal(t, []string{v1.ERC4337ProtocolV09}, resp.SupportedERC4337ProtocolVersions)
	require.Equal(t, []string{v1.ERC4337SimpleAccountSigningSchema}, resp.SupportedAccountSigningSchemas)
	require.Equal(t, []string{v1.EIP7702AuthorizationSchemaV1}, resp.SupportedEIP7702AuthorizationSchemas)
	require.Equal(t, []v1.ERC4337AccountCapability{{
		ID: v1.ERC4337AccountSimpleAccount, Version: v1.ERC4337AccountSimpleAccountVersion,
		ProtocolVersions: []string{v1.ERC4337ProtocolV09}, SigningSchemas: []string{v1.ERC4337SimpleAccountSigningSchema},
		SignatureEncoding: v1.SignatureEncodingRSV27,
	}}, resp.SupportedAccountImplementations)
}

func TestVersionFailsOnEmptyResponse(t *testing.T) {
	client := New(&fakeLogical{}, "chain-signer")
	_, err := client.Version(context.Background())
	require.ErrorContains(t, err, "vault returned an empty response")
}

type fakeLogical struct {
	readSecret    *api.Secret
	listSecret    *api.Secret
	writeSecret   *api.Secret
	writeErr      error
	lastReadPath  string
	lastWritePath string
	lastWriteData map[string]interface{}
}

func (f *fakeLogical) ReadWithContext(_ context.Context, path string) (*api.Secret, error) {
	f.lastReadPath = path
	return f.readSecret, nil
}

func (f *fakeLogical) WriteWithContext(_ context.Context, path string, data map[string]interface{}) (*api.Secret, error) {
	f.lastWritePath = path
	f.lastWriteData = data
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	return f.writeSecret, nil
}

func (f *fakeLogical) ListWithContext(context.Context, string) (*api.Secret, error) {
	return f.listSecret, nil
}
