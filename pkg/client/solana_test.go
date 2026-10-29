package client

import (
	"context"
	"testing"

	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func TestSignSolanaMessageDetachedResponse(t *testing.T) {
	logical := &fakeLogical{writeSecret: &api.Secret{Data: map[string]interface{}{"api_version": "v1", "key_id": "source", "operation": "solana_message", "public_key_hex": "0x01", "signer_address": "address", "signing_scheme": "ed25519", "signature_encoding": "hex", "signature_hex": "0x02"}}}
	client := New(logical, "chain-signer")
	req := v1.SolanaMessageSignRequest{KeyID: "source", ChainFamily: "solana", Network: "devnet", RequestID: "r", MessageHex: "00"}
	result, err := client.Signing.SignSolanaMessage(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "chain-signer/v1/solana/messages/sign", logical.lastWritePath)
	require.Equal(t, "00", logical.lastWriteData["message_hex"])
	require.NotContains(t, logical.lastWriteData, "expected_signer_address")
	require.Equal(t, "ed25519", result.SigningScheme)
	require.Equal(t, "hex", result.SignatureEncoding)
}
