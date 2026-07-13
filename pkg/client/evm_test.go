package client

import (
	"context"
	"errors"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestSigningPropagatesTransportErrors(t *testing.T) {
	client := New(&fakeLogical{writeErr: errors.New("boom")}, "chain-signer")
	_, err := client.Signing.SignEVMLegacyTransfer(context.Background(), v1.EVMLegacyTransferSignRequest{})
	require.ErrorContains(t, err, "boom")
}
