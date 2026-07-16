package policy

import (
	"testing"

	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestValidateTRXAndTRC20Transfers(t *testing.T) {
	signer := testSignerAddress(t, v1.ChainFamilyTRON)
	key := baseTRONKey(signer)
	base := v1.BaseSignRequest{
		KeyID: "tron-key", ChainFamily: v1.ChainFamilyTRON, Network: testTronNetwork,
		RequestID: testRequestID, SourceAddress: signer,
	}

	trxReq := &v1.TRXTransferSignRequest{
		BaseSignRequest: base,
		To:              testTronRecipient, Amount: 10, FeeLimit: 1000000,
		RefBlockBytes: "a1b2", RefBlockHash: "0102030405060708",
		Timestamp: 1710000000000, Expiration: 1710000060000,
	}
	require.NoError(t, ValidateTRXTransfer(key, trxReq))
	trxReq.Amount = 101
	require.Equal(t, faults.PolicyDenied, faults.KindOf(ValidateTRXTransfer(key, trxReq)))
	trxReq.Amount = 10
	trxReq.FeeLimit = 21000000
	require.Equal(t, faults.PolicyDenied, faults.KindOf(ValidateTRXTransfer(key, trxReq)))

	trc20Req := &v1.TRC20TransferSignRequest{
		BaseSignRequest: base,
		To:              testTronRecipient, TokenContract: testTronContract, Amount: "25", FeeLimit: 1000000,
		RefBlockBytes: "a1b2", RefBlockHash: "0102030405060708",
		Timestamp: 1710000000000, Expiration: 1710000060000,
	}
	require.NoError(t, ValidateTRC20Transfer(key, trc20Req))
	trc20Req.TokenContract = testTronRecipient
	require.Equal(t, faults.PolicyDenied, faults.KindOf(ValidateTRC20Transfer(key, trc20Req)))
}
