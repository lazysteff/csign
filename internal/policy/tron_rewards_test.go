package policy

import (
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/stretchr/testify/require"
)

func TestValidateTRONRewardRoutes(t *testing.T) {
	signer := testSignerAddress(t, v1.ChainFamilyTRON)
	key := baseTRONKey(signer)

	withdrawBalanceReq := &v1.TRONWithdrawBalanceSignRequest{
		TRONOwnerSignRequestBase: tronPolicyOwnerBase(signer),
		TRONRawDataEnvelope:      tronPolicyEnvelope(),
	}
	require.NoError(t, ValidateTRONWithdrawBalance(key, withdrawBalanceReq))
}
