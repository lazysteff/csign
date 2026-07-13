package routes

import "github.com/chain-signer/chain-signer/internal/keyid"

const (
	Version       = "v1/version"
	Keys          = "v1/keys"
	KeyStatusRoot = "v1/key-status"
	KeyPolicyRoot = "v1/key-policy"
	KeyPath       = "v1/keys/{key_id}"
	KeyStatusPath = "v1/key-status/{key_id}"
	KeyPolicyPath = "v1/key-policy/{key_id}"

	EVMLegacyTransferSign          = "v1/evm/transfers/legacy/sign"
	EVMEIP1559TransferSign         = "v1/evm/transfers/eip1559/sign"
	EVMContractCallSign            = "v1/evm/contracts/eip1559/sign"
	EVMEIP712Sign                  = "v1/evm/eip712/sign"
	EVMERC4337UserOperationSign    = "v1/evm/erc4337/user-operations/sign"
	EVMEIP7702AuthorizationSign    = "v1/evm/eip7702/authorizations/sign"
	EVMEIP7702TransactionSign      = "v1/evm/eip7702/transactions/sign"
	TRXTransferSign                = "v1/tron/transfers/trx/sign"
	TRC20TransferSign              = "v1/tron/transfers/trc20/sign"
	TRONFreezeBalanceV2Sign        = "v1/tron/resources/freeze_v2/sign"
	TRONUnfreezeBalanceV2Sign      = "v1/tron/resources/unfreeze_v2/sign"
	TRONDelegateResourceSign       = "v1/tron/resources/delegate/sign"
	TRONUndelegateResourceSign     = "v1/tron/resources/undelegate/sign"
	TRONWithdrawExpireUnfreezeSign = "v1/tron/resources/withdraw_expire_unfreeze/sign"
	TRONVoteWitnessSign            = "v1/tron/governance/vote_witness/sign"
	TRONWithdrawBalanceSign        = "v1/tron/rewards/withdraw_balance/sign"

	Verify  = "v1/verify"
	Recover = "v1/recover"

	EVMEIP712Verify               = "v1/evm/eip712/verify"
	EVMERC4337UserOperationVerify = "v1/evm/erc4337/user-operations/verify"
	EVMEIP7702AuthorizationVerify = "v1/evm/eip7702/authorizations/verify"
	EVMEIP7702TransactionRecover  = "v1/evm/eip7702/transactions/recover"
)

func Key(keyID string) (string, error) {
	escaped, err := keyid.EscapePath(keyID)
	if err != nil {
		return "", err
	}
	return Keys + "/" + escaped, nil
}

func KeyStatus(keyID string) (string, error) {
	escaped, err := keyid.EscapePath(keyID)
	if err != nil {
		return "", err
	}
	return KeyStatusRoot + "/" + escaped, nil
}

func KeyPolicy(keyID string) (string, error) {
	escaped, err := keyid.EscapePath(keyID)
	if err != nil {
		return "", err
	}
	return KeyPolicyRoot + "/" + escaped, nil
}
