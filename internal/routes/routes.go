package routes

const (
	Version       = "v1/version"
	Keys          = "v1/keys"
	KeyPath       = "v1/keys/{key_id}"
	KeyPathStatus = "v1/keys/{key_id}/status"

	EVMLegacyTransferSign          = "v1/evm/transfers/legacy/sign"
	EVMEIP1559TransferSign         = "v1/evm/transfers/eip1559/sign"
	EVMContractCallSign            = "v1/evm/contracts/eip1559/sign"
	TRXTransferSign                = "v1/tron/transfers/trx/sign"
	TRC20TransferSign              = "v1/tron/transfers/trc20/sign"
	TRONFreezeBalanceV2Sign        = "v1/tron/resources/freeze_v2/sign"
	TRONUnfreezeBalanceV2Sign      = "v1/tron/resources/unfreeze_v2/sign"
	TRONDelegateResourceSign       = "v1/tron/resources/delegate/sign"
	TRONUndelegateResourceSign     = "v1/tron/resources/undelegate/sign"
	TRONWithdrawExpireUnfreezeSign = "v1/tron/resources/withdraw_expire_unfreeze/sign"

	Verify  = "v1/verify"
	Recover = "v1/recover"
)

func Key(keyID string) string {
	return Keys + "/" + keyID
}

func KeyStatus(keyID string) string {
	return Key(keyID) + "/status"
}
