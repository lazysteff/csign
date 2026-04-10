package routes

const (
	Version = "v1/version"
	Keys    = "v1/keys"

	EVMLegacyTransferSign  = "v1/evm/transfers/legacy/sign"
	EVMEIP1559TransferSign = "v1/evm/transfers/eip1559/sign"
	EVMContractCallSign    = "v1/evm/contracts/eip1559/sign"
	TRXTransferSign        = "v1/tron/transfers/trx/sign"
	TRC20TransferSign      = "v1/tron/transfers/trc20/sign"

	Verify  = "v1/verify"
	Recover = "v1/recover"
)

func Key(keyID string) string {
	return Keys + "/" + keyID
}

func KeyStatus(keyID string) string {
	return Key(keyID) + "/status"
}
