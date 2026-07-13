package advancedcodec

import v1 "github.com/chain-signer/chain-signer/pkg/api/v1"

const (
	codecSigner     = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
	codecContract   = "0x1111111111111111111111111111111111111111"
	codecSpender    = "0x2222222222222222222222222222222222222222"
	codecSender     = "0x3333333333333333333333333333333333333333"
	codecFactory    = "0x4444444444444444444444444444444444444444"
	codecPaymaster  = "0x5555555555555555555555555555555555555555"
	codecEntryPoint = v1.ERC4337EntryPointV09
)

func codecUserOperation() v1.ERC4337UserOperationV09 {
	return v1.ERC4337UserOperationV09{
		Sender:               codecSender,
		Nonce:                "7",
		Factory:              &v1.ERC4337Factory{Address: codecFactory, Data: "0x1234"},
		CallData:             "0xaabb",
		CallGasLimit:         "100000",
		VerificationGasLimit: "200000",
		PreVerificationGas:   "50000",
		MaxFeePerGas:         "100",
		MaxPriorityFeePerGas: "2",
		Paymaster: &v1.ERC4337Paymaster{
			Address:              codecPaymaster,
			VerificationGasLimit: "30000",
			PostOpGasLimit:       "40000",
			Data:                 "0x5678",
			Signature:            "0x9900",
		},
	}
}
