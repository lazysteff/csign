package erc4337

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

func standardVectorOperation(paymasterSignature []byte) UserOperation {
	return UserOperation{
		Sender: common.HexToAddress("0x1111111111111111111111111111111111111111"),
		Nonce:  big.NewInt(123),
		Factory: &Factory{
			Address: common.HexToAddress("0x2222222222222222222222222222222222222222"),
			Data:    common.FromHex("0xdeadbeef"),
		},
		CallData:             common.FromHex("0xca11"),
		VerificationGasLimit: big.NewInt(20),
		CallGasLimit:         big.NewInt(10),
		PreVerificationGas:   big.NewInt(30),
		MaxPriorityFeePerGas: big.NewInt(50),
		MaxFeePerGas:         big.NewInt(40),
		Paymaster: &Paymaster{
			Address:              common.HexToAddress("0x3333333333333333333333333333333333333333"),
			VerificationGasLimit: big.NewInt(60),
			PostOpGasLimit:       big.NewInt(70),
			Data:                 common.FromHex("0xcafe"),
			Signature:            paymasterSignature,
		},
		Signature: common.FromHex("0xdeadface"),
	}
}

func hexBytes(value []byte) string {
	return "0x" + common.Bytes2Hex(value)
}
