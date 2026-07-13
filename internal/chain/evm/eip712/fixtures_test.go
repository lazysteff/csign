package eip712

var (
	testDomain = Domain{
		Name:              "Uniswap V2",
		Version:           "1",
		ChainID:           "1",
		VerifyingContract: "0x1111111111111111111111111111111111111111",
	}
	testMessage = PermitMessage{
		Owner:    "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
		Spender:  "0x2222222222222222222222222222222222222222",
		Value:    "10000000000000000000",
		Nonce:    "0",
		Deadline: "115792089237316195423570985008687907853269984665640564039457584007913129639935",
	}
)
