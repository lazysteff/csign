package erc4337

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPackRejectsOutOfRangeAndAmbiguousValues(t *testing.T) {
	op := standardVectorOperation(nil)
	op.Nonce = nil
	_, err := op.Pack()
	require.ErrorContains(t, err, "nonce is required")

	op = standardVectorOperation(nil)
	op.PreVerificationGas = big.NewInt(-1)
	_, err = op.Pack()
	require.ErrorContains(t, err, "preVerificationGas must be unsigned")

	op = standardVectorOperation(nil)
	op.CallGasLimit = new(big.Int).Lsh(big.NewInt(1), 128)
	_, err = op.Pack()
	require.ErrorContains(t, err, "callGasLimit exceeds uint120")

	op = standardVectorOperation(nil)
	op.EIP7702 = &EIP7702Init{}
	_, err = op.Pack()
	require.ErrorContains(t, err, "mutually exclusive")

	_, err = EncodePaymasterSignature(make([]byte, PaymasterSignatureMaxLength+1))
	require.ErrorContains(t, err, "exceeds uint16")

	_, err = DomainSeparator(EntryPointAddress(), new(big.Int).Lsh(big.NewInt(1), 256))
	require.ErrorContains(t, err, "chainID exceeds uint256")
}

func TestPackDefensivelyCopiesInput(t *testing.T) {
	op := standardVectorOperation(nil)
	packed, err := op.Pack()
	require.NoError(t, err)
	originalCallData := append([]byte(nil), packed.CallData...)
	originalNonce := new(big.Int).Set(packed.Nonce)

	op.CallData[0] ^= 0xff
	op.Nonce.SetInt64(999)
	require.True(t, bytes.Equal(originalCallData, packed.CallData))
	require.Equal(t, originalNonce, packed.Nonce)
}

func TestPackEnforcesEntryPointV09Uint120GasBounds(t *testing.T) {
	maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 120), big.NewInt(1))
	overflow := new(big.Int).Lsh(big.NewInt(1), 120)
	op := standardVectorOperation(nil)
	op.VerificationGasLimit = new(big.Int).Set(maximum)
	op.CallGasLimit = new(big.Int).Set(maximum)
	op.PreVerificationGas = new(big.Int).Set(maximum)
	op.MaxPriorityFeePerGas = new(big.Int).Set(maximum)
	op.MaxFeePerGas = new(big.Int).Set(maximum)
	_, err := op.Pack()
	require.NoError(t, err)

	tests := []struct {
		name   string
		mutate func(*UserOperation)
	}{
		{name: "verification gas", mutate: func(op *UserOperation) { op.VerificationGasLimit = overflow }},
		{name: "call gas", mutate: func(op *UserOperation) { op.CallGasLimit = overflow }},
		{name: "pre-verification gas", mutate: func(op *UserOperation) { op.PreVerificationGas = overflow }},
		{name: "priority fee", mutate: func(op *UserOperation) { op.MaxPriorityFeePerGas = overflow }},
		{name: "fee", mutate: func(op *UserOperation) { op.MaxFeePerGas = overflow }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := standardVectorOperation(nil)
			test.mutate(&candidate)
			_, err := candidate.Pack()
			require.ErrorContains(t, err, "exceeds uint120")
		})
	}

	paymaster := Paymaster{VerificationGasLimit: maximum, PostOpGasLimit: maximum}
	_, err = paymaster.Pack()
	require.NoError(t, err)
	paymaster.PostOpGasLimit = overflow
	_, err = paymaster.Pack()
	require.ErrorContains(t, err, "exceeds uint120")
}
