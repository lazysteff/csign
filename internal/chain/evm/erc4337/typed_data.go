package erc4337

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	ethmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

func (op PackedUserOperation) typedDataMessage(eip7702Delegate *common.Address) (apitypes.TypedDataMessage, error) {
	if err := validateUint("nonce", op.Nonce, 256); err != nil {
		return nil, err
	}
	if err := validateUint("preVerificationGas", op.PreVerificationGas, 256); err != nil {
		return nil, err
	}
	initCode, err := initCodeForHash(op.InitCode, eip7702Delegate)
	if err != nil {
		return nil, err
	}
	paymasterAndData, err := paymasterDataForHash(op.PaymasterAndData)
	if err != nil {
		return nil, err
	}
	return apitypes.TypedDataMessage{
		"sender":             op.Sender.Bytes(),
		"nonce":              new(big.Int).Set(op.Nonce),
		"initCode":           initCode,
		"callData":           cloneBytes(op.CallData),
		"accountGasLimits":   op.AccountGasLimits.Bytes(),
		"preVerificationGas": new(big.Int).Set(op.PreVerificationGas),
		"gasFees":            op.GasFees.Bytes(),
		"paymasterAndData":   paymasterAndData,
	}, nil
}

func userOperationDomain(entryPoint common.Address, chainID *big.Int) (apitypes.TypedDataDomain, error) {
	if err := validateUint("chainID", chainID, 256); err != nil {
		return apitypes.TypedDataDomain{}, err
	}
	typedChainID := ethmath.HexOrDecimal256(*new(big.Int).Set(chainID))
	return apitypes.TypedDataDomain{
		Name:              DomainName,
		Version:           DomainVersion,
		ChainId:           &typedChainID,
		VerifyingContract: entryPoint.Hex(),
	}, nil
}

func newUserOperationTypedData(domain apitypes.TypedDataDomain, message apitypes.TypedDataMessage) apitypes.TypedData {
	return apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			packedUserOperationPrimaryType: {
				{Name: "sender", Type: "address"},
				{Name: "nonce", Type: "uint256"},
				{Name: "initCode", Type: "bytes"},
				{Name: "callData", Type: "bytes"},
				{Name: "accountGasLimits", Type: "bytes32"},
				{Name: "preVerificationGas", Type: "uint256"},
				{Name: "gasFees", Type: "bytes32"},
				{Name: "paymasterAndData", Type: "bytes"},
			},
		},
		PrimaryType: packedUserOperationPrimaryType,
		Domain:      domain,
		Message:     message,
	}
}
