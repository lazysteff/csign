package advancedcodec

import (
	"fmt"
	"math/big"

	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedregistry"
	"github.com/chain-signer/chain-signer/internal/chain/evm/erc4337"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
)

type PreparedUserOperation struct {
	Operation  erc4337.UserOperation
	EntryPoint common.Address
	ChainID    *big.Int
	Delegate   *common.Address
	Hash       common.Hash
	Expected   common.Address
}

func PrepareUserOperation(protocolVersion, implementation, implementationVersion, signingSchema, chainIDValue, entryPointValue, expectedSigner, expectedHash string, input v1.ERC4337UserOperationV09) (PreparedUserOperation, error) {
	adapter, err := advancedregistry.Default().AccountAdapter(protocolVersion, implementation, implementationVersion, signingSchema)
	if err != nil {
		return PreparedUserOperation{}, err
	}
	chainID, err := parseUint("chain_id", chainIDValue, 256, false)
	if err != nil {
		return PreparedUserOperation{}, err
	}
	entryPoint, err := parseAddress("entry_point", entryPointValue, false)
	if err != nil {
		return PreparedUserOperation{}, err
	}
	expected, err := parseAddress("expected_signer_address", expectedSigner, false)
	if err != nil {
		return PreparedUserOperation{}, err
	}
	sender, err := parseAddress("user_operation.sender", input.Sender, false)
	if err != nil {
		return PreparedUserOperation{}, err
	}
	nonce, err := parseUint("user_operation.nonce", input.Nonce, 256, true)
	if err != nil {
		return PreparedUserOperation{}, err
	}
	callData, err := parseHex("user_operation.call_data", input.CallData, -1)
	if err != nil {
		return PreparedUserOperation{}, err
	}
	callGas, err := parseUint("user_operation.call_gas_limit", input.CallGasLimit, 128, true)
	if err != nil {
		return PreparedUserOperation{}, err
	}
	verificationGas, err := parseUint("user_operation.verification_gas_limit", input.VerificationGasLimit, 128, true)
	if err != nil {
		return PreparedUserOperation{}, err
	}
	preVerificationGas, err := parseUint("user_operation.pre_verification_gas", input.PreVerificationGas, 256, true)
	if err != nil {
		return PreparedUserOperation{}, err
	}
	maxFee, err := parseUint("user_operation.max_fee_per_gas", input.MaxFeePerGas, 128, true)
	if err != nil {
		return PreparedUserOperation{}, err
	}
	maxPriority, err := parseUint("user_operation.max_priority_fee_per_gas", input.MaxPriorityFeePerGas, 128, true)
	if err != nil {
		return PreparedUserOperation{}, err
	}
	if maxPriority.Cmp(maxFee) > 0 {
		return PreparedUserOperation{}, fmt.Errorf("user_operation.max_priority_fee_per_gas exceeds max_fee_per_gas")
	}

	op := erc4337.UserOperation{
		Sender:               sender,
		Nonce:                nonce,
		CallData:             callData,
		CallGasLimit:         callGas,
		VerificationGasLimit: verificationGas,
		PreVerificationGas:   preVerificationGas,
		MaxFeePerGas:         maxFee,
		MaxPriorityFeePerGas: maxPriority,
	}
	if input.Factory != nil && input.EIP7702 != nil {
		return PreparedUserOperation{}, fmt.Errorf("user_operation.factory and eip7702 are mutually exclusive")
	}
	if input.Factory != nil {
		address, err := parseAddress("user_operation.factory.address", input.Factory.Address, false)
		if err != nil {
			return PreparedUserOperation{}, err
		}
		data, err := parseHex("user_operation.factory.data", input.Factory.Data, -1)
		if err != nil {
			return PreparedUserOperation{}, err
		}
		op.Factory = &erc4337.Factory{Address: address, Data: data}
	}
	var delegate *common.Address
	if input.EIP7702 != nil {
		parsed, err := parseAddress("user_operation.eip7702.delegate_address", input.EIP7702.DelegateAddress, false)
		if err != nil {
			return PreparedUserOperation{}, err
		}
		data, err := parseHex("user_operation.eip7702.data", input.EIP7702.Data, -1)
		if err != nil {
			return PreparedUserOperation{}, err
		}
		delegate = &parsed
		op.EIP7702 = &erc4337.EIP7702Init{Data: data}
	}
	if input.Paymaster != nil {
		address, err := parseAddress("user_operation.paymaster.address", input.Paymaster.Address, false)
		if err != nil {
			return PreparedUserOperation{}, err
		}
		verification, err := parseUint("user_operation.paymaster.verification_gas_limit", input.Paymaster.VerificationGasLimit, 128, true)
		if err != nil {
			return PreparedUserOperation{}, err
		}
		postOp, err := parseUint("user_operation.paymaster.post_op_gas_limit", input.Paymaster.PostOpGasLimit, 128, true)
		if err != nil {
			return PreparedUserOperation{}, err
		}
		data, err := parseHex("user_operation.paymaster.data", input.Paymaster.Data, -1)
		if err != nil {
			return PreparedUserOperation{}, err
		}
		var signature []byte
		if input.Paymaster.Signature != "" {
			signature, err = parseHex("user_operation.paymaster.signature", input.Paymaster.Signature, -1)
			if err != nil {
				return PreparedUserOperation{}, err
			}
		}
		op.Paymaster = &erc4337.Paymaster{
			Address:              address,
			VerificationGasLimit: verification,
			PostOpGasLimit:       postOp,
			Data:                 data,
			Signature:            signature,
		}
	}
	hash, err := adapter.HashUserOperation(op, entryPoint, chainID, delegate)
	if err != nil {
		return PreparedUserOperation{}, err
	}
	if expectedHash != "" {
		expectedBytes, err := parseHex("expected_user_operation_hash", expectedHash, common.HashLength)
		if err != nil {
			return PreparedUserOperation{}, err
		}
		if hash != common.BytesToHash(expectedBytes) {
			return PreparedUserOperation{}, ErrUserOperationHashMismatch
		}
	}
	return PreparedUserOperation{Operation: op, EntryPoint: entryPoint, ChainID: chainID, Delegate: delegate, Hash: hash, Expected: expected}, nil
}
