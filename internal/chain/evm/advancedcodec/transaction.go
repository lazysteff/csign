package advancedcodec

import (
	"fmt"
	"math"

	"github.com/chain-signer/chain-signer/internal/chain/evm/eip7702"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

type PreparedTransaction struct {
	Transaction          *ethtypes.SetCodeTx
	ExpectedSigner       common.Address
	RecoveredAuthorities []common.Address
}

func PrepareTransaction(input v1.EVMEIP7702TransactionSignRequest) (PreparedTransaction, error) {
	chainID, err := parseUint("chain_id", input.ChainID, 256, false)
	if err != nil {
		return PreparedTransaction{}, err
	}
	nonce, err := parseUint64("nonce", input.Nonce)
	if err != nil {
		return PreparedTransaction{}, err
	}
	if nonce == math.MaxUint64 {
		return PreparedTransaction{}, fmt.Errorf("nonce must be less than 2^64-1")
	}
	to, err := parseAddress("to", input.To, true)
	if err != nil {
		return PreparedTransaction{}, err
	}
	value, err := parseUint("value", input.Value, 256, true)
	if err != nil {
		return PreparedTransaction{}, err
	}
	gasLimit, err := parseUint64("gas_limit", input.GasLimit)
	if err != nil {
		return PreparedTransaction{}, err
	}
	if gasLimit == 0 {
		return PreparedTransaction{}, fmt.Errorf("gas_limit must be greater than zero")
	}
	maxFee, err := parseUint("max_fee_per_gas", input.MaxFeePerGas, 256, true)
	if err != nil {
		return PreparedTransaction{}, err
	}
	maxPriority, err := parseUint("max_priority_fee_per_gas", input.MaxPriorityFeePerGas, 256, true)
	if err != nil {
		return PreparedTransaction{}, err
	}
	if maxPriority.Cmp(maxFee) > 0 {
		return PreparedTransaction{}, fmt.Errorf("max_priority_fee_per_gas exceeds max_fee_per_gas")
	}
	data, err := parseHex("data", input.Data, -1)
	if err != nil {
		return PreparedTransaction{}, err
	}
	source, err := parseAddress("source_address", input.SourceAddress, false)
	if err != nil {
		return PreparedTransaction{}, err
	}

	accessList := make(ethtypes.AccessList, 0, len(input.AccessList))
	for index, tuple := range input.AccessList {
		address, err := parseAddress(fmt.Sprintf("access_list[%d].address", index), tuple.Address, true)
		if err != nil {
			return PreparedTransaction{}, err
		}
		keys := make([]common.Hash, 0, len(tuple.StorageKeys))
		for keyIndex, value := range tuple.StorageKeys {
			decoded, err := parseHex(fmt.Sprintf("access_list[%d].storage_keys[%d]", index, keyIndex), value, common.HashLength)
			if err != nil {
				return PreparedTransaction{}, err
			}
			keys = append(keys, common.BytesToHash(decoded))
		}
		accessList = append(accessList, ethtypes.AccessTuple{Address: address, StorageKeys: keys})
	}

	authorizations := make([]ethtypes.SetCodeAuthorization, 0, len(input.AuthorizationList))
	recoveredAuthorities := make([]common.Address, 0, len(input.AuthorizationList))
	for index, value := range input.AuthorizationList {
		authorization, recovered, err := prepareSignedAuthorization(eip7702.AuthorizationSchemaV1, value, fmt.Sprintf("authorization_list[%d]", index))
		if err != nil {
			return PreparedTransaction{}, err
		}
		authorizations = append(authorizations, authorization)
		recoveredAuthorities = append(recoveredAuthorities, recovered)
	}
	canonicalChainID, chainIDOverflow := uint256.FromBig(chainID)
	canonicalMaxPriority, priorityOverflow := uint256.FromBig(maxPriority)
	canonicalMaxFee, feeOverflow := uint256.FromBig(maxFee)
	canonicalValue, valueOverflow := uint256.FromBig(value)
	if chainIDOverflow || priorityOverflow || feeOverflow || valueOverflow {
		return PreparedTransaction{}, fmt.Errorf("type-4 transaction contains a value outside the uint256 range")
	}
	return PreparedTransaction{
		Transaction: &ethtypes.SetCodeTx{
			ChainID:    canonicalChainID,
			Nonce:      nonce,
			GasTipCap:  canonicalMaxPriority,
			GasFeeCap:  canonicalMaxFee,
			Gas:        gasLimit,
			To:         to,
			Value:      canonicalValue,
			Data:       data,
			AccessList: accessList,
			AuthList:   authorizations,
		},
		ExpectedSigner:       source,
		RecoveredAuthorities: recoveredAuthorities,
	}, nil
}
