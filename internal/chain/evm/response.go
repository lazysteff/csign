package evm

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/chain-signer/chain-signer/internal/chain/evm/eip7702"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
)

func operationResponse(keyID, network, operation string, signer common.Address, requestID string) v1.EVMOperationResponseBase {
	return v1.EVMOperationResponseBase{
		EVMResponseContext: responseContext(network, operation, requestID),
		KeyID:              keyID,
		SignerAddress:      canonicalAddress(signer),
	}
}

func responseContext(network, operation, requestID string) v1.EVMResponseContext {
	return v1.EVMResponseContext{
		APIVersion:  v1.APIVersion,
		ChainFamily: v1.ChainFamilyEVM,
		Network:     network,
		Operation:   operation,
		RequestID:   requestID,
	}
}

func decodedTransaction(artifact *eip7702.TransactionArtifact) v1.EIP7702DecodedTransaction {
	transaction := artifact.Transaction
	canonicalAccessList := transaction.AccessList()
	accessList := make([]v1.EVMAccessTuple, 0, len(canonicalAccessList))
	for _, tuple := range canonicalAccessList {
		keys := make([]string, 0, len(tuple.StorageKeys))
		for _, key := range tuple.StorageKeys {
			keys = append(keys, key.Hex())
		}
		accessList = append(accessList, v1.EVMAccessTuple{Address: canonicalAddress(tuple.Address), StorageKeys: keys})
	}
	canonicalAuthorizations := transaction.SetCodeAuthorizations()
	authorizations := make([]v1.EIP7702DecodedAuthorization, 0, len(canonicalAuthorizations))
	for index, authorization := range canonicalAuthorizations {
		authorizations = append(authorizations, v1.EIP7702DecodedAuthorization{
			EIP7702SignedAuthorization: v1.EIP7702SignedAuthorization{
				EIP7702Authorization: v1.EIP7702Authorization{
					ChainID: authorization.ChainID.ToBig().String(),
					Address: canonicalAddress(authorization.Address),
					Nonce:   fmt.Sprintf("%d", authorization.Nonce),
				},
				YParity: authorization.V,
				R:       fixedBigHex(authorization.R.ToBig()),
				S:       fixedBigHex(authorization.S.ToBig()),
			},
			AuthorityAddress: canonicalAddress(artifact.Authorities[index]),
		})
	}
	to := transaction.To()
	return v1.EIP7702DecodedTransaction{
		EIP7702TransactionFields: v1.EIP7702TransactionFields{
			ChainID:              transaction.ChainId().String(),
			Nonce:                fmt.Sprintf("%d", transaction.Nonce()),
			To:                   canonicalAddress(*to),
			Value:                transaction.Value().String(),
			GasLimit:             fmt.Sprintf("%d", transaction.Gas()),
			MaxFeePerGas:         transaction.GasFeeCap().String(),
			MaxPriorityFeePerGas: transaction.GasTipCap().String(),
			Data:                 enc.EncodeHex(transaction.Data()),
			AccessList:           accessList,
		},
		AuthorizationList: authorizations,
	}
}

func fixedBigHex(value *big.Int) string {
	if value == nil {
		return "0x" + strings.Repeat("0", 64)
	}
	return fmt.Sprintf("0x%064x", value)
}

func canonicalAddress(address common.Address) string {
	return strings.ToLower(address.Hex())
}
