package erc4337

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// PackedUserOperationTypeHash returns the v0.9 EIP-712 struct type hash.
func PackedUserOperationTypeHash() common.Hash {
	typedData := newUserOperationTypedData(apitypes.TypedDataDomain{Name: DomainName}, nil)
	return common.BytesToHash(typedData.TypeHash(packedUserOperationPrimaryType))
}

// EIP712DomainTypeHash returns the EIP-712 domain type hash used by EntryPoint.
func EIP712DomainTypeHash() common.Hash {
	typedData := newUserOperationTypedData(apitypes.TypedDataDomain{Name: DomainName}, nil)
	return common.BytesToHash(typedData.TypeHash("EIP712Domain"))
}

// EncodeForHash returns UserOperationLib.encode: the 9-word abi.encode
// preimage whose Keccak-256 is the PackedUserOperation EIP-712 struct hash.
func (op PackedUserOperation) EncodeForHash(eip7702Delegate *common.Address) ([]byte, error) {
	message, err := op.typedDataMessage(eip7702Delegate)
	if err != nil {
		return nil, err
	}
	// apitypes requires a non-empty domain while validating any struct. This
	// placeholder is not encoded into the PackedUserOperation struct hash.
	typedData := newUserOperationTypedData(apitypes.TypedDataDomain{Name: DomainName}, message)
	encoded, err := typedData.EncodeData(packedUserOperationPrimaryType, typedData.Message, 1)
	if err != nil {
		return nil, fmt.Errorf("encode PackedUserOperation: %w", err)
	}
	return encoded, nil
}

// StructHash returns UserOperationLib.hash for EntryPoint v0.9.
func (op PackedUserOperation) StructHash(eip7702Delegate *common.Address) (common.Hash, error) {
	message, err := op.typedDataMessage(eip7702Delegate)
	if err != nil {
		return common.Hash{}, err
	}
	typedData := newUserOperationTypedData(apitypes.TypedDataDomain{Name: DomainName}, message)
	hash, err := typedData.HashStruct(packedUserOperationPrimaryType, typedData.Message)
	if err != nil {
		return common.Hash{}, fmt.Errorf("hash PackedUserOperation: %w", err)
	}
	return common.BytesToHash(hash), nil
}

// DomainSeparator reproduces EntryPoint._domainSeparatorV4 for the fixed
// ERC4337 version 1 domain.
func DomainSeparator(entryPoint common.Address, chainID *big.Int) (common.Hash, error) {
	domain, err := userOperationDomain(entryPoint, chainID)
	if err != nil {
		return common.Hash{}, err
	}
	typedData := newUserOperationTypedData(domain, nil)
	hash, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return common.Hash{}, fmt.Errorf("hash ERC-4337 domain: %w", err)
	}
	return common.BytesToHash(hash), nil
}

// UserOperationHash reproduces EntryPoint.getUserOpHash in v0.9. The optional
// delegate is used only when InitCode is marked as EIP-7702.
func (op PackedUserOperation) UserOperationHash(entryPoint common.Address, chainID *big.Int, eip7702Delegate *common.Address) (common.Hash, error) {
	message, err := op.typedDataMessage(eip7702Delegate)
	if err != nil {
		return common.Hash{}, err
	}
	domain, err := userOperationDomain(entryPoint, chainID)
	if err != nil {
		return common.Hash{}, err
	}
	typedData := newUserOperationTypedData(domain, message)
	digest, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return common.Hash{}, fmt.Errorf("hash ERC-4337 typed data: %w", err)
	}
	return common.BytesToHash(digest), nil
}

// SimpleAccountSigningDigest is the digest SimpleAccount v0.9 passes directly
// to OpenZeppelin ECDSA.recover. It is intentionally identical to
// EntryPoint.getUserOpHash and is not wrapped with an eth_sign prefix.
func (op PackedUserOperation) SimpleAccountSigningDigest(entryPoint common.Address, chainID *big.Int, eip7702Delegate *common.Address) (common.Hash, error) {
	return op.UserOperationHash(entryPoint, chainID, eip7702Delegate)
}

// UserOperationHash packs op and returns EntryPoint.getUserOpHash.
func (op UserOperation) UserOperationHash(entryPoint common.Address, chainID *big.Int, eip7702Delegate *common.Address) (common.Hash, error) {
	packed, err := op.Pack()
	if err != nil {
		return common.Hash{}, err
	}
	return packed.UserOperationHash(entryPoint, chainID, eip7702Delegate)
}

// SimpleAccountSigningDigest packs op and returns the direct EIP-712 digest
// expected by SimpleAccount v0.9.
func (op UserOperation) SimpleAccountSigningDigest(entryPoint common.Address, chainID *big.Int, eip7702Delegate *common.Address) (common.Hash, error) {
	return op.UserOperationHash(entryPoint, chainID, eip7702Delegate)
}
