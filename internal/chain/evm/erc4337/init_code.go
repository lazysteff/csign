package erc4337

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Factory is the unpacked factory portion of a UserOperation.
type Factory struct {
	Address common.Address
	Data    []byte
}

// EIP7702Init marks a UserOperation as EIP-7702 account initialization. Data
// is the optional initialization payload executed after delegation is active.
type EIP7702Init struct {
	Data []byte
}

func packInitCode(factory *Factory, eip7702 *EIP7702Init) ([]byte, error) {
	if factory != nil && eip7702 != nil {
		return nil, fmt.Errorf("factory and EIP-7702 initialization are mutually exclusive")
	}
	if factory != nil {
		ret := make([]byte, 0, common.AddressLength+len(factory.Data))
		ret = append(ret, factory.Address.Bytes()...)
		ret = append(ret, factory.Data...)
		return ret, nil
	}
	if eip7702 == nil {
		return nil, nil
	}
	if len(eip7702.Data) == 0 {
		return cloneBytes(eip7702InitCodeMarker[:]), nil
	}

	// Eip7702Support expects the two-byte marker to be right-padded to a
	// complete address-sized factory field when initialization data follows.
	ret := make([]byte, common.AddressLength, common.AddressLength+len(eip7702.Data))
	copy(ret, eip7702InitCodeMarker[:])
	ret = append(ret, eip7702.Data...)
	return ret, nil
}

// IsEIP7702InitCode reproduces Eip7702Support._isEip7702InitCode. Solidity
// zero-pads short calldata, so 0x7702 followed only by zero bytes through byte
// 20 is a marker; bytes after the first 20 are initialization data.
func IsEIP7702InitCode(initCode []byte) bool {
	if len(initCode) < len(eip7702InitCodeMarker) || initCode[0] != eip7702InitCodeMarker[0] || initCode[1] != eip7702InitCodeMarker[1] {
		return false
	}
	for index, value := range initCode {
		if index < len(eip7702InitCodeMarker) {
			continue
		}
		if index >= common.AddressLength {
			break
		}
		if value != 0 {
			return false
		}
	}
	return true
}

// InitCodeHash returns the hash EntryPoint v0.9 places in the UserOperation
// struct hash. A delegate is required for an EIP-7702 marker because the
// on-chain implementation reads it from the sender's delegated code.
func InitCodeHash(initCode []byte, eip7702Delegate *common.Address) (common.Hash, error) {
	preimage, err := initCodeForHash(initCode, eip7702Delegate)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(preimage), nil
}

func initCodeForHash(initCode []byte, eip7702Delegate *common.Address) ([]byte, error) {
	if !IsEIP7702InitCode(initCode) {
		return cloneBytes(initCode), nil
	}
	if eip7702Delegate == nil {
		return nil, fmt.Errorf("EIP-7702 delegate is required for marked initCode")
	}

	preimage := make([]byte, 0, common.AddressLength+max(0, len(initCode)-common.AddressLength))
	preimage = append(preimage, eip7702Delegate.Bytes()...)
	if len(initCode) > common.AddressLength {
		preimage = append(preimage, initCode[common.AddressLength:]...)
	}
	return preimage, nil
}
