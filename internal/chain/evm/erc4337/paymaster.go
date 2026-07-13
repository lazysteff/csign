package erc4337

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Paymaster is the unpacked v0.9 paymaster portion of a UserOperation.
// Signature is appended using the v0.9 paymaster-signature suffix and is
// intentionally excluded from the wallet's UserOperation hash.
type Paymaster struct {
	Address              common.Address
	VerificationGasLimit *big.Int
	PostOpGasLimit       *big.Int
	Data                 []byte
	Signature            []byte
}

// Pack returns paymaster(20) || verificationGasLimit(16) ||
// postOpGasLimit(16) || data || optional-signature-suffix.
func (paymaster Paymaster) Pack() ([]byte, error) {
	if err := validateUint("paymasterVerificationGasLimit", paymaster.VerificationGasLimit, 120); err != nil {
		return nil, err
	}
	if err := validateUint("paymasterPostOpGasLimit", paymaster.PostOpGasLimit, 120); err != nil {
		return nil, err
	}
	suffix, err := EncodePaymasterSignature(paymaster.Signature)
	if err != nil {
		return nil, err
	}

	ret := make([]byte, 0, PaymasterStaticFieldsLength+len(paymaster.Data)+len(suffix))
	ret = append(ret, paymaster.Address.Bytes()...)
	verification := make([]byte, 16)
	paymaster.VerificationGasLimit.FillBytes(verification)
	ret = append(ret, verification...)
	postOp := make([]byte, 16)
	paymaster.PostOpGasLimit.FillBytes(postOp)
	ret = append(ret, postOp...)
	ret = append(ret, paymaster.Data...)
	ret = append(ret, suffix...)
	return ret, nil
}

// EncodePaymasterSignature returns signature || uint16(len(signature)) ||
// PAYMASTER_SIG_MAGIC. The length is encoded in network byte order, as it is
// by Solidity's abi.encodePacked(uint16(...)). An empty signature has no suffix.
func EncodePaymasterSignature(signature []byte) ([]byte, error) {
	if len(signature) == 0 {
		return nil, nil
	}
	if len(signature) > PaymasterSignatureMaxLength {
		return nil, fmt.Errorf("paymaster signature length %d exceeds uint16", len(signature))
	}
	ret := make([]byte, 0, len(signature)+2+len(paymasterSigMagic))
	ret = append(ret, signature...)
	var length [2]byte
	// The length was bounded by PaymasterSignatureMaxLength immediately above.
	binary.BigEndian.PutUint16(length[:], uint16(len(signature))) // #nosec G115
	ret = append(ret, length[:]...)
	ret = append(ret, paymasterSigMagic[:]...)
	return ret, nil
}

// PaymasterSignatureLength reproduces
// UserOperationLib.getPaymasterSignatureLength. A trailing magic value with an
// impossible length is an error, matching the contract revert.
func PaymasterSignatureLength(paymasterAndData []byte) (int, error) {
	const suffixLength = 2 + len(paymasterSigMagic)
	const minimumLength = PaymasterStaticFieldsLength + suffixLength
	if len(paymasterAndData) < minimumLength || !bytes.Equal(paymasterAndData[len(paymasterAndData)-len(paymasterSigMagic):], paymasterSigMagic[:]) {
		return 0, nil
	}

	lengthOffset := len(paymasterAndData) - suffixLength
	signatureLength := int(binary.BigEndian.Uint16(paymasterAndData[lengthOffset : lengthOffset+2]))
	if signatureLength > len(paymasterAndData)-minimumLength {
		return 0, fmt.Errorf("invalid paymaster signature length %d for data length %d", signatureLength, len(paymasterAndData))
	}
	return signatureLength, nil
}

// PaymasterSignature extracts the optional v0.9 paymaster signature.
func PaymasterSignature(paymasterAndData []byte) ([]byte, error) {
	length, err := PaymasterSignatureLength(paymasterAndData)
	if err != nil || length == 0 {
		return nil, err
	}
	end := len(paymasterAndData) - 2 - len(paymasterSigMagic)
	return cloneBytes(paymasterAndData[end-length : end]), nil
}

// PaymasterDataHash reproduces Helpers.paymasterDataKeccak. If a non-empty
// v0.9 paymaster signature suffix is present, the signature and its uint16
// length are omitted while PAYMASTER_SIG_MAGIC remains in the hash preimage.
func PaymasterDataHash(paymasterAndData []byte) (common.Hash, error) {
	preimage, err := paymasterDataForHash(paymasterAndData)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(preimage), nil
}

func paymasterDataForHash(paymasterAndData []byte) ([]byte, error) {
	signatureLength, err := PaymasterSignatureLength(paymasterAndData)
	if err != nil {
		return nil, err
	}
	if signatureLength == 0 {
		return cloneBytes(paymasterAndData), nil
	}

	prefixEnd := len(paymasterAndData) - signatureLength - 2 - len(paymasterSigMagic)
	preimage := make([]byte, 0, prefixEnd+len(paymasterSigMagic))
	preimage = append(preimage, paymasterAndData[:prefixEnd]...)
	preimage = append(preimage, paymasterSigMagic[:]...)
	return preimage, nil
}
