package chain

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/chain-signer/chain-signer/internal/chain/evm"
	"github.com/chain-signer/chain-signer/internal/chain/tron"
	"github.com/chain-signer/chain-signer/internal/domain"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

func DeriveSignerAddress(chainFamily string, pub *ecdsa.PublicKey) (string, error) {
	switch domain.NormalizeChainFamily(chainFamily) {
	case v1.ChainFamilyEVM:
		return evm.DeriveAddress(pub), nil
	case v1.ChainFamilyTRON:
		return tron.DeriveAddress(pub), nil
	default:
		return "", fmt.Errorf("unsupported chain family %q", chainFamily)
	}
}

func NormalizeAddress(chainFamily, value string) (string, error) {
	switch domain.NormalizeChainFamily(chainFamily) {
	case v1.ChainFamilyEVM:
		return evm.NormalizeAddress(value)
	case v1.ChainFamilyTRON:
		return tron.NormalizeAddress(value)
	default:
		return "", fmt.Errorf("unsupported chain family %q", chainFamily)
	}
}

func EqualAddress(chainFamily, left, right string) bool {
	switch domain.NormalizeChainFamily(chainFamily) {
	case v1.ChainFamilyEVM:
		return evm.EqualAddress(left, right)
	case v1.ChainFamilyTRON:
		return tron.EqualAddress(left, right)
	default:
		return false
	}
}

func Recover(req v1.VerifyRequest) (*v1.RecoverResponse, error) {
	switch domain.NormalizeChainFamily(req.ChainFamily) {
	case v1.ChainFamilyEVM:
		return evm.Recover(req)
	case v1.ChainFamilyTRON:
		return tron.Recover(req)
	default:
		return nil, fmt.Errorf("unsupported chain family %q", req.ChainFamily)
	}
}
