package chain

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/lazysteff/csign/v2/internal/chain/evm"
	"github.com/lazysteff/csign/v2/internal/chain/solana"
	"github.com/lazysteff/csign/v2/internal/chain/tron"
	"github.com/lazysteff/csign/v2/internal/cryptography"
	"github.com/lazysteff/csign/v2/internal/domain"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
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
	case v1.ChainFamilySolana:
		return solana.NormalizeAddress(value)
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
	case v1.ChainFamilySolana:
		return solana.EqualAddress(left, right)
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

// DerivePublicIdentity belongs to protocol logic, not cryptographic custody.
func DerivePublicIdentity(protocol string, pub cryptography.PublicKey) (string, error) {
	if protocol == v1.ChainFamilySolana {
		return solana.DeriveAddress(pub)
	}
	p, err := cryptography.ECDSAPublicKey(pub)
	if err != nil {
		return "", err
	}
	return DeriveSignerAddress(protocol, p)
}
