package advancedcodec

import (
	"fmt"
	"math"

	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedregistry"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

type PreparedAuthorization struct {
	Authorization ethtypes.SetCodeAuthorization
	Expected      common.Address
}

func PrepareAuthorization(schema, chainIDValue, delegateValue, nonceValue, expectedAuthority string) (PreparedAuthorization, error) {
	authorization, err := prepareAuthorizationFields(schema, chainIDValue, delegateValue, nonceValue, "")
	if err != nil {
		return PreparedAuthorization{}, err
	}
	expected, err := parseAddress("authority_address", expectedAuthority, false)
	if err != nil {
		return PreparedAuthorization{}, err
	}
	return PreparedAuthorization{Authorization: authorization, Expected: expected}, nil
}

func prepareAuthorizationFields(schema, chainIDValue, addressValue, nonceValue, prefix string) (ethtypes.SetCodeAuthorization, error) {
	if err := advancedregistry.Default().AuthorizationSchema(schema); err != nil {
		return ethtypes.SetCodeAuthorization{}, err
	}
	chainIDField := fieldPath(prefix, "chain_id")
	chainID, err := parseUint(chainIDField, chainIDValue, 256, true)
	if err != nil {
		return ethtypes.SetCodeAuthorization{}, err
	}
	address, err := parseAddress(fieldPath(prefix, "address"), addressValue, true)
	if err != nil {
		return ethtypes.SetCodeAuthorization{}, err
	}
	nonceField := fieldPath(prefix, "nonce")
	nonce, err := parseUint64(nonceField, nonceValue)
	if err != nil {
		return ethtypes.SetCodeAuthorization{}, err
	}
	if nonce == math.MaxUint64 {
		return ethtypes.SetCodeAuthorization{}, fmt.Errorf("%s must be less than 2^64-1", nonceField)
	}
	canonicalChainID, overflow := uint256.FromBig(chainID)
	if overflow {
		return ethtypes.SetCodeAuthorization{}, fmt.Errorf("%s is outside the uint256 range", chainIDField)
	}
	return ethtypes.SetCodeAuthorization{ChainID: *canonicalChainID, Address: address, Nonce: nonce}, nil
}

func PrepareSignedAuthorization(schema string, input v1.EIP7702SignedAuthorization) (ethtypes.SetCodeAuthorization, common.Address, error) {
	return prepareSignedAuthorization(schema, input, "")
}

func prepareSignedAuthorization(schema string, input v1.EIP7702SignedAuthorization, prefix string) (ethtypes.SetCodeAuthorization, common.Address, error) {
	authorization, err := prepareAuthorizationFields(schema, input.ChainID, input.Address, input.Nonce, prefix)
	if err != nil {
		return ethtypes.SetCodeAuthorization{}, common.Address{}, err
	}
	if input.YParity > 1 {
		return ethtypes.SetCodeAuthorization{}, common.Address{}, fmt.Errorf("%s must be 0 or 1", fieldPath(prefix, "y_parity"))
	}
	rBytes, err := parseHex(fieldPath(prefix, "r"), input.R, common.HashLength)
	if err != nil {
		return ethtypes.SetCodeAuthorization{}, common.Address{}, err
	}
	sBytes, err := parseHex(fieldPath(prefix, "s"), input.S, common.HashLength)
	if err != nil {
		return ethtypes.SetCodeAuthorization{}, common.Address{}, err
	}
	authorization.V = input.YParity
	authorization.R.SetBytes(rBytes)
	authorization.S.SetBytes(sBytes)
	recovered, err := authorization.Authority()
	if err != nil {
		if prefix != "" {
			return ethtypes.SetCodeAuthorization{}, common.Address{}, fmt.Errorf("%s: %w", prefix, err)
		}
		return ethtypes.SetCodeAuthorization{}, common.Address{}, err
	}
	return authorization, recovered, nil
}
