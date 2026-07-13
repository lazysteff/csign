package eip7702

import (
	"context"
	"fmt"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// SignAuthorization validates and signs geth's canonical EIP-7702
// authorization structure through the configured custody backend.
func SignAuthorization(ctx context.Context, material custody.Material, authorization ethtypes.SetCodeAuthorization, options AuthorizationOptions) (*AuthorizationArtifact, error) {
	if err := validateAuthorizationContext(authorization, options); err != nil {
		return nil, err
	}
	hash := authorization.SigHash()
	signature, err := custody.RecoverableSignature(ctx, material, hash[:])
	if err != nil {
		return nil, err
	}
	return AssembleAuthorization(authorization, signature, options)
}

// AssembleAuthorization combines the canonical unsigned authorization fields
// with a low-s [R || S || YParity] signature.
func AssembleAuthorization(authorization ethtypes.SetCodeAuthorization, signature []byte, options AuthorizationOptions) (*AuthorizationArtifact, error) {
	if err := validateAuthorizationContext(authorization, options); err != nil {
		return nil, err
	}
	if len(signature) != crypto.SignatureLength {
		return nil, fmt.Errorf("authorization signature must be %d bytes", crypto.SignatureLength)
	}
	if signature[crypto.RecoveryIDOffset] > 1 {
		return nil, fmt.Errorf("authorization signature y parity must be 0 or 1")
	}

	signed := ethtypes.SetCodeAuthorization{
		ChainID: authorization.ChainID,
		Address: authorization.Address,
		Nonce:   authorization.Nonce,
		V:       signature[crypto.RecoveryIDOffset],
		R:       *new(uint256.Int).SetBytes(signature[:32]),
		S:       *new(uint256.Int).SetBytes(signature[32:64]),
	}
	authority, err := signed.Authority()
	if err != nil {
		return nil, fmt.Errorf("authorization authority: %w", err)
	}
	if options.ExpectedAuthority != nil && authority != *options.ExpectedAuthority {
		return nil, fmt.Errorf("authorization authority %s does not match expected authority %s", authority.Hex(), options.ExpectedAuthority.Hex())
	}
	serialized, err := SerializeAuthorization(signed)
	if err != nil {
		return nil, err
	}
	return &AuthorizationArtifact{
		Authorization: signed,
		SigningHash:   signed.SigHash(),
		Authority:     authority,
		Serialized:    serialized,
	}, nil
}

// ValidateSignedAuthorization enforces wildcard/chain context and recovers
// the authority using geth's canonical signature validation.
func ValidateSignedAuthorization(authorization ethtypes.SetCodeAuthorization, options AuthorizationOptions) (common.Address, error) {
	if err := validateAuthorizationContext(authorization, options); err != nil {
		return common.Address{}, err
	}
	authority, err := authorization.Authority()
	if err != nil {
		return common.Address{}, fmt.Errorf("authorization authority: %w", err)
	}
	if options.ExpectedAuthority != nil && authority != *options.ExpectedAuthority {
		return common.Address{}, fmt.Errorf("authorization authority %s does not match expected authority %s", authority.Hex(), options.ExpectedAuthority.Hex())
	}
	return authority, nil
}

// SerializeAuthorization returns the canonical RLP encoding of geth's
// six-field signed authorization tuple.
func SerializeAuthorization(authorization ethtypes.SetCodeAuthorization) ([]byte, error) {
	if _, err := authorization.Authority(); err != nil {
		return nil, fmt.Errorf("authorization authority: %w", err)
	}
	serialized, err := rlp.EncodeToBytes(authorization)
	if err != nil {
		return nil, fmt.Errorf("serialize authorization: %w", err)
	}
	return serialized, nil
}

// ParseAuthorization decodes a canonical RLP authorization tuple and returns
// the authority recovered by geth.
func ParseAuthorization(serialized []byte) (ethtypes.SetCodeAuthorization, common.Address, error) {
	var authorization ethtypes.SetCodeAuthorization
	if err := rlp.DecodeBytes(serialized, &authorization); err != nil {
		return ethtypes.SetCodeAuthorization{}, common.Address{}, fmt.Errorf("decode authorization: %w", err)
	}
	authority, err := authorization.Authority()
	if err != nil {
		return ethtypes.SetCodeAuthorization{}, common.Address{}, fmt.Errorf("authorization authority: %w", err)
	}
	return authorization, authority, nil
}

func validateAuthorizationContext(authorization ethtypes.SetCodeAuthorization, options AuthorizationOptions) error {
	if options.ExecutionChainID != nil {
		if _, err := uint256Value("execution chain_id", options.ExecutionChainID, false); err != nil {
			return err
		}
	}
	if authorization.ChainID.IsZero() {
		if !options.AllowWildcard {
			return fmt.Errorf("wildcard authorization chain_id requires explicit permission")
		}
		return nil
	}
	if options.ExecutionChainID != nil && authorization.ChainID.ToBig().Cmp(options.ExecutionChainID) != 0 {
		return fmt.Errorf("authorization chain_id %s does not match execution chain_id %s", authorization.ChainID.ToBig(), options.ExecutionChainID)
	}
	return nil
}
