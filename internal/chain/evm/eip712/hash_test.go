package eip712

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/stretchr/testify/require"
)

func TestHashPermitMatchesERC2612AndGeth(t *testing.T) {
	// This type hash is the value published by the Uniswap V2 ERC-2612
	// implementation and is independently fixed here as a compatibility guard.
	typeHashData := newPermitTypedData(apitypes.TypedDataDomain{Name: "test"}, nil)
	require.Equal(t,
		"0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9",
		common.BytesToHash(typeHashData.TypeHash(PrimaryType)).Hex(),
	)

	hashes, err := HashPermit(testDomain, testMessage)
	require.NoError(t, err)

	chainID := ethmath.HexOrDecimal256(*big.NewInt(1))
	reference := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"Permit": {
				{Name: "owner", Type: "address"},
				{Name: "spender", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "nonce", Type: "uint256"},
				{Name: "deadline", Type: "uint256"},
			},
		},
		PrimaryType: "Permit",
		Domain: apitypes.TypedDataDomain{
			Name:              testDomain.Name,
			Version:           testDomain.Version,
			ChainId:           &chainID,
			VerifyingContract: testDomain.VerifyingContract,
		},
		Message: apitypes.TypedDataMessage{
			"owner":    testMessage.Owner,
			"spender":  testMessage.Spender,
			"value":    testMessage.Value,
			"nonce":    testMessage.Nonce,
			"deadline": testMessage.Deadline,
		},
	}
	domainSeparator, err := reference.HashStruct("EIP712Domain", reference.Domain.Map())
	require.NoError(t, err)
	structHash, err := reference.HashStruct("Permit", reference.Message)
	require.NoError(t, err)
	digest, _, err := apitypes.TypedDataAndHash(reference)
	require.NoError(t, err)

	require.Equal(t, common.BytesToHash(domainSeparator), hashes.DomainSeparator)
	require.Equal(t, common.BytesToHash(structHash), hashes.StructHash)
	require.Equal(t, common.BytesToHash(digest), hashes.Digest)

	// Literal outputs make the vector deterministic even if geth's generic
	// typed-data implementation changes in a future dependency upgrade.
	require.Equal(t, "0x8baf3ca6cb3e1553c0ab80e7cd3cc8237b8afb8cdf27a0e06c866517cea0b62c", hashes.DomainSeparator.Hex())
	require.Equal(t, "0xaa8e22808e48689838321c46fefee7ae880463e7354fd7ea101b79a5533724f4", hashes.StructHash.Hex())
	require.Equal(t, "0x83f78a1913150a156c62c6bde8a2aaeff986408f673034df02ee4b7587cda01f", hashes.Digest.Hex())
}

func TestRegisteredPermitMessageRejectsUnknownFields(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"owner": testMessage.Owner, "spender": testMessage.Spender, "value": testMessage.Value,
		"nonce": testMessage.Nonce, "deadline": testMessage.Deadline, "witness": "0x00",
	})
	require.NoError(t, err)
	_, err = HashPermitRaw(testDomain, raw)
	require.ErrorContains(t, err, `unknown field "witness"`)
}
