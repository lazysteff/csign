package advancedcodec

import (
	"encoding/json"
	"testing"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestPreparePermitMapsTypedContractAndChecksIdentities(t *testing.T) {
	domain := v1.EIP712Domain{
		Name:              "Token",
		Version:           "1",
		ChainID:           "1",
		VerifyingContract: codecContract,
	}
	message := v1.EIP2612PermitMessage{
		Owner:    codecSigner,
		Spender:  codecSpender,
		Value:    "10",
		Nonce:    "0",
		Deadline: "100",
	}

	prepared, err := PreparePermit(v1.EIP712SchemaEIP2612Permit, v1.EIP712SchemaEIP2612PermitVersion, "1", codecSigner, domain, message)
	require.NoError(t, err)
	require.Equal(t, domain, prepared.Domain)
	var decoded v1.EIP2612PermitMessage
	require.NoError(t, json.Unmarshal(prepared.Message, &decoded))
	require.Equal(t, message, decoded)
	require.Equal(t, common.HexToAddress(codecSigner), prepared.Expected)
	require.NotEqual(t, common.Hash{}, prepared.Hashes.DomainSeparator)
	require.NotEqual(t, common.Hash{}, prepared.Hashes.StructHash)
	require.NotEqual(t, common.Hash{}, prepared.Hashes.Digest)

	_, err = PreparePermit("arbitrary-schema", "1", "1", codecSigner, domain, message)
	require.ErrorContains(t, err, "unsupported EIP-712 schema")

	mismatchedDomain := domain
	mismatchedDomain.ChainID = "2"
	_, err = PreparePermit(v1.EIP712SchemaEIP2612Permit, v1.EIP712SchemaEIP2612PermitVersion, "1", codecSigner, mismatchedDomain, message)
	require.ErrorContains(t, err, "domain.chain_id does not match chain_id")

	mismatchedOwner := message
	mismatchedOwner.Owner = codecSender
	_, err = PreparePermit(v1.EIP712SchemaEIP2612Permit, v1.EIP712SchemaEIP2612PermitVersion, "1", codecSigner, domain, mismatchedOwner)
	require.ErrorContains(t, err, "permit owner does not match expected signer")
}
