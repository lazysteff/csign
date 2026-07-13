package policy

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/chain-signer/chain-signer/internal/chain/evm/eip7702"
	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func TestEIP7702AuthorizationPolicyRequiresDelegateRevocationAndWildcardOptIn(t *testing.T) {
	request := v1.EVMEIP7702AuthorizationSignRequest{
		EIP7702Authorization: v1.EIP7702Authorization{ChainID: "1", Address: advancedPolicyContract, Nonce: "0"},
		EVMKeyRequestContext: v1.EVMKeyRequestContext{
			EVMRequestContext: v1.EVMRequestContext{
				ChainFamily: v1.ChainFamilyEVM,
				Network:     advancedPolicyNetwork,
				RequestID:   "authorization-request",
			},
			KeyID: "advanced-key",
		},
		AuthorityAddress:    advancedPolicySigner,
		AuthorizationSchema: v1.EIP7702AuthorizationSchemaV1,
	}
	key := advancedPolicyKey(v1.Policy{})
	err := ValidateEVMEIP7702Authorization(key, &request)
	require.Equal(t, faults.SigningOperationNotAllowed, faults.CodeOf(err))

	key.Policy = v1.Policy{
		AllowedSigningOperations: []string{v1.OperationEVMEIP7702Authorization},
		AllowedNetworks:          []string{advancedPolicyNetwork},
		AllowedChainIDs:          []int64{1},
		AllowedEIP7702Delegates:  []string{advancedPolicyContract},
	}
	require.NoError(t, ValidateEVMEIP7702Authorization(key, &request))

	request.Address = "0x0000000000000000000000000000000000000000"
	err = ValidateEVMEIP7702Authorization(key, &request)
	require.Equal(t, faults.EIP7702RevocationNotAllowed, faults.CodeOf(err))
	key.Policy.AllowEIP7702Revocation = true
	require.NoError(t, ValidateEVMEIP7702Authorization(key, &request))

	request.Address = advancedPolicyContract
	request.ChainID = "0"
	err = ValidateEVMEIP7702Authorization(key, &request)
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.Empty(t, faults.CodeOf(err))
	require.ErrorContains(t, err, "wildcard chain_id")
	key.Policy.AllowEIP7702ChainIDZero = true
	require.NoError(t, ValidateEVMEIP7702Authorization(key, &request))
}

func TestEIP7702TransactionPolicyRejectsSelectorBypass(t *testing.T) {
	request := signedType4PolicyRequest(t)
	key := advancedPolicyKey(v1.Policy{
		AllowedSigningOperations:    []string{v1.OperationEVMEIP7702Transaction},
		AllowedNetworks:             []string{advancedPolicyNetwork},
		AllowedChainIDs:             []int64{1},
		AllowedEIP7702Delegates:     []string{advancedPolicyContract},
		AllowedTransactionTypes:     []string{v1.EIP7702TransactionTypeV1},
		AllowedContractDestinations: []string{advancedPolicySpender},
		MaxAuthorizationListEntries: 1,
	})
	require.NoError(t, ValidateEVMEIP7702Transaction(key, &request))

	key.Policy.AllowedSelectors = []string{"aabbccdd"}
	err := ValidateEVMEIP7702Transaction(key, &request)
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.ErrorContains(t, err, "4-byte selector")
	request.Data = "0xaabbccdd"
	require.NoError(t, ValidateEVMEIP7702Transaction(key, &request))
}

func TestEIP7702TransactionPolicyRejectsListBeforeSignatureRecovery(t *testing.T) {
	request := signedType4PolicyRequest(t)
	request.AuthorizationList[0].R = "malformed"
	key := advancedPolicyKey(v1.Policy{
		AllowedSigningOperations:    []string{v1.OperationEVMEIP7702Transaction},
		AllowedNetworks:             []string{advancedPolicyNetwork},
		AllowedChainIDs:             []int64{1},
		AllowedEIP7702Delegates:     []string{advancedPolicyContract},
		AllowedTransactionTypes:     []string{v1.EIP7702TransactionTypeV1},
		AllowedContractDestinations: []string{advancedPolicySpender},
	})

	err := ValidateEVMEIP7702Transaction(key, &request)
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.ErrorContains(t, err, "must explicitly allow")

	key.Policy.MaxAuthorizationListEntries = 1
	request.AuthorizationList = append(request.AuthorizationList, request.AuthorizationList[0])
	err = ValidateEVMEIP7702Transaction(key, &request)
	require.Equal(t, faults.PolicyDenied, faults.KindOf(err))
	require.ErrorContains(t, err, "exceeds configured maximum")
}

func TestEIP7702AuthorizationMismatchHasStableCode(t *testing.T) {
	request := v1.EVMEIP7702AuthorizationSignRequest{
		EIP7702Authorization: v1.EIP7702Authorization{ChainID: "1", Address: advancedPolicyContract, Nonce: "0"},
		EVMKeyRequestContext: v1.EVMKeyRequestContext{
			EVMRequestContext: v1.EVMRequestContext{ChainFamily: v1.ChainFamilyEVM, Network: advancedPolicyNetwork, RequestID: "mismatch"},
			KeyID:             "advanced-key",
		},
		AuthorityAddress:    "0x3000000000000000000000000000000000000003",
		AuthorizationSchema: v1.EIP7702AuthorizationSchemaV1,
	}
	key := advancedPolicyKey(v1.Policy{
		AllowedSigningOperations: []string{v1.OperationEVMEIP7702Authorization},
		AllowedNetworks:          []string{advancedPolicyNetwork},
		AllowedChainIDs:          []int64{1},
		AllowedEIP7702Delegates:  []string{advancedPolicyContract},
	})
	err := ValidateEVMEIP7702Authorization(key, &request)
	require.Equal(t, faults.AuthorizationSignerMismatch, faults.CodeOf(err))
}

func signedType4PolicyRequest(t *testing.T) v1.EVMEIP7702TransactionSignRequest {
	t.Helper()
	privateKey, err := crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000001")
	require.NoError(t, err)
	expected := crypto.PubkeyToAddress(privateKey.PublicKey)
	artifact, err := eip7702.SignAuthorization(context.Background(), custody.ExternalMaterial{
		Pub: &privateKey.PublicKey,
		SignFunc: func(_ context.Context, digest []byte) ([]byte, error) {
			return crypto.Sign(digest, privateKey)
		},
	}, ethtypes.SetCodeAuthorization{
		ChainID: *uint256.MustFromBig(big.NewInt(1)),
		Address: common.HexToAddress(advancedPolicyContract),
		Nonce:   0,
	}, eip7702.AuthorizationOptions{ExpectedAuthority: &expected})
	require.NoError(t, err)

	return v1.EVMEIP7702TransactionSignRequest{
		EVMKeyRequestContext: v1.EVMKeyRequestContext{
			EVMRequestContext: v1.EVMRequestContext{
				ChainFamily: v1.ChainFamilyEVM,
				Network:     advancedPolicyNetwork,
				RequestID:   "type4-policy-request",
			},
			KeyID: "advanced-key",
		},
		EIP7702TransactionFields: v1.EIP7702TransactionFields{
			ChainID:              "1",
			Nonce:                "0",
			To:                   advancedPolicySpender,
			Value:                "0",
			GasLimit:             "100000",
			MaxFeePerGas:         "100",
			MaxPriorityFeePerGas: "2",
			Data:                 "0x",
			AccessList:           []v1.EVMAccessTuple{},
		},
		SourceAddress: advancedPolicySigner,
		AuthorizationList: []v1.EIP7702SignedAuthorization{{
			EIP7702Authorization: v1.EIP7702Authorization{ChainID: "1", Address: advancedPolicyContract, Nonce: "0"},
			YParity:              artifact.Authorization.V,
			R:                    fmt.Sprintf("0x%064x", artifact.Authorization.R.ToBig()),
			S:                    fmt.Sprintf("0x%064x", artifact.Authorization.S.ToBig()),
		}},
	}
}
