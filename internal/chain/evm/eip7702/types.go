package eip7702

import (
	"math/big"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
)

const (
	// AuthorizationSchemaV1 identifies the EIP-7702 authorization format
	// whose signing payload is 0x05 || rlp([chain_id, address, nonce]).
	AuthorizationSchemaV1 = v1.EIP7702AuthorizationSchemaV1

	// TransactionType is the EIP-7702 set-code transaction envelope type.
	TransactionType = ethtypes.SetCodeTxType
)

// AuthorizationOptions supplies context that is not part of the signed
// authorization itself.
type AuthorizationOptions struct {
	// ExecutionChainID, when set, requires a non-wildcard authorization to
	// target this chain. It must be a positive uint256.
	ExecutionChainID *big.Int

	// AllowWildcard permits authorization ChainID zero. It is false by
	// default so a wildcard authorization always requires an explicit choice.
	AllowWildcard bool

	// ExpectedAuthority, when set, must match both the custody material and
	// the address recovered from the final signature.
	ExpectedAuthority *common.Address
}

// AuthorizationArtifact contains all deterministic products of signing an
// authorization.
type AuthorizationArtifact struct {
	Authorization ethtypes.SetCodeAuthorization
	SigningHash   common.Hash
	Authority     common.Address
	Serialized    []byte
}

// TransactionOptions controls contextual validation for type-4 transaction
// construction, signing, and recovery.
type TransactionOptions struct {
	// AllowWildcardAuthorizations permits chain-id-zero authorizations in the
	// transaction's authorization list.
	AllowWildcardAuthorizations bool

	// ExpectedAuthorities, when non-empty, must contain one authority per
	// authorization-list entry in the same order.
	ExpectedAuthorities []common.Address

	// ExpectedSigner, when set, must match the executor custody material and
	// the recovered transaction signer.
	ExpectedSigner *common.Address

	// MaxAuthorizationListEntries applies an optional application limit. Zero
	// means no extra limit; negative values are invalid.
	MaxAuthorizationListEntries int
}

// TransactionArtifact is the verified result of signing or recovering a
// type-4 transaction.
type TransactionArtifact struct {
	Transaction     *ethtypes.Transaction
	SigningHash     common.Hash
	TransactionHash common.Hash
	Signer          common.Address
	Authorities     []common.Address
	SignedPayload   []byte
}
