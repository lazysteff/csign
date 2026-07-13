package eip7702

import (
	"context"
	"fmt"
	"math"
	"math/big"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
)

// BuildTransaction validates geth's canonical EIP-7702 transaction data and
// constructs an unsigned type-4 transaction.
func BuildTransaction(transaction *ethtypes.SetCodeTx, options TransactionOptions) (*ethtypes.Transaction, error) {
	built, err := prepareTransaction(transaction, options)
	return built, err
}

// TransactionSigningHash reconstructs the type-4 transaction signing hash
// from canonical geth transaction data.
func TransactionSigningHash(transaction *ethtypes.SetCodeTx, options TransactionOptions) (common.Hash, error) {
	built, err := prepareTransaction(transaction, options)
	if err != nil {
		return common.Hash{}, err
	}
	return ethtypes.NewPragueSigner(built.ChainId()).Hash(built), nil
}

// SignTransaction validates and signs a type-4 transaction through custody,
// then verifies it with geth's canonical sender and authorization recovery.
func SignTransaction(ctx context.Context, material custody.Material, transaction *ethtypes.SetCodeTx, options TransactionOptions) (*TransactionArtifact, error) {
	built, err := prepareTransaction(transaction, options)
	if err != nil {
		return nil, err
	}
	signer := ethtypes.NewPragueSigner(built.ChainId())
	signingHash := signer.Hash(built)
	signature, err := custody.RecoverableSignature(ctx, material, signingHash[:])
	if err != nil {
		return nil, err
	}
	signed, err := built.WithSignature(signer, signature)
	if err != nil {
		return nil, fmt.Errorf("attach type-4 transaction signature: %w", err)
	}
	artifact, err := recoverTransaction(signed, options)
	if err != nil {
		return nil, fmt.Errorf("verify signed type-4 transaction: %w", err)
	}
	if artifact.SigningHash != signingHash {
		return nil, fmt.Errorf("verified transaction signing hash changed after signing")
	}
	return artifact, nil
}

// RecoverTransaction decodes and verifies a signed EIP-7702 transaction using
// geth's canonical transaction and authorization types.
func RecoverTransaction(signedPayload []byte, options TransactionOptions) (*TransactionArtifact, error) {
	if len(signedPayload) == 0 {
		return nil, fmt.Errorf("signed type-4 transaction payload is required")
	}
	var transaction ethtypes.Transaction
	if err := transaction.UnmarshalBinary(signedPayload); err != nil {
		return nil, fmt.Errorf("decode type-4 transaction: %w", err)
	}
	return recoverTransaction(&transaction, options)
}

func SerializeTransaction(transaction *ethtypes.Transaction) ([]byte, error) {
	if transaction == nil {
		return nil, fmt.Errorf("type-4 transaction is required")
	}
	if transaction.Type() != TransactionType {
		return nil, fmt.Errorf("transaction type %d is not EIP-7702 type %d", transaction.Type(), TransactionType)
	}
	payload, err := transaction.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("serialize type-4 transaction: %w", err)
	}
	return payload, nil
}

func prepareTransaction(transaction *ethtypes.SetCodeTx, options TransactionOptions) (*ethtypes.Transaction, error) {
	if transaction == nil {
		return nil, fmt.Errorf("type-4 transaction is required")
	}
	if transaction.ChainID == nil || transaction.ChainID.IsZero() {
		return nil, fmt.Errorf("transaction chain_id must be positive")
	}
	if transaction.Nonce == math.MaxUint64 {
		return nil, fmt.Errorf("transaction nonce must be less than 2^64-1")
	}
	if transaction.GasTipCap == nil {
		return nil, fmt.Errorf("max_priority_fee_per_gas is required")
	}
	if transaction.GasFeeCap == nil {
		return nil, fmt.Errorf("max_fee_per_gas is required")
	}
	if transaction.GasTipCap.Cmp(transaction.GasFeeCap) > 0 {
		return nil, fmt.Errorf("max_priority_fee_per_gas exceeds max_fee_per_gas")
	}
	if transaction.Value == nil {
		return nil, fmt.Errorf("transaction value is required")
	}
	if transaction.Gas == 0 {
		return nil, fmt.Errorf("gas_limit must be positive")
	}
	_, err := validateAuthorizationList(transaction.AuthList, transaction.ChainID.ToBig(), options)
	if err != nil {
		return nil, err
	}
	return ethtypes.NewTx(transaction), nil
}

func recoverTransaction(transaction *ethtypes.Transaction, options TransactionOptions) (*TransactionArtifact, error) {
	if transaction == nil {
		return nil, fmt.Errorf("type-4 transaction is required")
	}
	if transaction.Type() != TransactionType {
		return nil, fmt.Errorf("transaction type %d is not EIP-7702 type %d", transaction.Type(), TransactionType)
	}
	if transaction.To() == nil {
		return nil, fmt.Errorf("type-4 transaction destination is required")
	}
	if transaction.ChainId() == nil || transaction.ChainId().Sign() <= 0 {
		return nil, fmt.Errorf("transaction chain_id must be positive")
	}
	if transaction.Nonce() == math.MaxUint64 {
		return nil, fmt.Errorf("transaction nonce must be less than 2^64-1")
	}
	if transaction.GasTipCap().Cmp(transaction.GasFeeCap()) > 0 {
		return nil, fmt.Errorf("max_priority_fee_per_gas exceeds max_fee_per_gas")
	}
	if transaction.Gas() == 0 {
		return nil, fmt.Errorf("gas_limit must be positive")
	}
	authorities, err := validateAuthorizationList(transaction.SetCodeAuthorizations(), transaction.ChainId(), options)
	if err != nil {
		return nil, err
	}

	signer := ethtypes.NewPragueSigner(transaction.ChainId())
	recovered, err := ethtypes.Sender(signer, transaction)
	if err != nil {
		return nil, fmt.Errorf("recover type-4 transaction signer: %w", err)
	}
	if options.ExpectedSigner != nil && recovered != *options.ExpectedSigner {
		return nil, fmt.Errorf("recovered signer %s does not match expected signer %s", recovered.Hex(), options.ExpectedSigner.Hex())
	}
	payload, err := SerializeTransaction(transaction)
	if err != nil {
		return nil, err
	}
	return &TransactionArtifact{
		Transaction:     transaction,
		SigningHash:     signer.Hash(transaction),
		TransactionHash: transaction.Hash(),
		Signer:          recovered,
		Authorities:     authorities,
		SignedPayload:   payload,
	}, nil
}

func validateAuthorizationList(authorizations []ethtypes.SetCodeAuthorization, chainID *big.Int, options TransactionOptions) ([]common.Address, error) {
	if len(authorizations) == 0 {
		return nil, fmt.Errorf("authorization_list must not be empty")
	}
	if options.MaxAuthorizationListEntries < 0 {
		return nil, fmt.Errorf("max authorization-list entries must not be negative")
	}
	if options.MaxAuthorizationListEntries > 0 && len(authorizations) > options.MaxAuthorizationListEntries {
		return nil, fmt.Errorf("authorization_list contains %d entries, maximum is %d", len(authorizations), options.MaxAuthorizationListEntries)
	}
	if len(options.ExpectedAuthorities) > 0 && len(options.ExpectedAuthorities) != len(authorizations) {
		return nil, fmt.Errorf("expected authorities count %d does not match authorization_list count %d", len(options.ExpectedAuthorities), len(authorizations))
	}

	authorities := make([]common.Address, 0, len(authorizations))
	seen := make(map[common.Address]struct{}, len(authorizations))
	for index, authorization := range authorizations {
		validation := AuthorizationOptions{ExecutionChainID: chainID, AllowWildcard: options.AllowWildcardAuthorizations}
		if len(options.ExpectedAuthorities) > 0 {
			expected := options.ExpectedAuthorities[index]
			validation.ExpectedAuthority = &expected
		}
		authority, err := ValidateSignedAuthorization(authorization, validation)
		if err != nil {
			return nil, fmt.Errorf("authorization_list[%d]: %w", index, err)
		}
		if _, duplicate := seen[authority]; duplicate {
			return nil, fmt.Errorf("authorization_list[%d] duplicates or conflicts with authority %s", index, authority.Hex())
		}
		seen[authority] = struct{}{}
		authorities = append(authorities, authority)
	}
	return authorities, nil
}
