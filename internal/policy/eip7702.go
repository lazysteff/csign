package policy

import (
	"math"

	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedcodec"
	"github.com/chain-signer/chain-signer/internal/chain/evm/eip7702"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
)

func ValidateEVMEIP7702Authorization(key domain.Key, req *v1.EVMEIP7702AuthorizationSignRequest) error {
	prepared, err := advancedcodec.PrepareAuthorization(req.AuthorizationSchema, req.ChainID, req.Address, req.Nonce, req.AuthorityAddress)
	if err != nil {
		return faults.NewCode(faults.Invalid, faults.InvalidEIP7702Authorization, err.Error())
	}
	if err := validateAdvancedBase(key, req.ChainFamily, req.Network, req.RequestID, req.AuthorityAddress, req.ChainID, v1.OperationEVMEIP7702Authorization, prepared.Authorization.ChainID.IsZero()); err != nil {
		return err
	}
	if prepared.Authorization.ChainID.IsZero() && !key.Policy.AllowEIP7702ChainIDZero {
		return faults.New(faults.PolicyDenied, "EIP-7702 wildcard chain_id is not allowed")
	}
	return enforceEIP7702DelegatePolicy(key.Policy, req.Address)
}

func ValidateEVMEIP7702Transaction(key domain.Key, req *v1.EVMEIP7702TransactionSignRequest) error {
	if key.Policy.MaxAuthorizationListEntries > uint64(math.MaxInt) {
		return faults.New(faults.Invalid, "max_authorization_list_entries exceeds platform limits")
	}
	if key.Policy.MaxAuthorizationListEntries == 0 {
		return faults.New(faults.PolicyDenied, "max_authorization_list_entries must explicitly allow type-4 authorization entries")
	}
	if uint64(len(req.AuthorizationList)) > key.Policy.MaxAuthorizationListEntries {
		return faults.New(faults.PolicyDenied, "authorization_list exceeds configured maximum")
	}
	if err := validateAdvancedBase(key, req.ChainFamily, req.Network, req.RequestID, req.SourceAddress, req.ChainID, v1.OperationEVMEIP7702Transaction, false); err != nil {
		return err
	}
	if err := requireStringAllowed(key.Policy.AllowedTransactionTypes, v1.EIP7702TransactionTypeV1, "transaction type"); err != nil {
		return err
	}
	if err := requireAddressAllowed(key.Policy.AllowedContractDestinations, req.To, "transaction destination"); err != nil {
		return err
	}
	prepared, err := advancedcodec.PrepareTransaction(*req)
	if err != nil {
		return faults.NewCode(faults.Invalid, faults.InvalidAuthorizationList, err.Error())
	}
	expectedSigner := prepared.ExpectedSigner
	if _, err := eip7702.BuildTransaction(prepared.Transaction, eip7702.TransactionOptions{
		AllowWildcardAuthorizations: key.Policy.AllowEIP7702ChainIDZero,
		ExpectedAuthorities:         prepared.RecoveredAuthorities,
		ExpectedSigner:              &expectedSigner,
		MaxAuthorizationListEntries: int(key.Policy.MaxAuthorizationListEntries),
	}); err != nil {
		return faults.NewCode(faults.Invalid, faults.InvalidAuthorizationList, err.Error())
	}
	for index, authorization := range req.AuthorizationList {
		if prepared.Transaction.AuthList[index].ChainID.IsZero() && !key.Policy.AllowEIP7702ChainIDZero {
			return faults.Newf(faults.PolicyDenied, "authorization_list[%d] uses forbidden wildcard chain_id", index)
		}
		if err := enforceEIP7702DelegatePolicy(key.Policy, authorization.Address); err != nil {
			return err
		}
	}
	if err := enforceBigCap(req.Value, key.Policy.MaxValue, "value"); err != nil {
		return err
	}
	gasLimit, _ := enc.ParseCanonicalUint64("gas_limit", req.GasLimit)
	if err := enforceGasLimit(gasLimit, key.Policy.MaxGasLimit); err != nil {
		return err
	}
	if err := enforceBigCap(req.MaxFeePerGas, key.Policy.MaxFeePerGas, "max_fee_per_gas"); err != nil {
		return err
	}
	if err := enforceBigCap(req.MaxPriorityFeePerGas, key.Policy.MaxPriorityFeePerGas, "max_priority_fee_per_gas"); err != nil {
		return err
	}
	if len(key.Policy.AllowedSelectors) > 0 {
		selector, err := selectorFromCanonicalHex(prepared.Transaction.Data)
		if err != nil {
			return err
		}
		if err := enforceSelectorAllowlist(key.Policy, selector); err != nil {
			return err
		}
	}
	return nil
}

func enforceEIP7702DelegatePolicy(policy v1.Policy, delegate string) error {
	address, err := enc.ParseEVMAddress("address", delegate, true)
	if err != nil {
		return faults.Wrap(faults.Invalid, err)
	}
	if address == (common.Address{}) {
		if !policy.AllowEIP7702Revocation {
			return faults.NewCode(faults.PolicyDenied, faults.EIP7702RevocationNotAllowed, "EIP-7702 revocation is not allowed")
		}
		return nil
	}
	return requireAddressAllowed(policy.AllowedEIP7702Delegates, delegate, "EIP-7702 delegate")
}
