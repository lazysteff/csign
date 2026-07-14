package eip712

import (
	"encoding/json"
	"strings"

	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

const (
	VerifyingPaymasterApprovalSchemaID        = "verifying-paymaster-approval-v1"
	VerifyingPaymasterApprovalSchemaVersion   = "1"
	VerifyingPaymasterApprovalPrimaryType     = "VerifyingPaymasterApproval"
	VerifyingPaymasterApprovalDomainName      = "VerifyingPaymaster"
	VerifyingPaymasterApprovalDomainVersion   = "1"
	VerifyingPaymasterApprovalSignatureFormat = v1.SignatureEncodingRSV27

	// The definition string is part of the compiled schema registration. Any
	// field, ordering, domain, or encoding change requires a new ID or version.
	VerifyingPaymasterApprovalDefinition = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)|VerifyingPaymasterApproval(uint256 chainId,address entryPoint,address paymaster,bytes32 userOpHash,uint48 validAfter,uint48 validUntil,uint256 maxSponsoredCost,bytes32 approvalNonce,bytes32 contextHash)|domain.name=VerifyingPaymaster|domain.version=1|signature=rsv-v27"
)

// VerifyingPaymasterApproval is owned by this registered schema module. It is
// deliberately absent from CSign's reusable API envelope.
type VerifyingPaymasterApproval struct {
	ChainID          string `json:"chain_id"`
	EntryPoint       string `json:"entry_point"`
	Paymaster        string `json:"paymaster"`
	UserOpHash       string `json:"user_op_hash"`
	ValidAfter       string `json:"valid_after"`
	ValidUntil       string `json:"valid_until"`
	MaxSponsoredCost string `json:"max_sponsored_cost"`
	Nonce            string `json:"approval_nonce"`
	ContextHash      string `json:"context_hash"`
}

func VerifyingPaymasterApprovalDefinitionHash() string {
	return crypto.Keccak256Hash([]byte(VerifyingPaymasterApprovalDefinition)).Hex()
}

func HashVerifyingPaymasterApproval(domain Domain, message VerifyingPaymasterApproval) (Hashes, error) {
	if domain.Name != VerifyingPaymasterApprovalDomainName {
		return Hashes{}, faults.Newf(faults.Invalid, "domain name must be %q", VerifyingPaymasterApprovalDomainName)
	}
	if domain.Version != VerifyingPaymasterApprovalDomainVersion {
		return Hashes{}, faults.Newf(faults.Invalid, "domain version must be %q", VerifyingPaymasterApprovalDomainVersion)
	}
	typedDomain, err := parseDomain(domain)
	if err != nil {
		return Hashes{}, err
	}
	chainID, err := enc.ParseCanonicalUint("approval chain ID", message.ChainID, 256, false)
	if err != nil {
		return Hashes{}, err
	}
	domainChainID, err := enc.ParseCanonicalUint("domain chain ID", domain.ChainID, 256, false)
	if err != nil {
		return Hashes{}, err
	}
	if chainID.Cmp(domainChainID) != 0 {
		return Hashes{}, faults.New(faults.Invalid, "message.chain_id does not match domain.chain_id")
	}
	entryPoint, err := enc.ParseEVMAddress("approval EntryPoint", message.EntryPoint, false)
	if err != nil {
		return Hashes{}, err
	}
	paymaster, err := enc.ParseEVMAddress("approval Paymaster", message.Paymaster, false)
	if err != nil {
		return Hashes{}, err
	}
	domainContract, err := enc.ParseEVMAddress("domain verifying contract", domain.VerifyingContract, false)
	if err != nil {
		return Hashes{}, err
	}
	if paymaster != domainContract {
		return Hashes{}, faults.New(faults.Invalid, "message.paymaster does not match domain.verifying_contract")
	}
	userOpHash, err := enc.DecodeCanonicalHex("approval UserOperation hash", message.UserOpHash, 32)
	if err != nil {
		return Hashes{}, err
	}
	validAfter, err := enc.ParseCanonicalUint("approval validAfter", message.ValidAfter, 48, true)
	if err != nil {
		return Hashes{}, err
	}
	validUntil, err := enc.ParseCanonicalUint("approval validUntil", message.ValidUntil, 48, false)
	if err != nil {
		return Hashes{}, err
	}
	if validUntil.Cmp(validAfter) <= 0 {
		return Hashes{}, faults.New(faults.Invalid, "approval validUntil must be greater than validAfter")
	}
	maxCost, err := enc.ParseCanonicalUint("approval maximum sponsored cost", message.MaxSponsoredCost, 256, false)
	if err != nil {
		return Hashes{}, err
	}
	approvalNonce, err := enc.DecodeCanonicalHex("approval nonce", message.Nonce, 32)
	if err != nil {
		return Hashes{}, err
	}
	contextHash, err := enc.DecodeCanonicalHex("approval context hash", message.ContextHash, 32)
	if err != nil {
		return Hashes{}, err
	}
	typedData := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			VerifyingPaymasterApprovalPrimaryType: {
				{Name: "chainId", Type: "uint256"},
				{Name: "entryPoint", Type: "address"},
				{Name: "paymaster", Type: "address"},
				{Name: "userOpHash", Type: "bytes32"},
				{Name: "validAfter", Type: "uint48"},
				{Name: "validUntil", Type: "uint48"},
				{Name: "maxSponsoredCost", Type: "uint256"},
				{Name: "approvalNonce", Type: "bytes32"},
				{Name: "contextHash", Type: "bytes32"},
			},
		},
		PrimaryType: VerifyingPaymasterApprovalPrimaryType,
		Domain:      typedDomain,
		Message: apitypes.TypedDataMessage{
			"chainId":          chainID,
			"entryPoint":       entryPoint.Bytes(),
			"paymaster":        paymaster.Bytes(),
			"userOpHash":       userOpHash,
			"validAfter":       validAfter,
			"validUntil":       validUntil,
			"maxSponsoredCost": maxCost,
			"approvalNonce":    approvalNonce,
			"contextHash":      contextHash,
		},
	}
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return Hashes{}, faults.Newf(faults.Internal, "hash EIP-712 domain: %v", err)
	}
	structHash, err := typedData.HashStruct(VerifyingPaymasterApprovalPrimaryType, typedData.Message)
	if err != nil {
		return Hashes{}, faults.Newf(faults.Internal, "hash verifying Paymaster approval: %v", err)
	}
	digest, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return Hashes{}, faults.Newf(faults.Internal, "hash verifying Paymaster approval typed data: %v", err)
	}
	return Hashes{
		DomainSeparator: common.BytesToHash(domainSeparator),
		StructHash:      common.BytesToHash(structHash),
		Digest:          common.BytesToHash(digest),
	}, nil
}

func HashVerifyingPaymasterApprovalRaw(domain Domain, raw json.RawMessage) (Hashes, error) {
	message, err := decodeFixedMessage[VerifyingPaymasterApproval](raw)
	if err != nil {
		return Hashes{}, faults.Newf(faults.Invalid, "decode registered VerifyingPaymasterApproval message: %v", err)
	}
	return HashVerifyingPaymasterApproval(domain, message)
}

// ValidateVerifyingPaymasterApprovalPolicy projects the schema's EntryPoint
// field onto CSign's existing neutral EntryPoint allowlist. The reusable
// policy engine remains unaware of Paymaster-specific message structure.
func ValidateVerifyingPaymasterApprovalPolicy(policy v1.Policy, raw json.RawMessage) error {
	message, err := decodeFixedMessage[VerifyingPaymasterApproval](raw)
	if err != nil {
		return faults.Newf(faults.Invalid, "decode registered VerifyingPaymasterApproval message: %v", err)
	}
	entryPoint, err := enc.ParseEVMAddress("approval EntryPoint", message.EntryPoint, false)
	if err != nil {
		return err
	}
	for _, allowed := range policy.AllowedEntryPoints {
		candidate, parseErr := enc.ParseEVMAddress("allowed EntryPoint", strings.TrimSpace(allowed), false)
		if parseErr == nil && candidate == entryPoint {
			return nil
		}
	}
	if len(policy.AllowedEntryPoints) == 0 {
		return faults.New(faults.PolicyDenied, "approval EntryPoint is not explicitly allowed")
	}
	return faults.Newf(faults.PolicyDenied, "approval EntryPoint %q is not allowed", message.EntryPoint)
}
