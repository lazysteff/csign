// Package eip712 implements explicitly registered EIP-712 schemas.
//
// This package intentionally does not expose a generic typed-data encoder. Its
// first schema is the fixed ERC-2612 Permit structure identified by SchemaID.
package eip712

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"

	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
	ethmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

const (
	// SchemaID is the immutable identifier for this constrained ERC-2612
	// Permit schema. Changing any field, field order, or hashing rule requires
	// a new identifier.
	SchemaID = v1.EIP712SchemaEIP2612Permit

	// SchemaVersion is the human-readable version of SchemaID.
	SchemaVersion = v1.EIP712SchemaEIP2612PermitVersion

	// PrimaryType is the only EIP-712 primary type supported by this schema.
	PrimaryType = "Permit"

	// SignatureEncoding identifies the returned 65-byte r || s || v encoding.
	// The v byte is encoded as 27 or 28.
	SignatureEncoding = v1.SignatureEncodingRSV27

	PermitDefinition = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)|Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)|signature=rsv-v27"
)

func PermitDefinitionHash() string { return crypto.Keccak256Hash([]byte(PermitDefinition)).Hex() }

// Domain contains exactly the EIP-712 domain fields admitted by SchemaID.
// ChainID is a canonical, positive base-10 uint256 string.
type Domain = v1.EIP712Domain

// PermitMessage contains exactly the fixed ERC-2612 Permit fields admitted by
// SchemaID. Value, Nonce, and Deadline are canonical base-10 uint256 strings.
type PermitMessage = v1.EIP2612PermitMessage

// Hashes contains each independently inspectable EIP-712 hash produced by the
// constrained schema.
type Hashes struct {
	DomainSeparator common.Hash
	StructHash      common.Hash
	Digest          common.Hash
}

// HashPermit validates the fixed domain and message and constructs the
// ERC-2612 signing digest: keccak256(0x1901 || domainSeparator || structHash).
func HashPermit(domain Domain, message PermitMessage) (Hashes, error) {
	typedDomain, err := parseDomain(domain)
	if err != nil {
		return Hashes{}, err
	}
	typedMessage, err := parsePermitMessage(message)
	if err != nil {
		return Hashes{}, err
	}
	typedData := newPermitTypedData(typedDomain, typedMessage)
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return Hashes{}, fmt.Errorf("hash EIP-712 domain: %w", err)
	}
	structHash, err := typedData.HashStruct(PrimaryType, typedData.Message)
	if err != nil {
		return Hashes{}, fmt.Errorf("hash ERC-2612 Permit: %w", err)
	}
	digest, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return Hashes{}, fmt.Errorf("hash ERC-2612 typed data: %w", err)
	}

	return Hashes{
		DomainSeparator: common.BytesToHash(domainSeparator),
		StructHash:      common.BytesToHash(structHash),
		Digest:          common.BytesToHash(digest),
	}, nil
}

func HashPermitRaw(domain Domain, raw json.RawMessage) (Hashes, error) {
	message, err := DecodePermitMessage(raw)
	if err != nil {
		return Hashes{}, faults.Newf(faults.Invalid, "decode registered Permit message: %v", err)
	}
	return HashPermit(domain, message)
}

func ValidatePermitSigner(expected common.Address, raw json.RawMessage) error {
	message, err := DecodePermitMessage(raw)
	if err != nil {
		return faults.Newf(faults.Invalid, "decode registered Permit message: %v", err)
	}
	owner, err := enc.ParseEVMAddress("permit owner", message.Owner, false)
	if err != nil {
		return err
	}
	if expected != owner {
		return faults.New(faults.Invalid, "permit owner does not match expected signer")
	}
	return nil
}

func DecodePermitMessage(raw json.RawMessage) (PermitMessage, error) {
	return decodeFixedMessage[PermitMessage](raw)
}

// DomainSeparator validates and hashes the schema's fixed EIP-712 domain.
func DomainSeparator(domain Domain) (common.Hash, error) {
	typedDomain, err := parseDomain(domain)
	if err != nil {
		return common.Hash{}, err
	}
	typedData := newPermitTypedData(typedDomain, nil)
	hash, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return common.Hash{}, fmt.Errorf("hash EIP-712 domain: %w", err)
	}
	return common.BytesToHash(hash), nil
}

// PermitStructHash validates and hashes the schema's fixed Permit message.
func PermitStructHash(message PermitMessage) (common.Hash, error) {
	typedMessage, err := parsePermitMessage(message)
	if err != nil {
		return common.Hash{}, err
	}
	// apitypes validates that a domain exists before hashing any struct. The
	// placeholder is not part of the Permit hash and is never exposed.
	typedData := newPermitTypedData(apitypes.TypedDataDomain{Name: "ERC-2612"}, typedMessage)
	hash, err := typedData.HashStruct(PrimaryType, typedData.Message)
	if err != nil {
		return common.Hash{}, fmt.Errorf("hash ERC-2612 Permit: %w", err)
	}
	return common.BytesToHash(hash), nil
}

func parseDomain(domain Domain) (apitypes.TypedDataDomain, error) {
	if err := validateDomainString("domain name", domain.Name); err != nil {
		return apitypes.TypedDataDomain{}, err
	}
	if err := validateDomainString("domain version", domain.Version); err != nil {
		return apitypes.TypedDataDomain{}, err
	}
	chainID, err := enc.ParseCanonicalUint("domain chain ID", domain.ChainID, 256, false)
	if err != nil {
		return apitypes.TypedDataDomain{}, err
	}
	_, err = enc.ParseEVMAddress("domain verifying contract", domain.VerifyingContract, false)
	if err != nil {
		return apitypes.TypedDataDomain{}, err
	}
	typedChainID := ethmath.HexOrDecimal256(*chainID)
	return apitypes.TypedDataDomain{
		Name:              domain.Name,
		Version:           domain.Version,
		ChainId:           &typedChainID,
		VerifyingContract: domain.VerifyingContract,
	}, nil
}

func parsePermitMessage(message PermitMessage) (apitypes.TypedDataMessage, error) {
	owner, err := enc.ParseEVMAddress("permit owner", message.Owner, false)
	if err != nil {
		return nil, err
	}
	spender, err := enc.ParseEVMAddress("permit spender", message.Spender, true)
	if err != nil {
		return nil, err
	}
	value, err := enc.ParseCanonicalUint("permit value", message.Value, 256, true)
	if err != nil {
		return nil, err
	}
	nonce, err := enc.ParseCanonicalUint("permit nonce", message.Nonce, 256, true)
	if err != nil {
		return nil, err
	}
	deadline, err := enc.ParseCanonicalUint("permit deadline", message.Deadline, 256, true)
	if err != nil {
		return nil, err
	}
	return apitypes.TypedDataMessage{
		"owner":    owner.Bytes(),
		"spender":  spender.Bytes(),
		"value":    value,
		"nonce":    nonce,
		"deadline": deadline,
	}, nil
}

func validateDomainString(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s must be valid UTF-8", field)
	}
	return nil
}

func newPermitTypedData(domain apitypes.TypedDataDomain, message apitypes.TypedDataMessage) apitypes.TypedData {
	return apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			PrimaryType: {
				{Name: "owner", Type: "address"},
				{Name: "spender", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "nonce", Type: "uint256"},
				{Name: "deadline", Type: "uint256"},
			},
		},
		PrimaryType: PrimaryType,
		Domain:      domain,
		Message:     message,
	}
}

func decodeFixedMessage[T any](raw json.RawMessage) (T, error) {
	var value T
	if len(bytes.TrimSpace(raw)) == 0 {
		return value, faults.New(faults.Invalid, "message is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return value, faults.New(faults.Invalid, "unexpected trailing JSON value")
		}
		return value, err
	}
	return value, nil
}
