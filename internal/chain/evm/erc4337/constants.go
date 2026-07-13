package erc4337

import (
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
)

const (
	// Version pins this implementation to the account-abstraction release whose
	// contract behavior it reproduces.
	Version    = "0.9.0"
	ProtocolID = v1.ERC4337ProtocolV09

	SimpleAccountImplementation        = v1.ERC4337AccountSimpleAccount
	SimpleAccountImplementationVersion = v1.ERC4337AccountSimpleAccountVersion
	SimpleAccountSigningSchema         = v1.ERC4337SimpleAccountSigningSchema
	SimpleAccountSignatureEncoding     = v1.SignatureEncodingRSV27

	// EntryPointAddressHex is the deterministic EntryPoint v0.9 deployment
	// published with account-abstraction v0.9.0.
	EntryPointAddressHex = v1.ERC4337EntryPointV09

	DomainName    = "ERC4337"
	DomainVersion = "1"

	PaymasterStaticFieldsLength = 52
	PaymasterSignatureMaxLength = 1<<16 - 1

	packedUserOperationPrimaryType = "PackedUserOperation"
)

var (
	eip7702InitCodeMarker = [...]byte{0x77, 0x02}
	paymasterSigMagic     = [...]byte{0x22, 0xe3, 0x25, 0xa2, 0x97, 0x43, 0x96, 0x56}
)

// EntryPointAddress returns the official deterministic v0.9 address.
func EntryPointAddress() common.Address {
	return common.HexToAddress(EntryPointAddressHex)
}
