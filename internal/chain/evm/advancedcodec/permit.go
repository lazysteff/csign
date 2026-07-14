package advancedcodec

import (
	"encoding/json"

	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedregistry"
	"github.com/chain-signer/chain-signer/internal/chain/evm/eip712"
	"github.com/chain-signer/chain-signer/internal/faults"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
)

type PreparedEIP712 struct {
	Domain   eip712.Domain
	Message  json.RawMessage
	Hashes   eip712.Hashes
	Expected common.Address
}

func PrepareEIP712(schemaID, schemaVersion, topLevelChainID, expectedSigner string, domain v1.EIP712Domain, message json.RawMessage) (PreparedEIP712, error) {
	schema, err := advancedregistry.Default().EIP712Schema(schemaID, schemaVersion)
	if err != nil {
		return PreparedEIP712{}, err
	}
	chainID, err := parseUint("chain_id", topLevelChainID, 256, false)
	if err != nil {
		return PreparedEIP712{}, err
	}
	domainChainID, err := parseUint("domain.chain_id", domain.ChainID, 256, false)
	if err != nil {
		return PreparedEIP712{}, err
	}
	if chainID.Cmp(domainChainID) != 0 {
		return PreparedEIP712{}, faults.New(faults.Invalid, "domain.chain_id does not match chain_id")
	}
	expected, err := parseAddress("expected_signer_address", expectedSigner, false)
	if err != nil {
		return PreparedEIP712{}, err
	}
	if err := schema.ValidateSigner(expected, message); err != nil {
		return PreparedEIP712{}, err
	}

	prepared := PreparedEIP712{
		Domain:   domain,
		Message:  message,
		Expected: expected,
	}
	prepared.Hashes, err = schema.HashMessage(prepared.Domain, prepared.Message)
	if err != nil {
		return PreparedEIP712{}, err
	}
	return prepared, nil
}

type PreparedPermit = PreparedEIP712

func PreparePermit(schemaID, schemaVersion, topLevelChainID, expectedSigner string, domain v1.EIP712Domain, message v1.EIP2612PermitMessage) (PreparedPermit, error) {
	raw, err := json.Marshal(message)
	if err != nil {
		return PreparedPermit{}, faults.Newf(faults.Internal, "encode Permit message: %v", err)
	}
	return PrepareEIP712(schemaID, schemaVersion, topLevelChainID, expectedSigner, domain, raw)
}
