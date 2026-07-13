package advancedcodec

import (
	"fmt"

	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedregistry"
	"github.com/chain-signer/chain-signer/internal/chain/evm/eip712"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
)

type PreparedPermit struct {
	Domain   eip712.Domain
	Message  eip712.PermitMessage
	Hashes   eip712.Hashes
	Expected common.Address
}

func PreparePermit(schemaID, schemaVersion, topLevelChainID, expectedSigner string, domain v1.EIP712Domain, message v1.EIP2612PermitMessage) (PreparedPermit, error) {
	schema, err := advancedregistry.Default().EIP712Schema(schemaID, schemaVersion)
	if err != nil {
		return PreparedPermit{}, err
	}
	chainID, err := parseUint("chain_id", topLevelChainID, 256, false)
	if err != nil {
		return PreparedPermit{}, err
	}
	domainChainID, err := parseUint("domain.chain_id", domain.ChainID, 256, false)
	if err != nil {
		return PreparedPermit{}, err
	}
	if chainID.Cmp(domainChainID) != 0 {
		return PreparedPermit{}, fmt.Errorf("domain.chain_id does not match chain_id")
	}
	expected, err := parseAddress("expected_signer_address", expectedSigner, false)
	if err != nil {
		return PreparedPermit{}, err
	}
	owner, err := parseAddress("message.owner", message.Owner, false)
	if err != nil {
		return PreparedPermit{}, err
	}
	if expected != owner {
		return PreparedPermit{}, fmt.Errorf("permit owner does not match expected signer")
	}

	prepared := PreparedPermit{
		Domain:   domain,
		Message:  message,
		Expected: expected,
	}
	prepared.Hashes, err = schema.HashPermit(prepared.Domain, prepared.Message)
	if err != nil {
		return PreparedPermit{}, err
	}
	return prepared, nil
}
