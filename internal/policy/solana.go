package policy

import (
	"strings"

	"github.com/lazysteff/csign/v2/internal/chain/solana"
	"github.com/lazysteff/csign/v2/internal/custody"
	"github.com/lazysteff/csign/v2/internal/domain"
	"github.com/lazysteff/csign/v2/internal/faults"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
)

func ValidateSolanaMessage(key domain.Key, request any) error {
	req, ok := request.(*v1.SolanaMessageSignRequest)
	if !ok {
		return faults.New(faults.Invalid, "invalid Solana message request")
	}
	if !key.Active {
		return faults.New(faults.PolicyDenied, "key is disabled")
	}
	if req.ChainFamily != v1.ChainFamilySolana {
		return faults.New(faults.Invalid, "chain_family does not match registered operation")
	}
	if key.ChainFamily != "" && key.ChainFamily != v1.ChainFamilySolana {
		return faults.New(faults.PolicyDenied, "key protocol binding denies operation")
	}
	if strings.TrimSpace(req.Network) == "" || strings.TrimSpace(req.RequestID) == "" {
		return faults.New(faults.Invalid, "network and request_id are required")
	}
	if err := enforceNetwork(key.Policy, req.Network, nil); err != nil {
		return err
	}
	pub, err := custody.CanonicalPublicKey(key)
	if err != nil {
		return faults.New(faults.Invalid, "invalid managed public key")
	}
	identity, err := solana.DeriveAddress(pub)
	if err != nil {
		return faults.New(faults.PolicyDenied, "incompatible protocol identity")
	}
	if req.ExpectedSignerAddress != "" && !solana.EqualAddress(identity, req.ExpectedSignerAddress) {
		return faults.New(faults.Invalid, "expected_signer_address does not match resolved key")
	}
	return nil
}
