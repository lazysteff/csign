package tron

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/chain-signer/chain-signer/internal/cryptography"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func prepareTRONOwnerTransaction(
	pub *ecdsa.PublicKey,
	keyID, network, requestID, operation string,
	contractType core.Transaction_Contract_ContractType,
	contract proto.Message,
	envelope v1.TRONRawDataEnvelope,
) (*cryptography.Prepared, error) {
	typed, err := anypb.New(contract)
	if err != nil {
		return nil, fmt.Errorf("wrap tron owner contract: %w", err)
	}
	tx, err := buildTransaction(
		contractType,
		typed,
		envelope.RefBlockBytes,
		envelope.RefBlockHash,
		0,
		envelope.Timestamp,
		envelope.Expiration,
		envelope.FeeLimitOrZero(),
	)
	if err != nil {
		return nil, err
	}
	return prepareTransaction(pub, keyID, network, requestID, operation, tx)
}
