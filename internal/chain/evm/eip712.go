package evm

import (
	"crypto/ecdsa"
	"strings"

	"github.com/lazysteff/csign/v2/internal/chain/evm/advancedcodec"
	"github.com/lazysteff/csign/v2/internal/chain/evm/eip712"
	"github.com/lazysteff/csign/v2/internal/cryptography"
	enc "github.com/lazysteff/csign/v2/internal/encoding"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
)

func PrepareEIP712(pub *ecdsa.PublicKey, req *v1.EVMEIP712SignRequest) (*cryptography.Prepared, error) {
	prepared, err := advancedcodec.PrepareEIP712(req.SchemaID, req.SchemaVersion, req.ChainID, req.ExpectedSignerAddress, req.Domain, req.Message)
	if err != nil {
		return nil, err
	}
	return &cryptography.Prepared{Payload: cryptography.NewPayload(cryptography.Digest, prepared.Hashes.Digest.Bytes()), Format: func(recoverable []byte) (any, error) {
		signature, err := eip712.FormatSignature(recoverable)
		if err != nil {
			return nil, err
		}
		recovered, err := eip712.VerifySigner(prepared.Hashes.Digest, signature.Bytes(), strings.ToLower(prepared.Expected.Hex()))
		if err != nil {
			return nil, err
		}
		return &v1.EVMEIP712SignResponse{
			EVMOperationResponseBase: operationResponse(req.KeyID, req.Network, v1.OperationEVMEIP712Typed, recovered, req.RequestID),
			SchemaID:                 req.SchemaID,
			SchemaVersion:            req.SchemaVersion,
			DomainSeparator:          prepared.Hashes.DomainSeparator.Hex(),
			StructHash:               prepared.Hashes.StructHash.Hex(),
			EIP712Digest:             prepared.Hashes.Digest.Hex(),
			Signature:                signature.Hex(),
			SignatureEncoding:        v1.SignatureEncodingRSV27,
			R:                        signature.R.Hex(),
			S:                        signature.S.Hex(),
			V:                        signature.V,
		}, nil
	}}, nil
}

func VerifyEIP712(req v1.EVMEIP712VerifyRequest) (*v1.EVMEIP712VerifyResponse, error) {
	prepared, err := advancedcodec.PrepareEIP712(req.SchemaID, req.SchemaVersion, req.ChainID, req.ExpectedSignerAddress, req.Domain, req.Message)
	if err != nil {
		return nil, err
	}
	raw, err := enc.DecodeCanonicalHex("signature", req.Signature, 65)
	if err != nil {
		return nil, err
	}
	recovered, err := eip712.RecoverSigner(prepared.Hashes.Digest, raw)
	if err != nil {
		return nil, err
	}
	return &v1.EVMEIP712VerifyResponse{
		EVMResponseContext: responseContext(req.Network, v1.OperationEVMEIP712Typed, req.RequestID),
		SchemaID:           req.SchemaID,
		SchemaVersion:      req.SchemaVersion,
		Digest:             prepared.Hashes.Digest.Hex(),
		RecoveredSigner:    canonicalAddress(recovered),
		SignatureValid:     recovered == prepared.Expected,
	}, nil
}
