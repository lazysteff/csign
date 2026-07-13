package evm

import (
	"context"
	"strings"

	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedcodec"
	"github.com/chain-signer/chain-signer/internal/chain/evm/eip712"
	"github.com/chain-signer/chain-signer/internal/custody"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

func SignEIP712(ctx context.Context, material custody.Material, req *v1.EVMEIP712SignRequest) (*v1.EVMEIP712SignResponse, error) {
	prepared, err := advancedcodec.PreparePermit(req.SchemaID, req.SchemaVersion, req.ChainID, req.ExpectedSignerAddress, req.Domain, req.Message)
	if err != nil {
		return nil, err
	}
	recoverable, err := custody.RecoverableSignature(ctx, material, prepared.Hashes.Digest.Bytes())
	if err != nil {
		return nil, err
	}
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
}

func VerifyEIP712(req v1.EVMEIP712VerifyRequest) (*v1.EVMEIP712VerifyResponse, error) {
	prepared, err := advancedcodec.PreparePermit(req.SchemaID, req.SchemaVersion, req.ChainID, req.ExpectedSignerAddress, req.Domain, req.Message)
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
