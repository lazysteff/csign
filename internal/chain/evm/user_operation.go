package evm

import (
	"context"
	"fmt"

	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedcodec"
	"github.com/chain-signer/chain-signer/internal/chain/evm/erc4337"
	"github.com/chain-signer/chain-signer/internal/custody"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

func SignUserOperation(ctx context.Context, material custody.Material, req *v1.EVMUserOperationSignRequest) (*v1.EVMUserOperationSignResponse, error) {
	prepared, err := advancedcodec.PrepareUserOperation(req.ProtocolVersion, req.AccountImplementation, req.AccountImplementationVersion, req.AccountSigningSchema, req.ChainID, req.EntryPoint, req.ExpectedSignerAddress, req.ExpectedUserOperationHash, req.UserOperation)
	if err != nil {
		return nil, err
	}
	recoverable, err := custody.RecoverableSignature(ctx, material, prepared.Hash.Bytes())
	if err != nil {
		return nil, err
	}
	signature, err := erc4337.EncodeSimpleAccountSignature(recoverable)
	if err != nil {
		return nil, err
	}
	recovered, err := erc4337.RecoverSimpleAccountSigner(prepared.Hash, signature)
	if err != nil {
		return nil, err
	}
	if recovered != prepared.Expected {
		return nil, fmt.Errorf("recovered UserOperation signer does not match expected signer")
	}
	return &v1.EVMUserOperationSignResponse{
		EVMOperationResponseBase:     operationResponse(req.KeyID, req.Network, v1.OperationEVMERC4337UserOperation, recovered, req.RequestID),
		ProtocolVersion:              req.ProtocolVersion,
		AccountImplementation:        req.AccountImplementation,
		AccountImplementationVersion: req.AccountImplementationVersion,
		AccountSigningSchema:         req.AccountSigningSchema,
		UserOperationHash:            prepared.Hash.Hex(),
		AccountSigningDigest:         prepared.Hash.Hex(),
		Signature:                    enc.EncodeHex(signature),
		SignatureEncoding:            v1.ERC4337SimpleAccountSignatureEncoding,
	}, nil
}

func VerifyUserOperation(req v1.EVMUserOperationVerifyRequest) (*v1.EVMUserOperationVerifyResponse, error) {
	prepared, err := advancedcodec.PrepareUserOperation(req.ProtocolVersion, req.AccountImplementation, req.AccountImplementationVersion, req.AccountSigningSchema, req.ChainID, req.EntryPoint, req.ExpectedSignerAddress, "", req.UserOperation)
	if err != nil {
		return nil, err
	}
	signature, err := enc.DecodeCanonicalHex("signature", req.Signature, 65)
	if err != nil {
		return nil, err
	}
	recovered, err := erc4337.RecoverSimpleAccountSigner(prepared.Hash, signature)
	if err != nil {
		return nil, err
	}
	return &v1.EVMUserOperationVerifyResponse{
		EVMResponseContext:    responseContext(req.Network, v1.OperationEVMERC4337UserOperation, req.RequestID),
		ProtocolVersion:       req.ProtocolVersion,
		AccountImplementation: req.AccountImplementation,
		UserOperationHash:     prepared.Hash.Hex(),
		AccountSigningDigest:  prepared.Hash.Hex(),
		RecoveredSigner:       canonicalAddress(recovered),
		SignatureValid:        recovered == prepared.Expected,
	}, nil
}
