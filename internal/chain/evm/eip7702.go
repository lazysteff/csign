package evm

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/chain-signer/chain-signer/internal/chain/evm/advancedcodec"
	"github.com/chain-signer/chain-signer/internal/chain/evm/eip7702"
	"github.com/chain-signer/chain-signer/internal/cryptography"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
)

func PrepareEIP7702Authorization(pub *ecdsa.PublicKey, req *v1.EVMEIP7702AuthorizationSignRequest) (*cryptography.Prepared, error) {
	prepared, err := advancedcodec.PrepareAuthorization(req.AuthorizationSchema, req.ChainID, req.Address, req.Nonce, req.AuthorityAddress)
	if err != nil {
		return nil, err
	}
	expected := prepared.Expected
	options := eip7702.AuthorizationOptions{AllowWildcard: prepared.Authorization.ChainID.IsZero(), ExpectedAuthority: &expected}
	hash := prepared.Authorization.SigHash()
	return &cryptography.Prepared{Payload: cryptography.NewPayload(cryptography.Digest, hash.Bytes()), Format: func(signature []byte) (any, error) {
		artifact, err := eip7702.AssembleAuthorization(prepared.Authorization, signature, options)
		if err != nil {
			return nil, err
		}
		return &v1.EVMEIP7702AuthorizationSignResponse{
			EVMOperationResponseBase: operationResponse(req.KeyID, req.Network, v1.OperationEVMEIP7702Authorization, artifact.Authority, req.RequestID),
			EIP7702SignedAuthorization: v1.EIP7702SignedAuthorization{
				EIP7702Authorization: v1.EIP7702Authorization{
					ChainID: artifact.Authorization.ChainID.ToBig().String(),
					Address: canonicalAddress(artifact.Authorization.Address),
					Nonce:   fmt.Sprintf("%d", artifact.Authorization.Nonce),
				},
				YParity: artifact.Authorization.V,
				R:       fixedBigHex(artifact.Authorization.R.ToBig()),
				S:       fixedBigHex(artifact.Authorization.S.ToBig()),
			},
			AuthorizationSchema:     req.AuthorizationSchema,
			AuthorityAddress:        canonicalAddress(artifact.Authority),
			AuthorizationHash:       artifact.SigningHash.Hex(),
			SerializedAuthorization: enc.EncodeHex(artifact.Serialized),
		}, nil
	}}, nil
}

func VerifyEIP7702Authorization(req v1.EVMEIP7702AuthorizationVerifyRequest) (*v1.EVMEIP7702AuthorizationVerifyResponse, error) {
	if req.ExpectedAuthorityAddress == "" {
		return nil, fmt.Errorf("expected_authority_address is required")
	}
	input := v1.EIP7702SignedAuthorization{
		EIP7702Authorization: req.EIP7702Authorization,
		YParity:              req.YParity,
		R:                    req.R,
		S:                    req.S,
	}
	signed, recovered, err := advancedcodec.PrepareSignedAuthorization(req.AuthorizationSchema, input)
	if err != nil {
		return nil, err
	}
	expected, err := enc.ParseEVMAddress("expected_authority_address", req.ExpectedAuthorityAddress, false)
	if err != nil {
		return nil, err
	}
	hash := signed.SigHash()
	return &v1.EVMEIP7702AuthorizationVerifyResponse{
		EVMResponseContext: responseContext(req.Network, v1.OperationEVMEIP7702Authorization, req.RequestID),
		AuthorizationHash:  hash.Hex(),
		RecoveredAuthority: canonicalAddress(recovered),
		AuthorizationValid: recovered == expected,
	}, nil
}

func PrepareEIP7702Transaction(pub *ecdsa.PublicKey, req *v1.EVMEIP7702TransactionSignRequest) (*cryptography.Prepared, error) {
	prepared, err := advancedcodec.PrepareTransaction(*req)
	if err != nil {
		return nil, err
	}
	expectedSigner := prepared.ExpectedSigner
	options := eip7702.TransactionOptions{AllowWildcardAuthorizations: hasWildcardAuthorization(prepared.Transaction.AuthList), ExpectedAuthorities: prepared.RecoveredAuthorities, ExpectedSigner: &expectedSigner, MaxAuthorizationListEntries: len(prepared.Transaction.AuthList)}
	built, err := eip7702.BuildTransaction(prepared.Transaction, options)
	if err != nil {
		return nil, err
	}
	signer := ethtypes.NewPragueSigner(built.ChainId())
	hash := signer.Hash(built)
	return &cryptography.Prepared{Payload: cryptography.NewPayload(cryptography.Digest, hash.Bytes()), Format: func(signature []byte) (any, error) {
		signed, err := built.WithSignature(signer, signature)
		if err != nil {
			return nil, err
		}
		raw, err := signed.MarshalBinary()
		if err != nil {
			return nil, err
		}
		artifact, err := eip7702.RecoverTransaction(raw, options)
		if err != nil {
			return nil, err
		}
		return &v1.EVMEIP7702TransactionSignResponse{
			EVMOperationResponseBase: operationResponse(req.KeyID, req.Network, v1.OperationEVMEIP7702Transaction, artifact.Signer, req.RequestID),
			TransactionType:          v1.EIP7702TransactionTypeV1,
			TransactionHash:          artifact.TransactionHash.Hex(),
			TransactionSigningHash:   artifact.SigningHash.Hex(),
			SignedPayload:            enc.EncodeHex(artifact.SignedPayload),
			PayloadEncoding:          v1.PayloadEncodingHex,
		}, nil
	}}, nil
}

func RecoverEIP7702Transaction(req v1.EVMEIP7702TransactionRecoverRequest) (*v1.EVMEIP7702TransactionRecoverResponse, error) {
	payload, err := enc.DecodeCanonicalHex("signed_payload", req.SignedPayload, -1)
	if err != nil {
		return nil, err
	}
	var expected *common.Address
	if req.ExpectedSignerAddress != "" {
		parsed, err := enc.ParseEVMAddress("expected_signer_address", req.ExpectedSignerAddress, false)
		if err != nil {
			return nil, err
		}
		expected = &parsed
	}
	artifact, err := eip7702.RecoverTransaction(payload, eip7702.TransactionOptions{
		AllowWildcardAuthorizations: true,
	})
	if err != nil {
		return nil, err
	}
	decoded := decodedTransaction(artifact)
	matches := expected == nil || artifact.Signer == *expected
	return &v1.EVMEIP7702TransactionRecoverResponse{
		EVMResponseContext: responseContext(req.Network, v1.OperationEVMEIP7702Transaction, req.RequestID),
		TransactionHash:    artifact.TransactionHash.Hex(),
		TransactionType:    v1.EIP7702TransactionTypeV1,
		RecoveredSigner:    canonicalAddress(artifact.Signer),
		ExpectedSigner:     req.ExpectedSignerAddress,
		MatchesExpected:    matches,
		DecodedTransaction: decoded,
	}, nil
}

func hasWildcardAuthorization(authorizations []ethtypes.SetCodeAuthorization) bool {
	for _, authorization := range authorizations {
		if authorization.ChainID.IsZero() {
			return true
		}
	}
	return false
}
