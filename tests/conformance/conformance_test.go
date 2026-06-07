package conformance_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	"github.com/chain-signer/chain-signer/internal/domain"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

const (
	testPrivHex             = "0x4c0883a69102937d6231471b5dbb6204fe512961708279f3c8dfe8d6b6f5f5ad"
	testTRONRecipient       = "TSvT6Bg3siokv3dbdtt9o4oM1CTXmymGn1"
	testTRONContract        = "TN3W4H6rK2ce4vX9YnFQHwKENnHjoxb3m9"
	testEVMRecipient        = "0x1111111111111111111111111111111111111111"
	testEVMContract         = "0x2222222222222222222222222222222222222222"
	testRequestID           = "req-123"
	testEVMNetwork          = "ethereum-sepolia"
	testTRONNetwork         = "tron-nile"
	testEVMChainID    int64 = 11155111
)

func TestConformance_MVPEVMOperations(t *testing.T) {
	ctx := context.Background()
	b, storage := newTestBackend(t, nil)

	createResp, createRaw := createKey(t, ctx, b, storage, v1.CreateKeyRequest{
		KeyID:            "evm-mvp",
		ChainFamily:      v1.ChainFamilyEVM,
		CustodyMode:      v1.CustodyModeMVP,
		ImportPrivateKey: testPrivHex,
		Policy: v1.Policy{
			AllowedNetworks:      []string{testEVMNetwork},
			AllowedChainIDs:      []int64{testEVMChainID},
			MaxValue:             "1000000000000000000",
			MaxGasLimit:          250000,
			MaxGasPrice:          "1000000000",
			MaxFeePerGas:         "2000000000",
			MaxPriorityFeePerGas: "1000000000",
			AllowedTokenContracts: []string{
				testEVMContract,
			},
			AllowedSelectors: []string{domain.TRC20TransferSelector},
		},
	})
	require.NotContains(t, createRaw, "private_key_hex")

	readResp, readRaw := readKey(t, ctx, b, storage, "evm-mvp")
	require.Equal(t, createResp.SignerAddress, readResp.SignerAddress)
	require.NotContains(t, readRaw, "private_key_hex")

	legacyReq := v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "evm-mvp",
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       testEVMNetwork,
			RequestID:     testRequestID,
			SourceAddress: createResp.SignerAddress,
		},
		ChainID:  testEVMChainID,
		To:       testEVMRecipient,
		Value:    "1",
		Nonce:    1,
		GasLimit: 21000,
		GasPrice: "1000",
	}
	legacySign := signEVMLegacy(t, ctx, b, storage, legacyReq)
	legacyVerify := verifyPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyEVM,
		Network:               testEVMNetwork,
		Operation:             v1.OperationEVMTransferLegacy,
		SignedPayload:         legacySign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, legacyVerify.MatchesExpected)
	require.Equal(t, v1.OperationEVMTransferLegacy, legacyVerify.Operation)
	require.Equal(t, legacySign.TxHash, legacyVerify.TxHash)

	eip1559Req := v1.EVMEIP1559TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "evm-mvp",
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       testEVMNetwork,
			RequestID:     testRequestID,
			SourceAddress: createResp.SignerAddress,
		},
		ChainID:              testEVMChainID,
		To:                   testEVMRecipient,
		Value:                "2",
		Nonce:                2,
		GasLimit:             21000,
		MaxFeePerGas:         "1500",
		MaxPriorityFeePerGas: "100",
	}
	eip1559Sign := signEVMEIP1559(t, ctx, b, storage, eip1559Req)
	eip1559Verify := verifyPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyEVM,
		Network:               testEVMNetwork,
		Operation:             v1.OperationEVMTransferEIP1559,
		SignedPayload:         eip1559Sign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, eip1559Verify.MatchesExpected)
	require.Equal(t, v1.OperationEVMTransferEIP1559, eip1559Verify.Operation)

	contractReq := v1.EVMContractCallSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "evm-mvp",
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       testEVMNetwork,
			RequestID:     testRequestID,
			SourceAddress: createResp.SignerAddress,
		},
		ChainID:              testEVMChainID,
		To:                   testEVMContract,
		Value:                "0",
		Data:                 "0xa9059cbb0000000000000000000000000000000000000000000000000000000000000000",
		Nonce:                3,
		GasLimit:             90000,
		MaxFeePerGas:         "1500",
		MaxPriorityFeePerGas: "100",
	}
	contractSign := signEVMContract(t, ctx, b, storage, contractReq)
	contractVerify := recoverPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyEVM,
		Network:               testEVMNetwork,
		SignedPayload:         contractSign.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, contractVerify.MatchesExpected)
	require.Equal(t, v1.OperationEVMContractEIP1559, contractVerify.Operation)
}

func TestConformance_PKCS11StyleExternalSigner(t *testing.T) {
	ctx := context.Background()
	privateKey := mustPrivateKey(t, testPrivHex)
	resolver := staticResolver{
		materials: map[string]custody.Material{
			"hsm-1": custody.ExternalMaterial{
				Pub: &privateKey.PublicKey,
				SignFunc: func(_ context.Context, digest []byte) ([]byte, error) {
					r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
					if err != nil {
						return nil, err
					}
					return sig64(r, s), nil
				},
			},
		},
	}
	b, storage := newTestBackend(t, resolver)

	createResp, createRaw := createKey(t, ctx, b, storage, v1.CreateKeyRequest{
		KeyID:             "evm-pkcs11",
		ChainFamily:       v1.ChainFamilyEVM,
		CustodyMode:       v1.CustodyModePKCS11,
		PublicKeyHex:      enc.EncodeHex(ethcrypto.FromECDSAPub(&privateKey.PublicKey)),
		ExternalSignerRef: "hsm-1",
	})
	require.NotContains(t, createRaw, "private_key_hex")

	signResp := signEVMEIP1559(t, ctx, b, storage, v1.EVMEIP1559TransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         "evm-pkcs11",
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       testEVMNetwork,
			RequestID:     testRequestID,
			SourceAddress: createResp.SignerAddress,
		},
		ChainID:              testEVMChainID,
		To:                   testEVMRecipient,
		Value:                "1",
		Nonce:                7,
		GasLimit:             21000,
		MaxFeePerGas:         "1000",
		MaxPriorityFeePerGas: "100",
	})
	verifyResp := verifyPayload(t, ctx, b, storage, v1.VerifyRequest{
		ChainFamily:           v1.ChainFamilyEVM,
		Network:               testEVMNetwork,
		Operation:             v1.OperationEVMTransferEIP1559,
		SignedPayload:         signResp.SignedPayload,
		ExpectedSignerAddress: createResp.SignerAddress,
	})
	require.True(t, verifyResp.MatchesExpected)
}

func TestConformance_HierarchicalKeyIDRoundTripsAcrossManagementAndSigning(t *testing.T) {
	ctx := context.Background()
	b, storage := newTestBackend(t, nil)

	keyID := "foo/status/bar"
	createResp, _ := createKey(t, ctx, b, storage, v1.CreateKeyRequest{
		KeyID:            keyID,
		ChainFamily:      v1.ChainFamilyEVM,
		CustodyMode:      v1.CustodyModeMVP,
		ImportPrivateKey: testPrivHex,
	})

	readResp, _ := readKey(t, ctx, b, storage, keyID)
	require.Equal(t, keyID, readResp.KeyID)
	require.Equal(t, createResp.SignerAddress, readResp.SignerAddress)

	listResp, err := handle(t, ctx, b, storage, logical.ListOperation, "v1/keys", nil)
	require.NoError(t, err)
	var listPayload struct {
		Keys []string `json:"keys"`
	}
	raw, err := json.Marshal(listResp.Data)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &listPayload))
	require.Contains(t, listPayload.Keys, keyID)

	_, err = handle(t, ctx, b, storage, logical.UpdateOperation, "v1/key-status/"+keyID, map[string]interface{}{
		"active": false,
	})
	require.NoError(t, err)

	_, err = handle(t, ctx, b, storage, logical.UpdateOperation, "v1/key-status/"+keyID, map[string]interface{}{
		"active": true,
	})
	require.NoError(t, err)

	signResp := signEVMLegacy(t, ctx, b, storage, v1.EVMLegacyTransferSignRequest{
		BaseSignRequest: v1.BaseSignRequest{
			KeyID:         keyID,
			ChainFamily:   v1.ChainFamilyEVM,
			Network:       testEVMNetwork,
			RequestID:     testRequestID,
			SourceAddress: createResp.SignerAddress,
		},
		ChainID:  testEVMChainID,
		To:       testEVMRecipient,
		Value:    "1",
		Nonce:    1,
		GasLimit: 21000,
		GasPrice: "1000",
	})
	require.Equal(t, keyID, signResp.KeyID)
}

func TestConformance_NegativeCases(t *testing.T) {
	ctx := context.Background()
	b, storage := newTestBackend(t, nil)

	createResp, _ := createKey(t, ctx, b, storage, v1.CreateKeyRequest{
		KeyID:            "negatives",
		ChainFamily:      v1.ChainFamilyEVM,
		CustodyMode:      v1.CustodyModeMVP,
		ImportPrivateKey: testPrivHex,
		Policy: v1.Policy{
			AllowedNetworks: []string{testEVMNetwork},
			AllowedChainIDs: []int64{testEVMChainID},
			MaxValue:        "1",
		},
	})

	t.Run("policy denial on cap violation", func(t *testing.T) {
		_, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", map[string]interface{}{
			"key_id":         "negatives",
			"chain_family":   v1.ChainFamilyEVM,
			"network":        testEVMNetwork,
			"request_id":     testRequestID,
			"source_address": createResp.SignerAddress,
			"chain_id":       testEVMChainID,
			"to":             testEVMRecipient,
			"value":          "2",
			"nonce":          1,
			"gas_limit":      21000,
			"gas_price":      "1000",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "cap")
	})

	t.Run("address mismatch", func(t *testing.T) {
		_, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", map[string]interface{}{
			"key_id":         "negatives",
			"chain_family":   v1.ChainFamilyEVM,
			"network":        testEVMNetwork,
			"request_id":     testRequestID,
			"source_address": testEVMRecipient,
			"chain_id":       testEVMChainID,
			"to":             testEVMRecipient,
			"value":          "1",
			"nonce":          1,
			"gas_limit":      21000,
			"gas_price":      "1000",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "source address")
	})

	t.Run("disabled key", func(t *testing.T) {
		_, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/key-status/negatives", map[string]interface{}{
			"active": false,
		})
		require.NoError(t, err)
		_, err = handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", map[string]interface{}{
			"key_id":         "negatives",
			"chain_family":   v1.ChainFamilyEVM,
			"network":        testEVMNetwork,
			"request_id":     testRequestID,
			"source_address": createResp.SignerAddress,
			"chain_id":       testEVMChainID,
			"to":             testEVMRecipient,
			"value":          "1",
			"nonce":          1,
			"gas_limit":      21000,
			"gas_price":      "1000",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "disabled")
	})

	t.Run("malformed request", func(t *testing.T) {
		_, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", map[string]interface{}{
			"chain_family": v1.ChainFamilyEVM,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "key_id")
	})

	t.Run("invalid key ids are rejected consistently", func(t *testing.T) {
		_, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/keys", map[string]interface{}{
			"key_id":                 "",
			"chain_family":           v1.ChainFamilyEVM,
			"custody_mode":           v1.CustodyModeMVP,
			"import_private_key_hex": testPrivHex,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "key_id")

		_, err = handle(t, ctx, b, storage, logical.UpdateOperation, "v1/keys", map[string]interface{}{
			"key_id":                 "a//b",
			"chain_family":           v1.ChainFamilyEVM,
			"custody_mode":           v1.CustodyModeMVP,
			"import_private_key_hex": testPrivHex,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "key_id")

		_, err = handle(t, ctx, b, storage, logical.ReadOperation, "v1/keys/a//b", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key_id")

		_, err = handle(t, ctx, b, storage, logical.UpdateOperation, "v1/key-status/a/./b", map[string]interface{}{
			"active": false,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "key_id")

		_, err = handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", map[string]interface{}{
			"key_id":         "a/../b",
			"chain_family":   v1.ChainFamilyEVM,
			"network":        testEVMNetwork,
			"request_id":     testRequestID,
			"source_address": createResp.SignerAddress,
			"chain_id":       testEVMChainID,
			"to":             testEVMRecipient,
			"value":          "1",
			"nonce":          1,
			"gas_limit":      21000,
			"gas_price":      "1000",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "key_id")
	})

	t.Run("removed legacy status route", func(t *testing.T) {
		_, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/keys/negatives/status", map[string]interface{}{
			"active": false,
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, logical.ErrUnsupportedPath) || errors.Is(err, logical.ErrUnsupportedOperation))
	})

	t.Run("unsupported operation", func(t *testing.T) {
		_, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/unsupported/sign", map[string]interface{}{})
		require.Error(t, err)
		require.True(t, errors.Is(err, logical.ErrUnsupportedPath) || errors.Is(err, logical.ErrUnsupportedOperation))
	})
}

type staticResolver struct {
	materials map[string]custody.Material
}

func (r staticResolver) ResolveExternal(_ context.Context, key domain.Key) (custody.Material, error) {
	material, ok := r.materials[key.ExternalSignerRef]
	if !ok {
		return nil, errors.New("external signer not found")
	}
	return material, nil
}
