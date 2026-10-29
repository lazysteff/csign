package conformance_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	enc "github.com/lazysteff/csign/v2/internal/encoding"
	"github.com/lazysteff/csign/v2/internal/routes"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/shengdoushi/base58"
	"github.com/stretchr/testify/require"
)

const solanaTestSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

func TestConformance_SolanaSingleKeyOpaqueBoundary(t *testing.T) {
	ctx := context.Background()
	backend, storage := newTestBackend(t, nil)
	key, raw := createKey(t, ctx, backend, storage, v1.CreateKeyRequest{KeyID: "gateway/solana/source", KeyType: "ed25519", ChainFamily: "solana", ImportPrivateKey: solanaTestSeed, Policy: v1.Policy{AllowedSigningOperations: []string{v1.OperationSolanaMessage}, AllowedNetworks: []string{"devnet"}}})
	require.Equal(t, "ed25519", key.KeyType)
	require.NotContains(t, raw, "private_key_hex")
	require.NotContains(t, raw, "material_format")
	rawPublic, err := enc.DecodeHex(key.PublicKeyHex)
	require.NoError(t, err)
	require.Equal(t, base58.Encode(rawPublic, base58.BitcoinAlphabet), key.SignerAddress)
	req := v1.SolanaMessageSignRequest{KeyID: key.KeyID, ChainFamily: "solana", Network: "devnet", RequestID: "r", MessageHex: "ff00abcd"}
	var first v1.SolanaMessageSignResponse
	for index := 0; index < 2; index++ {
		response, err := handle(t, ctx, backend, storage, logical.UpdateOperation, routes.SolanaMessageSign, mustMap(t, req))
		require.NoError(t, err)
		signed := decodeResponse[v1.SolanaMessageSignResponse](t, response)
		require.Equal(t, "ed25519", signed.SigningScheme)
		require.Equal(t, "hex", signed.SignatureEncoding)
		require.Equal(t, key.SignerAddress, signed.SignerAddress)
		signature, err := enc.DecodeHex(signed.SignatureHex)
		require.NoError(t, err)
		require.True(t, ed25519.Verify(ed25519.PublicKey(rawPublic), []byte{255, 0, 171, 205}, signature))
		require.False(t, ed25519.Verify(ed25519.PublicKey(rawPublic), []byte{255, 0, 171, 206}, signature))
		publicResponse, err := json.Marshal(response.Data)
		require.NoError(t, err)
		require.NotContains(t, string(publicResponse), solanaTestSeed)
		require.NotContains(t, string(publicResponse), "private_key")
		if index == 0 {
			first = signed
		} else {
			require.Equal(t, first.SignatureHex, signed.SignatureHex)
		}
	}
	// No expected identity assertion is necessary; supplying the correct one is
	// equivalent and a mismatched assertion fails without choosing another key.
	req.ExpectedSignerAddress = key.SignerAddress
	response, err := handle(t, ctx, backend, storage, logical.UpdateOperation, routes.SolanaMessageSign, mustMap(t, req))
	require.NoError(t, err)
	require.Equal(t, first.SignatureHex, decodeResponse[v1.SolanaMessageSignResponse](t, response).SignatureHex)
	req.ExpectedSignerAddress = base58.Encode(bytes.Repeat([]byte{1}, 32), base58.BitcoinAlphabet)
	_, err = handle(t, ctx, backend, storage, logical.UpdateOperation, routes.SolanaMessageSign, mustMap(t, req))
	require.Error(t, err)
	req.ExpectedSignerAddress = ""
	req.ChainFamily = "SOLANA"
	_, err = handle(t, ctx, backend, storage, logical.UpdateOperation, routes.SolanaMessageSign, mustMap(t, req))
	require.Error(t, err)
	req.ChainFamily = "solana"
	req.Network = "mainnet"
	_, err = handle(t, ctx, backend, storage, logical.UpdateOperation, routes.SolanaMessageSign, mustMap(t, req))
	require.Error(t, err)
	req.Network = "devnet"
	req.RequestID = ""
	_, err = handle(t, ctx, backend, storage, logical.UpdateOperation, routes.SolanaMessageSign, mustMap(t, req))
	require.Error(t, err)
}
func TestConformance_SolanaResourceLimitsAndDefaultDeny(t *testing.T) {
	ctx := context.Background()
	backend, storage := newTestBackend(t, nil)
	// Unbound generic Ed25519 key has protocol-neutral material; operation policy
	// independently grants the Solana opaque signing boundary.
	key, _ := createKey(t, ctx, backend, storage, v1.CreateKeyRequest{KeyID: "opaque", KeyType: "ed25519", Policy: v1.Policy{AllowedSigningOperations: []string{v1.OperationSolanaMessage}}})
	require.Empty(t, key.ChainFamily)
	require.Empty(t, key.SignerAddress)
	for _, test := range []struct {
		name, message string
		valid         bool
	}{
		{"empty", "", false}, {"empty prefixed", "0x", false}, {"bad hex", "gg", false}, {"odd hex", "1", false},
		{"one byte", "01", true}, {"non-transaction bytes", "ff", true},
		{"above historical transaction sizes", strings.Repeat("ff", 8192), true},
		{"maximum", strings.Repeat("ab", v1.SolanaMaxMessageBytes), true},
		{"maximum prefixed", "0x" + strings.Repeat("ab", v1.SolanaMaxMessageBytes), true},
		{"decoded oversized", strings.Repeat("ab", v1.SolanaMaxMessageBytes+1), false},
		{"encoded oversized", "0x" + strings.Repeat("ab", v1.SolanaMaxMessageBytes+1), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := v1.SolanaMessageSignRequest{KeyID: key.KeyID, ChainFamily: "solana", Network: "arbitrary-policy-metadata", RequestID: "r", MessageHex: test.message}
			response, err := handle(t, ctx, backend, storage, logical.UpdateOperation, routes.SolanaMessageSign, mustMap(t, req))
			if test.valid {
				require.NoError(t, err)
				require.Equal(t, "ed25519", decodeResponse[v1.SolanaMessageSignResponse](t, response).SigningScheme)
			} else {
				require.Error(t, err)
			}
		})
	}
	denied, _ := createKey(t, ctx, backend, storage, v1.CreateKeyRequest{KeyID: "denied", KeyType: "ed25519"})
	version := readVersion(t, ctx, backend, storage)
	require.Contains(t, version.SupportedRoutes, routes.SolanaMessageSign)
	req := v1.SolanaMessageSignRequest{KeyID: denied.KeyID, ChainFamily: "solana", Network: "devnet", RequestID: "r", MessageHex: "01"}
	_, err := handle(t, ctx, backend, storage, logical.UpdateOperation, routes.SolanaMessageSign, mustMap(t, req))
	require.ErrorContains(t, err, "signing_operation_not_allowed")
	req.KeyID = key.KeyID
	data := mustMap(t, req)
	data["signing_scheme"] = "ecdsa_secp256k1"
	_, err = handle(t, ctx, backend, storage, logical.UpdateOperation, routes.SolanaMessageSign, data)
	require.Error(t, err)
	statusRoute, err := routes.KeyStatus(key.KeyID)
	require.NoError(t, err)
	_, err = handle(t, ctx, backend, storage, logical.UpdateOperation, statusRoute, map[string]interface{}{"active": false})
	require.NoError(t, err)
	_, err = handle(t, ctx, backend, storage, logical.UpdateOperation, routes.SolanaMessageSign, mustMap(t, req))
	require.Error(t, err)
	for _, detail := range version.SigningOperationDetails {
		if detail.Operation == v1.OperationSolanaMessage {
			require.Equal(t, "opaque", detail.SecurityModel)
			require.Equal(t, []string{"ed25519"}, detail.SigningSchemes)
			require.Equal(t, []string{"ed25519"}, detail.CompatibleKeyTypes)
			require.Equal(t, []string{"hex"}, detail.SignatureEncodings)
		}
	}
}
func TestConformance_GatewayCombinesManagedAndExternalSolanaSignatures(t *testing.T) {
	ctx := context.Background()
	backend, storage := newTestBackend(t, nil)
	funding, _ := createKey(t, ctx, backend, storage, v1.CreateKeyRequest{KeyID: "funding", KeyType: "ed25519", Policy: v1.Policy{AllowedSigningOperations: []string{v1.OperationSolanaMessage}}})
	source, _ := createKey(t, ctx, backend, storage, v1.CreateKeyRequest{KeyID: "source", KeyType: "ed25519", Policy: v1.Policy{AllowedSigningOperations: []string{v1.OperationSolanaMessage}}})
	external := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	externalPub := external.Public().(ed25519.PublicKey)
	fundingPub, err := enc.DecodeHex(funding.PublicKeyHex)
	require.NoError(t, err)
	sourcePub, err := enc.DecodeHex(source.PublicKeyHex)
	require.NoError(t, err)
	// Gateway-owned legacy fixture: source SOL transfer plus a memo signed by an
	// external party. csign sees only the frozen message, never this envelope.
	message := []byte{3, 1, 2, 6}
	for _, key := range [][]byte{fundingPub, sourcePub, externalPub, bytes.Repeat([]byte{7}, 32), make([]byte, 32)} {
		message = append(message, key...)
	}
	memoProgram, err := base58.Decode("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", base58.BitcoinAlphabet)
	require.NoError(t, err)
	message = append(message, memoProgram...)
	message = append(message, bytes.Repeat([]byte{4}, 32)...)
	message = append(message, 2, 4, 2, 1, 3, 12, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5, 1, 2, 1, 'x')
	frozen := bytes.Clone(message)
	externalSig := ed25519.Sign(external, frozen)
	slots := [][]byte{make([]byte, 64), make([]byte, 64), bytes.Clone(externalSig)}
	// Source signs first; funding signs later. Neither call claims completeness.
	for _, entry := range []struct {
		key  v1.KeyResponse
		slot int
	}{{source, 1}, {funding, 0}} {
		req := v1.SolanaMessageSignRequest{KeyID: entry.key.KeyID, ChainFamily: "solana", Network: "devnet", RequestID: entry.key.KeyID, MessageHex: hex.EncodeToString(frozen)}
		response, err := handle(t, ctx, backend, storage, logical.UpdateOperation, routes.SolanaMessageSign, mustMap(t, req))
		require.NoError(t, err)
		signed := decodeResponse[v1.SolanaMessageSignResponse](t, response)
		slots[entry.slot], err = enc.DecodeHex(signed.SignatureHex)
		require.NoError(t, err)
		require.Equal(t, externalSig, slots[2])
		require.Equal(t, frozen, message)
	}
	envelope := []byte{3}
	for _, sig := range slots {
		envelope = append(envelope, sig...)
	}
	envelope = append(envelope, frozen...)
	require.Equal(t, frozen, envelope[1+3*64:])
	require.Equal(t, externalSig, envelope[1+2*64:1+3*64])
	for index, pub := range []ed25519.PublicKey{fundingPub, sourcePub, externalPub} {
		require.True(t, ed25519.Verify(pub, frozen, slots[index]))
		require.False(t, ed25519.Verify(pub, append(bytes.Clone(frozen), 0), slots[index]))
	}
}
func TestConformance_EVMNetworksReuseCryptography(t *testing.T) {
	ctx := context.Background()
	backend, storage := newTestBackend(t, nil)
	key, _ := createKey(t, ctx, backend, storage, v1.CreateKeyRequest{KeyID: "evm-compatible", ChainFamily: "evm", Policy: v1.Policy{AllowedSigningOperations: []string{v1.OperationEVMTransferLegacy}, AllowedNetworks: []string{"bsc", "polygon"}, AllowedChainIDs: []int64{56, 137}}})
	for _, network := range []struct {
		name    string
		chainID int64
	}{{"bsc", 56}, {"polygon", 137}} {
		signed := signEVMLegacy(t, ctx, backend, storage, v1.EVMLegacyTransferSignRequest{BaseSignRequest: v1.BaseSignRequest{KeyID: key.KeyID, ChainFamily: "evm", Network: network.name, SourceAddress: key.SignerAddress}, ChainID: network.chainID, To: testEVMRecipient, Value: "1", GasPrice: "1", GasLimit: 21000})
		recovered := recoverPayload(t, ctx, backend, storage, v1.VerifyRequest{ChainFamily: "evm", Network: network.name, SignedPayload: signed.SignedPayload, ExpectedSignerAddress: key.SignerAddress})
		require.True(t, recovered.MatchesExpected)
	}
}
