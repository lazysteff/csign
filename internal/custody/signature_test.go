package custody

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestRecoverableSignatureAndRecoverAddress(t *testing.T) {
	privateKey := mustPrivateKey(t)
	digest := ethcrypto.Keccak256([]byte("hello"))
	address := ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	sig65, err := RecoverableSignature(context.Background(), localMaterial{privateKey: privateKey}, digest)
	require.NoError(t, err)
	require.Len(t, sig65, 65)
	recovered, err := RecoverAddressFromDigest(func(pub *ecdsa.PublicKey) string {
		return ethcrypto.PubkeyToAddress(*pub).Hex()
	}, digest, sig65)
	require.NoError(t, err)
	require.Equal(t, address, recovered)

	sig64, err := signRS(privateKey, digest)
	require.NoError(t, err)
	sig, err := RecoverableSignature(context.Background(), ExternalMaterial{
		Pub: privateKey.Public().(*ecdsa.PublicKey),
		SignFunc: func(context.Context, []byte) ([]byte, error) {
			return sig64, nil
		},
	}, digest)
	require.NoError(t, err)
	require.Len(t, sig, 65)

	asn1Sig, err := ecdsa.SignASN1(rand.Reader, privateKey, digest)
	require.NoError(t, err)
	sig, err = RecoverableSignature(context.Background(), ExternalMaterial{
		Pub: privateKey.Public().(*ecdsa.PublicKey),
		SignFunc: func(context.Context, []byte) ([]byte, error) {
			return asn1Sig, nil
		},
	}, digest)
	require.NoError(t, err)
	require.Len(t, sig, 65)
}

func TestNormalizeLowSAndSignatureBytes(t *testing.T) {
	curveOrder := ethcrypto.S256().Params().N
	s := new(big.Int).Sub(curveOrder, big.NewInt(1))
	normalized := normalizeLowS(s)
	require.True(t, normalized.Cmp(s) < 0)

	out := signatureBytes(big.NewInt(1), big.NewInt(2))
	require.Len(t, out, 64)
}

func TestRecoverableSignatureRejectsMalformedExternalMaterialWithoutPanicking(t *testing.T) {
	digest := ethcrypto.Keccak256([]byte("custody-boundary"))
	privateKey := mustPrivateKey(t)

	var typedNil *ExternalMaterial
	_, err := RecoverableSignature(context.Background(), typedNil, digest)
	require.ErrorContains(t, err, "signer material")

	_, err = RecoverableSignature(context.Background(), ExternalMaterial{
		Pub: &privateKey.PublicKey,
	}, digest)
	require.ErrorContains(t, err, "external signer callback")

	_, err = RecoverableSignature(context.Background(), ExternalMaterial{
		Pub: &ecdsa.PublicKey{Curve: ethcrypto.S256()},
		SignFunc: func(context.Context, []byte) ([]byte, error) {
			return nil, errors.New("must not be called")
		},
	}, digest)
	require.ErrorContains(t, err, "signer public key is required")
}

func TestRecoverableSignatureDefensivelyCopiesDigest(t *testing.T) {
	privateKey := mustPrivateKey(t)
	digest := ethcrypto.Keccak256([]byte("immutable-digest"))
	original := append([]byte(nil), digest...)

	signature, err := RecoverableSignature(context.Background(), ExternalMaterial{
		Pub: &privateKey.PublicKey,
		SignFunc: func(_ context.Context, received []byte) ([]byte, error) {
			signature, err := ethcrypto.Sign(append([]byte(nil), received...), privateKey)
			clear(received)
			return signature, err
		},
	}, digest)
	require.NoError(t, err)
	require.Len(t, signature, 65)
	require.Equal(t, original, digest)
}

func TestSnapshotBindsObservedPublicKey(t *testing.T) {
	first := mustPrivateKey(t)
	second, err := ethcrypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000001")
	require.NoError(t, err)
	material := &switchingMaterial{first: &first.PublicKey, second: second}
	digest := ethcrypto.Keccak256([]byte("key-snapshot"))

	bound, err := Snapshot(material)
	require.NoError(t, err)
	_, err = RecoverableSignature(context.Background(), bound, digest)
	require.ErrorContains(t, err, "could not determine recovery id")
}

type switchingMaterial struct {
	first  *ecdsa.PublicKey
	second *ecdsa.PrivateKey
	calls  int
}

func (m *switchingMaterial) PublicKey() *ecdsa.PublicKey {
	m.calls++
	if m.calls == 1 {
		return m.first
	}
	return &m.second.PublicKey
}

func (m *switchingMaterial) SignDigest(_ context.Context, digest []byte) ([]byte, error) {
	return ethcrypto.Sign(digest, m.second)
}

func signRS(privateKey *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):], sb)
	return out, nil
}
