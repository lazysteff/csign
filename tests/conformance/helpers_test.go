package conformance_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/chain-signer/chain-signer/internal/custody"
	enc "github.com/chain-signer/chain-signer/internal/encoding"
	"github.com/chain-signer/chain-signer/internal/vaultbackend"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func newTestBackend(t *testing.T, resolver custody.ExternalResolver) (*vaultbackend.Backend, logical.Storage) {
	t.Helper()
	b := vaultbackend.New(resolver)
	conf := logical.TestBackendConfig()
	require.NoError(t, b.Setup(context.Background(), conf))
	return b, new(logical.InmemStorage)
}

func createKey(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.CreateKeyRequest) (v1.KeyResponse, map[string]interface{}) {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/keys", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.KeyResponse](t, resp), resp.Data
}

func readKey(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, keyID string) (v1.KeyResponse, map[string]interface{}) {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.ReadOperation, "v1/keys/"+keyID, nil)
	require.NoError(t, err)
	return decodeResponse[v1.KeyResponse](t, resp), resp.Data
}

func signEVMLegacy(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.EVMLegacyTransferSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/legacy/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signEVMEIP1559(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.EVMEIP1559TransferSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/transfers/eip1559/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signEVMContract(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.EVMContractCallSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/evm/contracts/eip1559/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRX(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRXTransferSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/transfers/trx/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRC20(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRC20TransferSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/transfers/trc20/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRONFreezeBalanceV2(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRONFreezeBalanceV2SignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/resources/freeze_v2/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRONUnfreezeBalanceV2(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRONUnfreezeBalanceV2SignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/resources/unfreeze_v2/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRONDelegateResource(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRONDelegateResourceSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/resources/delegate/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRONUndelegateResource(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRONUndelegateResourceSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/resources/undelegate/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRONWithdrawExpireUnfreeze(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRONWithdrawExpireUnfreezeSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/resources/withdraw_expire_unfreeze/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRONVoteWitness(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRONVoteWitnessSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/governance/vote_witness/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func signTRONWithdrawBalance(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.TRONWithdrawBalanceSignRequest) v1.SignResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/tron/rewards/withdraw_balance/sign", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.SignResponse](t, resp)
}

func readVersion(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage) v1.VersionResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.ReadOperation, "v1/version", nil)
	require.NoError(t, err)
	return decodeResponse[v1.VersionResponse](t, resp)
}

func verifyPayload(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.VerifyRequest) v1.RecoverResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/verify", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.RecoverResponse](t, resp)
}

func recoverPayload(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, payload v1.VerifyRequest) v1.RecoverResponse {
	t.Helper()
	resp, err := handle(t, ctx, b, storage, logical.UpdateOperation, "v1/recover", mustMap(t, payload))
	require.NoError(t, err)
	return decodeResponse[v1.RecoverResponse](t, resp)
}

func handle(t *testing.T, ctx context.Context, b *vaultbackend.Backend, storage logical.Storage, op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	req := logical.TestRequest(t, op, path)
	req.Storage = storage
	req.Data = data
	return b.HandleRequest(ctx, req)
}

func decodeResponse[T any](t *testing.T, resp *logical.Response) T {
	t.Helper()
	var out T
	raw, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func mustMap(t *testing.T, payload interface{}) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func mustPrivateKey(t *testing.T, raw string) *ecdsa.PrivateKey {
	t.Helper()
	keyBytes, err := enc.DecodeHex(raw)
	require.NoError(t, err)
	key, err := ethcrypto.ToECDSA(keyBytes)
	require.NoError(t, err)
	return key
}

func sig64(r, s *big.Int) []byte {
	out := make([]byte, 64)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):], sb)
	return out
}

func int64Ptr(value int64) *int64 {
	return &value
}
