//go:build integration

package live_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/chain-signer/chain-signer/internal/vaultbackend"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	tronclient "github.com/fbsobreira/gotron-sdk/pkg/client"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type liveTRONConfig struct {
	Endpoint           string
	APIKey             string
	Network            string
	OwnerPrivateKey    string
	ReceiverAddress    string
	NegativePrivateKey string
	WithdrawPrivateKey string
}

func TestLiveTRONResourceBroadcasts(t *testing.T) {
	cfg := loadLiveTRONConfig(t)
	ctx := context.Background()
	client := newLiveTRONClient(t, cfg)
	backend, storage := newLiveBackend(t)
	owner := createLiveTRONKey(t, ctx, backend, storage, "live-owner", cfg.OwnerPrivateKey)

	t.Run("freeze_v2", func(t *testing.T) {
		resp := signLiveTRON(t, ctx, backend, storage, "v1/tron/resources/freeze_v2/sign", v1.TRONFreezeBalanceV2SignRequest{
			TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
				KeyID:        owner.KeyID,
				ChainFamily:  v1.ChainFamilyTRON,
				Network:      cfg.Network,
				RequestID:    "freeze-live",
				OwnerAddress: owner.SignerAddress,
			},
			TRONRawDataEnvelope: freshEnvelope(t, client, 60_000),
			Resource:            v1.TRONResourceEnergy,
			Amount:              1_000_000,
		})
		require.NoError(t, broadcastSignedPayload(client, resp.SignedPayload))
	})

	t.Run("delegate", func(t *testing.T) {
		resp := signLiveTRON(t, ctx, backend, storage, "v1/tron/resources/delegate/sign", v1.TRONDelegateResourceSignRequest{
			TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
				KeyID:        owner.KeyID,
				ChainFamily:  v1.ChainFamilyTRON,
				Network:      cfg.Network,
				RequestID:    "delegate-live",
				OwnerAddress: owner.SignerAddress,
			},
			TRONRawDataEnvelope: freshEnvelope(t, client, 60_000),
			ReceiverAddress:     cfg.ReceiverAddress,
			Resource:            v1.TRONResourceEnergy,
			Amount:              500_000,
		})
		require.NoError(t, broadcastSignedPayload(client, resp.SignedPayload))
	})

	t.Run("undelegate", func(t *testing.T) {
		resp := signLiveTRON(t, ctx, backend, storage, "v1/tron/resources/undelegate/sign", v1.TRONUndelegateResourceSignRequest{
			TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
				KeyID:        owner.KeyID,
				ChainFamily:  v1.ChainFamilyTRON,
				Network:      cfg.Network,
				RequestID:    "undelegate-live",
				OwnerAddress: owner.SignerAddress,
			},
			TRONRawDataEnvelope: freshEnvelope(t, client, 60_000),
			ReceiverAddress:     cfg.ReceiverAddress,
			Resource:            v1.TRONResourceEnergy,
			Amount:              500_000,
		})
		require.NoError(t, broadcastSignedPayload(client, resp.SignedPayload))
	})

	t.Run("unfreeze_v2", func(t *testing.T) {
		resp := signLiveTRON(t, ctx, backend, storage, "v1/tron/resources/unfreeze_v2/sign", v1.TRONUnfreezeBalanceV2SignRequest{
			TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
				KeyID:        owner.KeyID,
				ChainFamily:  v1.ChainFamilyTRON,
				Network:      cfg.Network,
				RequestID:    "unfreeze-live",
				OwnerAddress: owner.SignerAddress,
			},
			TRONRawDataEnvelope: freshEnvelope(t, client, 60_000),
			Resource:            v1.TRONResourceEnergy,
			Amount:              500_000,
		})
		require.NoError(t, broadcastSignedPayload(client, resp.SignedPayload))
	})

	t.Run("withdraw_expire_unfreeze", func(t *testing.T) {
		if strings.TrimSpace(cfg.WithdrawPrivateKey) == "" {
			t.Skip("set TRON_LIVE_WITHDRAW_PRIVATE_KEY_HEX to run withdraw_expire_unfreeze")
		}
		withdrawOwner := createLiveTRONKey(t, ctx, backend, storage, "live-withdraw-owner", cfg.WithdrawPrivateKey)
		resp := signLiveTRON(t, ctx, backend, storage, "v1/tron/resources/withdraw_expire_unfreeze/sign", v1.TRONWithdrawExpireUnfreezeSignRequest{
			TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
				KeyID:        withdrawOwner.KeyID,
				ChainFamily:  v1.ChainFamilyTRON,
				Network:      cfg.Network,
				RequestID:    "withdraw-live",
				OwnerAddress: withdrawOwner.SignerAddress,
			},
			TRONRawDataEnvelope: freshEnvelope(t, client, 60_000),
		})
		require.NoError(t, broadcastSignedPayload(client, resp.SignedPayload))
	})
}

func TestLiveTRONResourceNodeRejections(t *testing.T) {
	cfg := loadLiveTRONConfig(t)
	ctx := context.Background()
	client := newLiveTRONClient(t, cfg)
	backend, storage := newLiveBackend(t)
	owner := createLiveTRONKey(t, ctx, backend, storage, "live-owner", cfg.OwnerPrivateKey)

	t.Run("stale_expiration_is_node_rejected", func(t *testing.T) {
		resp := signLiveTRON(t, ctx, backend, storage, "v1/tron/resources/freeze_v2/sign", v1.TRONFreezeBalanceV2SignRequest{
			TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
				KeyID:        owner.KeyID,
				ChainFamily:  v1.ChainFamilyTRON,
				Network:      cfg.Network,
				RequestID:    "freeze-stale",
				OwnerAddress: owner.SignerAddress,
			},
			TRONRawDataEnvelope: freshEnvelope(t, client, -60_000),
			Resource:            v1.TRONResourceEnergy,
			Amount:              1_000_000,
		})
		require.Error(t, broadcastSignedPayload(client, resp.SignedPayload))
	})

	t.Run("delegate_without_state_is_node_rejected", func(t *testing.T) {
		if strings.TrimSpace(cfg.NegativePrivateKey) == "" {
			t.Skip("set TRON_LIVE_NEGATIVE_PRIVATE_KEY_HEX to run negative state tests")
		}
		negativeOwner := createLiveTRONKey(t, ctx, backend, storage, "live-negative-owner", cfg.NegativePrivateKey)
		resp := signLiveTRON(t, ctx, backend, storage, "v1/tron/resources/delegate/sign", v1.TRONDelegateResourceSignRequest{
			TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
				KeyID:        negativeOwner.KeyID,
				ChainFamily:  v1.ChainFamilyTRON,
				Network:      cfg.Network,
				RequestID:    "delegate-negative",
				OwnerAddress: negativeOwner.SignerAddress,
			},
			TRONRawDataEnvelope: freshEnvelope(t, client, 60_000),
			ReceiverAddress:     cfg.ReceiverAddress,
			Resource:            v1.TRONResourceEnergy,
			Amount:              1_000_000,
		})
		require.Error(t, broadcastSignedPayload(client, resp.SignedPayload))
	})

	t.Run("unfreeze_without_available_amount_is_node_rejected", func(t *testing.T) {
		if strings.TrimSpace(cfg.NegativePrivateKey) == "" {
			t.Skip("set TRON_LIVE_NEGATIVE_PRIVATE_KEY_HEX to run negative state tests")
		}
		negativeOwner := createLiveTRONKey(t, ctx, backend, storage, "live-negative-unfreeze", cfg.NegativePrivateKey)
		resp := signLiveTRON(t, ctx, backend, storage, "v1/tron/resources/unfreeze_v2/sign", v1.TRONUnfreezeBalanceV2SignRequest{
			TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
				KeyID:        negativeOwner.KeyID,
				ChainFamily:  v1.ChainFamilyTRON,
				Network:      cfg.Network,
				RequestID:    "unfreeze-negative",
				OwnerAddress: negativeOwner.SignerAddress,
			},
			TRONRawDataEnvelope: freshEnvelope(t, client, 60_000),
			Resource:            v1.TRONResourceEnergy,
			Amount:              1_000_000_000_000,
		})
		require.Error(t, broadcastSignedPayload(client, resp.SignedPayload))
	})

	t.Run("withdraw_without_expired_balance_is_node_rejected", func(t *testing.T) {
		if strings.TrimSpace(cfg.NegativePrivateKey) == "" {
			t.Skip("set TRON_LIVE_NEGATIVE_PRIVATE_KEY_HEX to run negative state tests")
		}
		negativeOwner := createLiveTRONKey(t, ctx, backend, storage, "live-negative-withdraw", cfg.NegativePrivateKey)
		resp := signLiveTRON(t, ctx, backend, storage, "v1/tron/resources/withdraw_expire_unfreeze/sign", v1.TRONWithdrawExpireUnfreezeSignRequest{
			TRONOwnerSignRequestBase: v1.TRONOwnerSignRequestBase{
				KeyID:        negativeOwner.KeyID,
				ChainFamily:  v1.ChainFamilyTRON,
				Network:      cfg.Network,
				RequestID:    "withdraw-negative",
				OwnerAddress: negativeOwner.SignerAddress,
			},
			TRONRawDataEnvelope: freshEnvelope(t, client, 60_000),
		})
		require.Error(t, broadcastSignedPayload(client, resp.SignedPayload))
	})
}

func loadLiveTRONConfig(t *testing.T) liveTRONConfig {
	t.Helper()
	return liveTRONConfig{
		Endpoint:           requiredEnv(t, "TRON_LIVE_GRPC_ENDPOINT"),
		APIKey:             strings.TrimSpace(os.Getenv("TRON_LIVE_API_KEY")),
		Network:            envOrDefault("TRON_LIVE_NETWORK", "tron-nile"),
		OwnerPrivateKey:    requiredEnv(t, "TRON_LIVE_OWNER_PRIVATE_KEY_HEX"),
		ReceiverAddress:    requiredEnv(t, "TRON_LIVE_RECEIVER_ADDRESS"),
		NegativePrivateKey: strings.TrimSpace(os.Getenv("TRON_LIVE_NEGATIVE_PRIVATE_KEY_HEX")),
		WithdrawPrivateKey: strings.TrimSpace(os.Getenv("TRON_LIVE_WITHDRAW_PRIVATE_KEY_HEX")),
	}
}

func newLiveTRONClient(t *testing.T, cfg liveTRONConfig) *tronclient.GrpcClient {
	t.Helper()
	client := tronclient.NewGrpcClient(cfg.Endpoint)
	require.NoError(t, client.Start(tronclient.GRPCInsecure()))
	if cfg.APIKey != "" {
		require.NoError(t, client.SetAPIKey(cfg.APIKey))
	}
	t.Cleanup(client.Stop)
	return client
}

func newLiveBackend(t *testing.T) (*vaultbackend.Backend, logical.Storage) {
	t.Helper()
	backend := vaultbackend.New(nil)
	conf := logical.TestBackendConfig()
	require.NoError(t, backend.Setup(context.Background(), conf))
	return backend, new(logical.InmemStorage)
}

func createLiveTRONKey(t *testing.T, ctx context.Context, backend *vaultbackend.Backend, storage logical.Storage, keyID, privateKey string) v1.KeyResponse {
	t.Helper()
	resp, err := handleLive(t, ctx, backend, storage, logical.UpdateOperation, "v1/keys", mustMap(t, v1.CreateKeyRequest{
		KeyID:            keyID,
		ChainFamily:      v1.ChainFamilyTRON,
		CustodyMode:      v1.CustodyModeMVP,
		ImportPrivateKey: privateKey,
	}))
	require.NoError(t, err)
	return decodeLiveResponse[v1.KeyResponse](t, resp)
}

func signLiveTRON[T any](t *testing.T, ctx context.Context, backend *vaultbackend.Backend, storage logical.Storage, path string, payload T) v1.SignResponse {
	t.Helper()
	resp, err := handleLive(t, ctx, backend, storage, logical.UpdateOperation, path, mustMap(t, payload))
	require.NoError(t, err)
	return decodeLiveResponse[v1.SignResponse](t, resp)
}

func handleLive(t *testing.T, ctx context.Context, backend *vaultbackend.Backend, storage logical.Storage, op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	req := logical.TestRequest(t, op, path)
	req.Storage = storage
	req.Data = data
	return backend.HandleRequest(ctx, req)
}

func decodeLiveResponse[T any](t *testing.T, resp *logical.Response) T {
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

func freshEnvelope(t *testing.T, client *tronclient.GrpcClient, offsetMillis int64) v1.TRONRawDataEnvelope {
	t.Helper()
	block, err := client.GetNowBlock()
	require.NoError(t, err)
	header := block.GetBlockHeader().GetRawData()
	require.NotNil(t, header)
	blockID := block.GetBlockid()
	require.GreaterOrEqual(t, len(blockID), 16)

	refBlockBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(refBlockBytes, uint16(header.GetNumber()))
	return v1.TRONRawDataEnvelope{
		RefBlockBytes: hex.EncodeToString(refBlockBytes),
		RefBlockHash:  hex.EncodeToString(blockID[8:16]),
		Timestamp:     header.GetTimestamp(),
		Expiration:    header.GetTimestamp() + offsetMillis,
	}
}

func broadcastSignedPayload(client *tronclient.GrpcClient, signedPayload string) error {
	raw, err := hex.DecodeString(strings.TrimPrefix(signedPayload, "0x"))
	if err != nil {
		return err
	}
	var tx core.Transaction
	if err := proto.Unmarshal(raw, &tx); err != nil {
		return err
	}
	_, err = client.Broadcast(&tx)
	return err
}

func requiredEnv(t *testing.T, key string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		t.Skipf("set %s to run live TRON integration tests", key)
	}
	return value
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
