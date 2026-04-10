package backend

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/chain-signer/chain-signer/internal/version"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/chain-signer/chain-signer/pkg/model"
	"github.com/chain-signer/chain-signer/pkg/policy"
	signerpkg "github.com/chain-signer/chain-signer/pkg/signer"
	storepkg "github.com/chain-signer/chain-signer/pkg/storage"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type Backend struct {
	*framework.Backend
	signers signerpkg.Engine
}

func New(resolver signerpkg.Resolver) *Backend {
	b := &Backend{
		signers: signerpkg.Engine{External: resolver},
	}
	b.Backend = &framework.Backend{
		Help:        "Chain-Signer is a typed signing backend for EVM and TRON workloads.",
		BackendType: logical.TypeLogical,
		Paths:       b.paths(),
	}
	return b
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := New(nil)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *Backend) paths() []*framework.Path {
	keyID := map[string]*framework.FieldSchema{
		"key_id": {Type: framework.TypeString},
	}

	return []*framework.Path{
		{
			Pattern:             `v1/version/?`,
			TakesArbitraryInput: true,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleVersion,
					Summary:  "Read API and build version metadata.",
				},
			},
		},
		{
			Pattern:             `v1/keys/?`,
			TakesArbitraryInput: true,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleCreateKey,
					Summary:  "Create or import a chain-bound signing key.",
				},
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleListKeys,
					Summary:  "List configured key IDs.",
				},
			},
		},
		{
			Pattern:             `v1/keys/` + framework.GenericNameRegex("key_id"),
			Fields:              keyID,
			TakesArbitraryInput: true,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleReadKey,
					Summary:  "Read key metadata.",
				},
			},
		},
		{
			Pattern:             `v1/keys/` + framework.GenericNameRegex("key_id") + `/status`,
			Fields:              keyID,
			TakesArbitraryInput: true,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleUpdateKeyStatus,
					Summary:  "Enable or disable a key.",
				},
			},
		},
		b.signPath(`v1/evm/transfers/legacy/sign`, b.handleEVMLegacyTransfer),
		b.signPath(`v1/evm/transfers/eip1559/sign`, b.handleEVMEIP1559Transfer),
		b.signPath(`v1/evm/contracts/eip1559/sign`, b.handleEVMContractCall),
		b.signPath(`v1/tron/transfers/trx/sign`, b.handleTRXTransfer),
		b.signPath(`v1/tron/transfers/trc20/sign`, b.handleTRC20Transfer),
		b.signPath(`v1/verify`, b.handleVerify),
		b.signPath(`v1/recover`, b.handleRecover),
	}
}

func (b *Backend) signPath(pattern string, callback framework.OperationFunc) *framework.Path {
	return &framework.Path{
		Pattern:             pattern,
		TakesArbitraryInput: true,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: callback,
				Summary:  "Handle a typed signing or recovery request.",
			},
		},
	}
}

func (b *Backend) handleVersion(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return response(versionResponse{
		APIVersion:   v1.APIVersion,
		BuildVersion: version.Version,
	}), nil
}

func (b *Backend) handleCreateKey(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.CreateKeyRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, badRequest(err)
	}
	if err := policy.ValidateCreateKeyRequest(payload); err != nil {
		return nil, badRequest(err)
	}

	keyID := payload.KeyID
	if keyID == "" {
		var err error
		keyID, err = model.GenerateKeyID()
		if err != nil {
			return nil, err
		}
	}
	existing, err := storepkg.GetKey(ctx, req.Storage, keyID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, logical.CodedError(http.StatusConflict, fmt.Sprintf("key %q already exists", keyID))
	}

	chainFamily := model.NormalizeChainFamily(payload.ChainFamily)
	custodyMode := model.NormalizeCustodyMode(payload.CustodyMode)
	if custodyMode == "" {
		custodyMode = model.CustodyModeMVP
	}

	var (
		publicKey *ecdsa.PublicKey
		privHex   string
	)
	switch custodyMode {
	case model.CustodyModeMVP:
		if payload.ImportPrivateKey != "" {
			privateKey, err := model.ParsePrivateKeyHex(payload.ImportPrivateKey)
			if err != nil {
				return nil, badRequest(err)
			}
			publicKey = &privateKey.PublicKey
			privHex = model.EncodeHex(ethcrypto.FromECDSA(privateKey))
		} else {
			privateKey, err := ethcrypto.GenerateKey()
			if err != nil {
				return nil, err
			}
			publicKey = &privateKey.PublicKey
			privHex = model.EncodeHex(ethcrypto.FromECDSA(privateKey))
		}
	case model.CustodyModePKCS11:
		var err error
		publicKey, err = model.ParsePublicKeyHex(payload.PublicKeyHex)
		if err != nil {
			return nil, badRequest(err)
		}
	default:
		return nil, badRequest(fmt.Errorf("unsupported custody mode %q", payload.CustodyMode))
	}

	signerAddress, err := model.DeriveSignerAddress(chainFamily, publicKey)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	key := model.Key{
		ID:                keyID,
		ChainFamily:       chainFamily,
		CustodyMode:       custodyMode,
		Active:            true,
		Labels:            payload.Labels,
		Policy:            payload.Policy,
		SignerAddress:     signerAddress,
		PublicKeyHex:      model.PublicKeyHex(publicKey),
		PrivateKeyHex:     privHex,
		ExternalSignerRef: payload.ExternalSignerRef,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := storepkg.PutKey(ctx, req.Storage, key); err != nil {
		return nil, err
	}
	return response(keyResponse(key)), nil
}

func (b *Backend) handleListKeys(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	keys, err := storepkg.ListKeys(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		ids = append(ids, key.ID)
	}
	return logical.ListResponse(ids), nil
}

func (b *Backend) handleReadKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	key, err := loadKey(ctx, req.Storage, fieldString(d, "key_id"))
	if err != nil {
		return nil, err
	}
	return response(keyResponse(*key)), nil
}

func (b *Backend) handleUpdateKeyStatus(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	key, err := loadKey(ctx, req.Storage, fieldString(d, "key_id"))
	if err != nil {
		return nil, err
	}
	var payload v1.UpdateKeyStatusRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, badRequest(err)
	}
	key.Active = payload.Active
	key.UpdatedAt = time.Now().UTC()
	if err := storepkg.PutKey(ctx, req.Storage, *key); err != nil {
		return nil, err
	}
	return response(keyResponse(*key)), nil
}

func (b *Backend) handleEVMLegacyTransfer(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.EVMLegacyTransferSignRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, badRequest(err)
	}
	key, err := loadKey(ctx, req.Storage, payload.KeyID)
	if err != nil {
		return nil, err
	}
	if err := policy.ValidateEVMLegacyTransfer(*key, payload); err != nil {
		return nil, badRequest(err)
	}
	material, err := b.signers.MaterialFor(ctx, *key)
	if err != nil {
		return nil, err
	}
	result, err := signerpkg.SignEVMLegacyTransfer(ctx, material, payload)
	if err != nil {
		return nil, badRequest(err)
	}
	return response(result), nil
}

func (b *Backend) handleEVMEIP1559Transfer(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.EVMEIP1559TransferSignRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, badRequest(err)
	}
	key, err := loadKey(ctx, req.Storage, payload.KeyID)
	if err != nil {
		return nil, err
	}
	if err := policy.ValidateEVMEIP1559Transfer(*key, payload); err != nil {
		return nil, badRequest(err)
	}
	material, err := b.signers.MaterialFor(ctx, *key)
	if err != nil {
		return nil, err
	}
	result, err := signerpkg.SignEVMEIP1559Transfer(ctx, material, payload)
	if err != nil {
		return nil, badRequest(err)
	}
	return response(result), nil
}

func (b *Backend) handleEVMContractCall(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.EVMContractCallSignRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, badRequest(err)
	}
	key, err := loadKey(ctx, req.Storage, payload.KeyID)
	if err != nil {
		return nil, err
	}
	if err := policy.ValidateEVMContractCall(*key, payload); err != nil {
		return nil, badRequest(err)
	}
	material, err := b.signers.MaterialFor(ctx, *key)
	if err != nil {
		return nil, err
	}
	result, err := signerpkg.SignEVMContractCall(ctx, material, payload)
	if err != nil {
		return nil, badRequest(err)
	}
	return response(result), nil
}

func (b *Backend) handleTRXTransfer(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.TRXTransferSignRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, badRequest(err)
	}
	key, err := loadKey(ctx, req.Storage, payload.KeyID)
	if err != nil {
		return nil, err
	}
	if err := policy.ValidateTRXTransfer(*key, payload); err != nil {
		return nil, badRequest(err)
	}
	material, err := b.signers.MaterialFor(ctx, *key)
	if err != nil {
		return nil, err
	}
	result, err := signerpkg.SignTRXTransfer(ctx, material, payload)
	if err != nil {
		return nil, badRequest(err)
	}
	return response(result), nil
}

func (b *Backend) handleTRC20Transfer(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.TRC20TransferSignRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, badRequest(err)
	}
	key, err := loadKey(ctx, req.Storage, payload.KeyID)
	if err != nil {
		return nil, err
	}
	if err := policy.ValidateTRC20Transfer(*key, payload); err != nil {
		return nil, badRequest(err)
	}
	material, err := b.signers.MaterialFor(ctx, *key)
	if err != nil {
		return nil, err
	}
	result, err := signerpkg.SignTRC20Transfer(ctx, material, payload)
	if err != nil {
		return nil, badRequest(err)
	}
	return response(result), nil
}

func (b *Backend) handleVerify(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.VerifyRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, badRequest(err)
	}
	result, err := recoverForVerify(payload)
	if err != nil {
		return nil, badRequest(err)
	}
	matchSigner := true
	if payload.ExpectedSignerAddress != "" {
		matchSigner = result.MatchesExpected
	}
	matchOperation := true
	if payload.Operation != "" {
		matchOperation = result.Operation == payload.Operation
	}
	result.MatchesExpected = matchSigner && matchOperation
	return response(result), nil
}

func (b *Backend) handleRecover(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var payload v1.VerifyRequest
	if err := decode(req.Data, &payload); err != nil {
		return nil, badRequest(err)
	}
	result, err := recoverForVerify(payload)
	if err != nil {
		return nil, badRequest(err)
	}
	return response(result), nil
}

func recoverForVerify(req v1.VerifyRequest) (*v1.RecoverResponse, error) {
	switch model.NormalizeChainFamily(req.ChainFamily) {
	case model.ChainFamilyEVM:
		return signerpkg.RecoverEVM(req)
	case model.ChainFamilyTRON:
		return signerpkg.RecoverTRON(req)
	default:
		return nil, fmt.Errorf("unsupported chain family %q", req.ChainFamily)
	}
}

func loadKey(ctx context.Context, s logical.Storage, keyID string) (*model.Key, error) {
	if keyID == "" {
		return nil, badRequest(errors.New("key_id is required"))
	}
	key, err := storepkg.GetKey(ctx, s, keyID)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, logical.CodedError(http.StatusNotFound, fmt.Sprintf("key %q was not found", keyID))
	}
	return key, nil
}

func decode(input map[string]interface{}, out interface{}) error {
	if len(input) == 0 {
		input = map[string]interface{}{}
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode request body: %w", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode request body: %w", err)
	}
	return nil
}

func response(payload interface{}) *logical.Response {
	raw, err := json.Marshal(payload)
	if err != nil {
		return logical.ErrorResponse(err.Error())
	}
	out := make(map[string]interface{})
	if err := json.Unmarshal(raw, &out); err != nil {
		return logical.ErrorResponse(err.Error())
	}
	return &logical.Response{Data: out}
}

func keyResponse(key model.Key) v1.KeyResponse {
	return v1.KeyResponse{
		APIVersion:    v1.APIVersion,
		KeyID:         key.ID,
		ChainFamily:   key.ChainFamily,
		CustodyMode:   key.CustodyMode,
		Active:        key.Active,
		Labels:        key.Labels,
		Policy:        key.Policy,
		SignerAddress: key.SignerAddress,
		PublicKeyHex:  key.PublicKeyHex,
		CreatedAt:     key.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt:     key.UpdatedAt.Format(time.RFC3339Nano),
	}
}

func fieldString(d *framework.FieldData, name string) string {
	value := d.Get(name)
	if value == nil {
		return ""
	}
	asString, _ := value.(string)
	return asString
}

func badRequest(err error) error {
	return logical.CodedError(http.StatusBadRequest, err.Error())
}

type versionResponse struct {
	APIVersion   string `json:"api_version"`
	BuildVersion string `json:"build_version"`
}
