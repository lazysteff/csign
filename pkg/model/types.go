package model

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	tronaddress "github.com/fbsobreira/gotron-sdk/pkg/address"
)

const (
	APIVersion = "v1"

	ChainFamilyEVM  = "evm"
	ChainFamilyTRON = "tron"

	CustodyModeMVP    = "mvp"
	CustodyModePKCS11 = "pkcs11"

	OperationEVMTransferLegacy  = "evm_transfer_legacy"
	OperationEVMTransferEIP1559 = "evm_transfer_eip1559"
	OperationEVMContractEIP1559 = "evm_contract_call_eip1559"
	OperationTRXTransfer        = "tron_transfer_trx"
	OperationTRC20Transfer      = "tron_transfer_trc20"
	TRC20TransferSelector       = "a9059cbb"
	DefaultPayloadEncoding      = "hex"
	DefaultGeneratedKeyIDPrefix = "key_"
)

type Policy struct {
	AllowedNetworks         []string          `json:"allowed_networks,omitempty"`
	AllowedChainIDs         []int64           `json:"allowed_chain_ids,omitempty"`
	MaxValue                string            `json:"max_value,omitempty"`
	MaxGasLimit             uint64            `json:"max_gas_limit,omitempty"`
	MaxGasPrice             string            `json:"max_gas_price,omitempty"`
	MaxFeePerGas            string            `json:"max_fee_per_gas,omitempty"`
	MaxPriorityFeePerGas    string            `json:"max_priority_fee_per_gas,omitempty"`
	MaxFeeLimit             int64             `json:"max_fee_limit,omitempty"`
	AllowedTokenContracts   []string          `json:"allowed_token_contracts,omitempty"`
	AllowedSelectors        []string          `json:"allowed_selectors,omitempty"`
	AdditionalPolicyContext map[string]string `json:"additional_policy_context,omitempty"`
}

type Key struct {
	ID                string            `json:"id"`
	ChainFamily       string            `json:"chain_family"`
	CustodyMode       string            `json:"custody_mode"`
	Active            bool              `json:"active"`
	Labels            map[string]string `json:"labels,omitempty"`
	Policy            Policy            `json:"policy,omitempty"`
	SignerAddress     string            `json:"signer_address"`
	PublicKeyHex      string            `json:"public_key_hex"`
	PrivateKeyHex     string            `json:"private_key_hex,omitempty"`
	ExternalSignerRef string            `json:"external_signer_ref,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

func NormalizeChainFamily(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func NormalizeCustodyMode(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func NormalizeSelector(value string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "0x"))
}

func GenerateKeyID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate key id: %w", err)
	}
	return DefaultGeneratedKeyIDPrefix + hex.EncodeToString(buf), nil
}

func NormalizeHex(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		return value[2:]
	}
	return value
}

func DecodeHex(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(NormalizeHex(value))
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	return decoded, nil
}

func EncodeHex(value []byte) string {
	return "0x" + hex.EncodeToString(value)
}

func ParseBigInt(value string) (*big.Int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("numeric value is required")
	}
	base := 10
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		base = 16
		value = value[2:]
	}
	out, ok := new(big.Int).SetString(value, base)
	if !ok {
		return nil, fmt.Errorf("invalid numeric value %q", value)
	}
	return out, nil
}

func ParsePrivateKeyHex(value string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := DecodeHex(value)
	if err != nil {
		return nil, err
	}
	key, err := ethcrypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return key, nil
}

func ParsePublicKeyHex(value string) (*ecdsa.PublicKey, error) {
	pubBytes, err := DecodeHex(value)
	if err != nil {
		return nil, err
	}
	switch len(pubBytes) {
	case 33:
		pub, err := ethcrypto.DecompressPubkey(pubBytes)
		if err != nil {
			return nil, fmt.Errorf("parse compressed public key: %w", err)
		}
		return pub, nil
	case 65:
		pub, err := ethcrypto.UnmarshalPubkey(pubBytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported public key length %d", len(pubBytes))
	}
}

func PublicKeyHex(pub *ecdsa.PublicKey) string {
	return EncodeHex(ethcrypto.FromECDSAPub(pub))
}

func DeriveSignerAddress(chainFamily string, pub *ecdsa.PublicKey) (string, error) {
	switch NormalizeChainFamily(chainFamily) {
	case ChainFamilyEVM:
		return ethcrypto.PubkeyToAddress(*pub).Hex(), nil
	case ChainFamilyTRON:
		return tronaddress.PubkeyToAddress(*pub).String(), nil
	default:
		return "", fmt.Errorf("unsupported chain family %q", chainFamily)
	}
}

func NormalizeAddress(chainFamily, value string) (string, error) {
	switch NormalizeChainFamily(chainFamily) {
	case ChainFamilyEVM:
		if !ethcommon.IsHexAddress(value) {
			return "", fmt.Errorf("invalid evm address %q", value)
		}
		return ethcommon.HexToAddress(value).Hex(), nil
	case ChainFamilyTRON:
		addr, err := tronaddress.Base58ToAddress(value)
		if err != nil {
			return "", fmt.Errorf("invalid tron address %q: %w", value, err)
		}
		return addr.String(), nil
	default:
		return "", fmt.Errorf("unsupported chain family %q", chainFamily)
	}
}

func EqualAddress(chainFamily, left, right string) bool {
	nl, err := NormalizeAddress(chainFamily, left)
	if err != nil {
		return false
	}
	nr, err := NormalizeAddress(chainFamily, right)
	if err != nil {
		return false
	}
	return nl == nr
}

func SelectorFromHexData(data string) (string, error) {
	raw, err := DecodeHex(data)
	if err != nil {
		return "", err
	}
	if len(raw) < 4 {
		return "", fmt.Errorf("call data must include a 4-byte selector")
	}
	return strings.ToLower(hex.EncodeToString(raw[:4])), nil
}
