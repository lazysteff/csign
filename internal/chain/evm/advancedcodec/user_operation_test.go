package advancedcodec

import (
	"math/big"
	"testing"

	"github.com/chain-signer/chain-signer/internal/chain/evm/erc4337"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestPrepareUserOperationMapsUnpackedFieldsAndChecksHash(t *testing.T) {
	input := codecUserOperation()
	prepared, err := PrepareUserOperation(
		v1.ERC4337ProtocolV09,
		v1.ERC4337AccountSimpleAccount,
		v1.ERC4337AccountSimpleAccountVersion,
		v1.ERC4337SimpleAccountSigningSchema,
		"1",
		codecEntryPoint,
		codecSigner,
		"",
		input,
	)
	require.NoError(t, err)
	require.Equal(t, common.HexToAddress(codecSender), prepared.Operation.Sender)
	require.Equal(t, "7", prepared.Operation.Nonce.String())
	require.Equal(t, []byte{0xaa, 0xbb}, prepared.Operation.CallData)
	require.Equal(t, "100000", prepared.Operation.CallGasLimit.String())
	require.Equal(t, "200000", prepared.Operation.VerificationGasLimit.String())
	require.Equal(t, "50000", prepared.Operation.PreVerificationGas.String())
	require.Equal(t, "100", prepared.Operation.MaxFeePerGas.String())
	require.Equal(t, "2", prepared.Operation.MaxPriorityFeePerGas.String())
	require.NotNil(t, prepared.Operation.Factory)
	require.Equal(t, common.HexToAddress(codecFactory), prepared.Operation.Factory.Address)
	require.Equal(t, []byte{0x12, 0x34}, prepared.Operation.Factory.Data)
	require.NotNil(t, prepared.Operation.Paymaster)
	require.Equal(t, common.HexToAddress(codecPaymaster), prepared.Operation.Paymaster.Address)
	require.Equal(t, []byte{0x56, 0x78}, prepared.Operation.Paymaster.Data)
	require.Equal(t, []byte{0x99, 0x00}, prepared.Operation.Paymaster.Signature)
	require.Equal(t, common.HexToAddress(codecEntryPoint), prepared.EntryPoint)
	require.Equal(t, big.NewInt(1), prepared.ChainID)
	require.Equal(t, common.HexToAddress(codecSigner), prepared.Expected)
	require.Nil(t, prepared.Delegate)

	withExpectedHash, err := PrepareUserOperation(
		v1.ERC4337ProtocolV09,
		v1.ERC4337AccountSimpleAccount,
		v1.ERC4337AccountSimpleAccountVersion,
		v1.ERC4337SimpleAccountSigningSchema,
		"1",
		codecEntryPoint,
		codecSigner,
		prepared.Hash.Hex(),
		input,
	)
	require.NoError(t, err)
	require.Equal(t, prepared.Hash, withExpectedHash.Hash)

	_, err = PrepareUserOperation(
		v1.ERC4337ProtocolV09,
		v1.ERC4337AccountSimpleAccount,
		v1.ERC4337AccountSimpleAccountVersion,
		v1.ERC4337SimpleAccountSigningSchema,
		"1",
		codecEntryPoint,
		codecSigner,
		common.Hash{}.Hex(),
		input,
	)
	require.ErrorContains(t, err, "expected_user_operation_hash does not match reconstructed hash")

	// EntryPoint v0.9 excludes the paymaster signature suffix from the
	// account hash even though advancedcodec preserves it for packing.
	changedPaymasterSignature := codecUserOperation()
	changedPaymasterSignature.Paymaster.Signature = "0x01020304"
	changed, err := PrepareUserOperation(
		v1.ERC4337ProtocolV09,
		v1.ERC4337AccountSimpleAccount,
		v1.ERC4337AccountSimpleAccountVersion,
		v1.ERC4337SimpleAccountSigningSchema,
		"1",
		codecEntryPoint,
		codecSigner,
		"",
		changedPaymasterSignature,
	)
	require.NoError(t, err)
	require.Equal(t, prepared.Hash, changed.Hash)
}

func TestPrepareUserOperationMapsEIP7702ContextAndRejectsAmbiguity(t *testing.T) {
	input := codecUserOperation()
	input.Factory = nil
	input.EIP7702 = &v1.ERC4337EIP7702Context{
		DelegateAddress: codecFactory,
		Data:            "0xabcd",
	}

	prepared, err := PrepareUserOperation(
		v1.ERC4337ProtocolV09,
		v1.ERC4337AccountSimpleAccount,
		v1.ERC4337AccountSimpleAccountVersion,
		v1.ERC4337SimpleAccountSigningSchema,
		"1",
		codecEntryPoint,
		codecSigner,
		"",
		input,
	)
	require.NoError(t, err)
	require.Nil(t, prepared.Operation.Factory)
	require.NotNil(t, prepared.Operation.EIP7702)
	require.Equal(t, []byte{0xab, 0xcd}, prepared.Operation.EIP7702.Data)
	require.NotNil(t, prepared.Delegate)
	require.Equal(t, common.HexToAddress(codecFactory), *prepared.Delegate)

	input.Factory = &v1.ERC4337Factory{Address: codecFactory, Data: "0x"}
	_, err = PrepareUserOperation(
		v1.ERC4337ProtocolV09,
		v1.ERC4337AccountSimpleAccount,
		v1.ERC4337AccountSimpleAccountVersion,
		v1.ERC4337SimpleAccountSigningSchema,
		"1",
		codecEntryPoint,
		codecSigner,
		"",
		input,
	)
	require.ErrorContains(t, err, "factory and eip7702 are mutually exclusive")
}

func TestPreparedUserOperationUsesPinnedCompatibilityIdentifiers(t *testing.T) {
	require.Equal(t, erc4337.ProtocolID, v1.ERC4337ProtocolV09)
	require.Equal(t, erc4337.SimpleAccountImplementation, v1.ERC4337AccountSimpleAccount)
	require.Equal(t, erc4337.SimpleAccountImplementationVersion, v1.ERC4337AccountSimpleAccountVersion)
	require.Equal(t, erc4337.SimpleAccountSigningSchema, v1.ERC4337SimpleAccountSigningSchema)
}
