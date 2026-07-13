package conformance_test

import (
	"testing"

	"github.com/chain-signer/chain-signer/internal/routes"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestConformance_AdvancedEVMPolicyOptIn(t *testing.T) {
	fixture, raw := newAdvancedEVMFixture(t, "evm-advanced-policy", false)
	require.NotContains(t, raw, "private_key_hex")
	require.NotContains(t, raw, "policy", "advanced operations must not be implicitly enabled")

	permitRequest := v1.EVMEIP712SignRequest{
		EVMAdvancedSignRequestBase: fixture.base("advanced-permit-denied"),
		EIP712PermitPayload:        conformancePermit(fixture.signer, fixture.chainID),
	}
	_, err := handle(t, fixture.ctx, fixture.backend, fixture.storage, logical.UpdateOperation, routes.EVMEIP712Sign, mustMap(t, permitRequest))
	require.Error(t, err)
	require.ErrorContains(t, err, "signing operation is not explicitly allowed")

	_, err = handle(t, fixture.ctx, fixture.backend, fixture.storage, logical.UpdateOperation, routes.KeyPolicyRoot+"/"+fixture.keyID, map[string]interface{}{})
	require.ErrorContains(t, err, "policy is required")
	readBack, _ := readKey(t, fixture.ctx, fixture.backend, fixture.storage, fixture.keyID)
	require.True(t, readBack.Policy.IsZero())

	policy := advancedEVMPolicy()
	response, err := handle(t, fixture.ctx, fixture.backend, fixture.storage, logical.UpdateOperation, routes.KeyPolicyRoot+"/"+fixture.keyID, mustMap(t, v1.UpdateKeyPolicyRequest{Policy: v1.StructuredPolicyFromPolicy(policy)}))
	require.NoError(t, err)
	updated := decodeResponse[v1.KeyResponse](t, response)
	require.Equal(t, policy, updated.Policy)
	require.NotEmpty(t, updated.UpdatedAt)

	readBack, _ = readKey(t, fixture.ctx, fixture.backend, fixture.storage, fixture.keyID)
	require.Equal(t, policy, readBack.Policy)
}
