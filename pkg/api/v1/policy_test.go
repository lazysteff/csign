package v1

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpdateKeyPolicyRequestRequiresExplicitNonNullPolicy(t *testing.T) {
	var missing UpdateKeyPolicyRequest
	require.NoError(t, json.Unmarshal([]byte(`{}`), &missing))
	require.False(t, missing.HasPolicy())

	var nullPolicy UpdateKeyPolicyRequest
	require.ErrorContains(t, json.Unmarshal([]byte(`{"policy":null}`), &nullPolicy), "policy must not be null")

	var explicit UpdateKeyPolicyRequest
	require.NoError(t, json.Unmarshal([]byte(`{"policy":{}}`), &explicit))
	require.True(t, explicit.HasPolicy())
}

func TestUpdateKeyPolicyRequestRejectsLegacyAdditionalPolicyContext(t *testing.T) {
	var request UpdateKeyPolicyRequest
	err := json.Unmarshal([]byte(`{"policy":{"additional_policy_context":{"workflow":"opaque"}}}`), &request)
	require.ErrorContains(t, err, `unknown field "additional_policy_context"`)
}

func TestStructuredPolicyConversionCoversEveryFieldWithoutAliasing(t *testing.T) {
	policy := Policy{}
	value := reflect.ValueOf(&policy).Elem()
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		if value.Type().Field(index).Name == "AdditionalPolicyContext" {
			continue
		}
		switch field.Kind() {
		case reflect.Slice:
			switch field.Type().Elem().Kind() {
			case reflect.String:
				field.Set(reflect.ValueOf([]string{"value"}))
			case reflect.Int64:
				field.Set(reflect.ValueOf([]int64{1}))
			}
		case reflect.String:
			field.SetString("1")
		case reflect.Uint64:
			field.SetUint(1)
		case reflect.Int64:
			field.SetInt(1)
		case reflect.Bool:
			field.SetBool(true)
		}
	}
	policy.AdditionalPolicyContext = map[string]string{"legacy": "opaque"}

	structured := StructuredPolicyFromPolicy(policy)
	require.Nil(t, structured.AdditionalPolicyContext)
	roundTrip := structured.Clone()
	want := policy.Clone()
	want.AdditionalPolicyContext = nil
	require.Equal(t, want, roundTrip)

	structured.AllowedNetworks[0] = "changed"
	require.Equal(t, "value", policy.AllowedNetworks[0])
	roundTrip.AllowedSelectors[0] = "changed"
	require.Equal(t, "value", structured.AllowedSelectors[0])
}
