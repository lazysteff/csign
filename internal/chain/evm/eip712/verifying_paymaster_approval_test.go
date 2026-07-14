package eip712

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestVerifyingPaymasterApprovalCrossLanguageFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/verifying_paymaster_approval_v1.json")
	require.NoError(t, err)
	var fixture struct {
		SchemaID      string                     `json:"schema_id"`
		SchemaVersion string                     `json:"schema_version"`
		Domain        Domain                     `json:"domain"`
		Message       VerifyingPaymasterApproval `json:"message"`
		Digest        string                     `json:"eip712_digest"`
	}
	require.NoError(t, json.Unmarshal(data, &fixture))
	require.Equal(t, VerifyingPaymasterApprovalSchemaID, fixture.SchemaID)
	require.Equal(t, VerifyingPaymasterApprovalSchemaVersion, fixture.SchemaVersion)
	hashes, err := HashVerifyingPaymasterApproval(fixture.Domain, fixture.Message)
	require.NoError(t, err)
	require.Equal(t, fixture.Digest, hashes.Digest.Hex())
}

func TestVerifyingPaymasterApprovalHashBindsEveryApprovalDimension(t *testing.T) {
	domain, message := testVerifyingPaymasterApproval()
	base, err := HashVerifyingPaymasterApproval(domain, message)
	require.NoError(t, err)
	require.NotEqual(t, common.Hash{}, base.Digest)

	mutations := []func(*VerifyingPaymasterApproval){
		func(m *VerifyingPaymasterApproval) { m.ChainID = "42162" },
		func(m *VerifyingPaymasterApproval) { m.EntryPoint = "0x3333333333333333333333333333333333333333" },
		func(m *VerifyingPaymasterApproval) { m.Paymaster = "0x4444444444444444444444444444444444444444" },
		func(m *VerifyingPaymasterApproval) {
			m.UserOpHash = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
		func(m *VerifyingPaymasterApproval) { m.ValidAfter = "2" },
		func(m *VerifyingPaymasterApproval) { m.ValidUntil = "200" },
		func(m *VerifyingPaymasterApproval) { m.MaxSponsoredCost = "1001" },
		func(m *VerifyingPaymasterApproval) {
			m.Nonce = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		},
		func(m *VerifyingPaymasterApproval) {
			m.ContextHash = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		},
	}
	for _, mutate := range mutations {
		changed := message
		mutate(&changed)
		changedDomain := domain
		if changed.ChainID != message.ChainID {
			changedDomain.ChainID = changed.ChainID
		}
		if changed.Paymaster != message.Paymaster {
			changedDomain.VerifyingContract = changed.Paymaster
		}
		hashes, hashErr := HashVerifyingPaymasterApproval(changedDomain, changed)
		require.NoError(t, hashErr)
		require.NotEqual(t, base.Digest, hashes.Digest)
	}
}

func TestVerifyingPaymasterApprovalRejectsWrongDomainAndMixedSchema(t *testing.T) {
	domain, message := testVerifyingPaymasterApproval()
	domain.Name = "ApplicationPaymaster"
	_, err := HashVerifyingPaymasterApproval(domain, message)
	require.ErrorContains(t, err, "domain name")

	domain.Name = VerifyingPaymasterApprovalDomainName
	raw, marshalErr := json.Marshal(map[string]any{
		"chain_id": message.ChainID, "entry_point": message.EntryPoint, "paymaster": message.Paymaster,
		"user_op_hash": message.UserOpHash, "valid_after": message.ValidAfter, "valid_until": message.ValidUntil,
		"max_sponsored_cost": message.MaxSponsoredCost, "approval_nonce": message.Nonce,
		"context_hash": message.ContextHash, "owner": "0x1111111111111111111111111111111111111111",
	})
	require.NoError(t, marshalErr)
	_, err = HashVerifyingPaymasterApprovalRaw(domain, raw)
	require.ErrorContains(t, err, "unknown field")
}

func testVerifyingPaymasterApproval() (Domain, VerifyingPaymasterApproval) {
	paymaster := "0x2222222222222222222222222222222222222222"
	return Domain{
			Name: VerifyingPaymasterApprovalDomainName, Version: VerifyingPaymasterApprovalDomainVersion,
			ChainID: "42161", VerifyingContract: paymaster,
		}, VerifyingPaymasterApproval{
			ChainID: "42161", EntryPoint: "0x1111111111111111111111111111111111111111", Paymaster: paymaster,
			UserOpHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ValidAfter: "1", ValidUntil: "100", MaxSponsoredCost: "1000",
			Nonce:       "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			ContextHash: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		}
}
