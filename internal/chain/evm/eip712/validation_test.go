package eip712

import (
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDomainValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Domain)
		want   string
	}{
		{name: "empty name", mutate: func(domain *Domain) { domain.Name = "" }, want: "domain name must not be empty"},
		{name: "invalid name UTF-8", mutate: func(domain *Domain) { domain.Name = string([]byte{0xff}) }, want: "valid UTF-8"},
		{name: "empty version", mutate: func(domain *Domain) { domain.Version = "" }, want: "domain version must not be empty"},
		{name: "empty chain", mutate: func(domain *Domain) { domain.ChainID = "" }, want: "canonical base-10"},
		{name: "hex chain", mutate: func(domain *Domain) { domain.ChainID = "0x1" }, want: "canonical base-10"},
		{name: "leading zero chain", mutate: func(domain *Domain) { domain.ChainID = "01" }, want: "canonical base-10"},
		{name: "zero chain", mutate: func(domain *Domain) { domain.ChainID = "0" }, want: "greater than zero"},
		{name: "chain overflow", mutate: func(domain *Domain) { domain.ChainID = new(big.Int).Lsh(big.NewInt(1), 256).String() }, want: "outside the uint256 range"},
		{name: "missing address prefix", mutate: func(domain *Domain) { domain.VerifyingContract = strings.Repeat("1", 40) }, want: "canonical lowercase"},
		{name: "uppercase address", mutate: func(domain *Domain) { domain.VerifyingContract = "0xA111111111111111111111111111111111111111" }, want: "canonical lowercase"},
		{name: "zero contract", mutate: func(domain *Domain) { domain.VerifyingContract = "0x0000000000000000000000000000000000000000" }, want: "must not be the zero address"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			domain := testDomain
			test.mutate(&domain)
			_, err := DomainSeparator(domain)
			require.ErrorContains(t, err, test.want)
		})
	}
}

func TestPermitMessageValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PermitMessage)
		want   string
	}{
		{name: "zero owner", mutate: func(message *PermitMessage) { message.Owner = "0x0000000000000000000000000000000000000000" }, want: "owner must not be the zero address"},
		{name: "uppercase owner", mutate: func(message *PermitMessage) { message.Owner = "0x7E5f4552091a69125d5dfcb7b8c2659029395bdf" }, want: "canonical lowercase"},
		{name: "bad spender", mutate: func(message *PermitMessage) { message.Spender = "0xnope" }, want: "canonical lowercase"},
		{name: "empty value", mutate: func(message *PermitMessage) { message.Value = "" }, want: "canonical base-10"},
		{name: "signed value", mutate: func(message *PermitMessage) { message.Value = "+1" }, want: "canonical base-10"},
		{name: "leading zero nonce", mutate: func(message *PermitMessage) { message.Nonce = "00" }, want: "canonical base-10"},
		{name: "negative deadline", mutate: func(message *PermitMessage) { message.Deadline = "-1" }, want: "canonical base-10"},
		{name: "deadline overflow", mutate: func(message *PermitMessage) { message.Deadline = new(big.Int).Lsh(big.NewInt(1), 256).String() }, want: "outside the uint256 range"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := testMessage
			test.mutate(&message)
			_, err := PermitStructHash(message)
			require.ErrorContains(t, err, test.want)
		})
	}
}
