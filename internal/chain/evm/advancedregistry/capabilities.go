package advancedregistry

import (
	"sort"

	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

func (r Registry) Capabilities() (
	[]v1.EIP712SchemaCapability,
	[]string,
	[]v1.ERC4337AccountCapability,
	[]string,
	[]string,
	[]v1.EIP7702TransactionCapability,
) {
	schemas := make([]v1.EIP712SchemaCapability, 0, len(r.eip712Schemas))
	for _, schema := range r.eip712Schemas {
		schemas = append(schemas, v1.EIP712SchemaCapability{
			ID: schema.ID, Version: schema.Version, PrimaryType: schema.PrimaryType, SignatureEncoding: schema.SignatureEncoding,
		})
	}
	sort.Slice(schemas, func(i, j int) bool {
		if schemas[i].ID == schemas[j].ID {
			return schemas[i].Version < schemas[j].Version
		}
		return schemas[i].ID < schemas[j].ID
	})

	protocolSet := make(map[string]struct{})
	signingSet := make(map[string]struct{})
	accountCapabilities := make(map[string]*v1.ERC4337AccountCapability, len(r.accountAdapters))
	for _, adapter := range r.accountAdapters {
		protocolSet[adapter.ProtocolVersion] = struct{}{}
		signingSet[adapter.SigningSchema] = struct{}{}
		key := accountCapabilityKey(adapter.ID, adapter.Version, adapter.SignatureEncoding)
		capability := accountCapabilities[key]
		if capability == nil {
			capability = &v1.ERC4337AccountCapability{
				ID:                adapter.ID,
				Version:           adapter.Version,
				SignatureEncoding: adapter.SignatureEncoding,
			}
			accountCapabilities[key] = capability
		}
		capability.ProtocolVersions = appendUnique(capability.ProtocolVersions, adapter.ProtocolVersion)
		capability.SigningSchemas = appendUnique(capability.SigningSchemas, adapter.SigningSchema)
	}
	accounts := make([]v1.ERC4337AccountCapability, 0, len(accountCapabilities))
	for _, capability := range accountCapabilities {
		sort.Strings(capability.ProtocolVersions)
		sort.Strings(capability.SigningSchemas)
		accounts = append(accounts, *capability)
	}
	sort.Slice(accounts, func(i, j int) bool {
		if accounts[i].ID == accounts[j].ID {
			if accounts[i].Version == accounts[j].Version {
				return accounts[i].SigningSchemas[0] < accounts[j].SigningSchemas[0]
			}
			return accounts[i].Version < accounts[j].Version
		}
		return accounts[i].ID < accounts[j].ID
	})
	protocols := sortedKeys(protocolSet)
	signingSchemas := sortedKeys(signingSet)
	authorizationSchemas := sortedKeys(r.authorizationSchemas)

	transactionTypes := make([]v1.EIP7702TransactionCapability, 0, len(r.transactionTypes))
	for id, typeNumber := range r.transactionTypes {
		transactionTypes = append(transactionTypes, v1.EIP7702TransactionCapability{ID: id, Number: typeNumber})
	}
	sort.Slice(transactionTypes, func(i, j int) bool { return transactionTypes[i].ID < transactionTypes[j].ID })
	return schemas, protocols, accounts, signingSchemas, authorizationSchemas, transactionTypes
}

func accountCapabilityKey(id, version, signatureEncoding string) string {
	return id + "\x00" + version + "\x00" + signatureEncoding
}

func appendUnique(values []string, candidate string) []string {
	for _, value := range values {
		if value == candidate {
			return values
		}
	}
	return append(values, candidate)
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
