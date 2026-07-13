// Package erc4337 implements the exact UserOperation hashing and SimpleAccount
// signature contract of eth-infinitism/account-abstraction v0.9.0.
//
// The implementation is pinned to tag v0.9.0, commit
// b36a1ed52ae00da6f8a4c8d50181e2877e4fa410, specifically:
//
//   - contracts/core/UserOperationLib.sol
//   - contracts/core/Helpers.sol (paymasterDataKeccak)
//   - contracts/core/Eip7702Support.sol
//   - contracts/core/EntryPoint.sol (ERC4337/version 1 EIP-712 domain)
//   - contracts/accounts/SimpleAccount.sol
//
// It intentionally has no generic arbitrary-message or raw-hash signing API.
package erc4337
