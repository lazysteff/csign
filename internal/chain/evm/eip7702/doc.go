// Package eip7702 implements the version-1 EIP-7702 authorization and
// set-code transaction signing rules used by CSign.
//
// The package accepts structured protocol fields, constructs all signing
// hashes internally, and delegates only the final 32-byte digest to a
// custody.Material. It deliberately does not allocate nonces, inspect chain
// state, or broadcast transactions.
package eip7702
