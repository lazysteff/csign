package v1

import enc "github.com/chain-signer/chain-signer/internal/encoding"

func strictUnmarshalJSON(data []byte, out any) error { return enc.StrictUnmarshalJSON(data, out) }
