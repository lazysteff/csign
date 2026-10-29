package v1

import enc "github.com/lazysteff/csign/v2/internal/encoding"

func strictUnmarshalJSON(data []byte, out any) error { return enc.StrictUnmarshalJSON(data, out) }
