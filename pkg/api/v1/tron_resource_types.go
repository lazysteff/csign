package v1

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

const (
	TRONResourceBandwidth = "BANDWIDTH"
	TRONResourceEnergy    = "ENERGY"
	TRONResourceTRONPower = "TRON_POWER"
)

func NormalizeTRONResource(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

type TRONOwnerSignRequestBase struct {
	KeyID        string            `json:"key_id"`
	ChainFamily  string            `json:"chain_family"`
	Network      string            `json:"network"`
	RequestID    string            `json:"request_id"`
	Labels       map[string]string `json:"labels,omitempty"`
	ApprovalRef  string            `json:"approval_ref,omitempty"`
	OwnerAddress string            `json:"owner_address"`
}

func (r TRONOwnerSignRequestBase) GetKeyID() string {
	return r.KeyID
}

type TRONRawDataEnvelope struct {
	RefBlockBytes string `json:"ref_block_bytes"`
	RefBlockHash  string `json:"ref_block_hash"`
	Timestamp     int64  `json:"timestamp"`
	Expiration    int64  `json:"expiration"`
	FeeLimit      *int64 `json:"fee_limit,omitempty"`
}

func (e TRONRawDataEnvelope) FeeLimitOrZero() int64 {
	if e.FeeLimit == nil {
		return 0
	}
	return *e.FeeLimit
}

type TRONFreezeBalanceV2SignRequest struct {
	TRONOwnerSignRequestBase
	TRONRawDataEnvelope
	Resource string `json:"resource"`
	Amount   int64  `json:"amount"`
}

func (r *TRONFreezeBalanceV2SignRequest) UnmarshalJSON(data []byte) error {
	type alias TRONFreezeBalanceV2SignRequest
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = TRONFreezeBalanceV2SignRequest(decoded)
	return nil
}

type TRONUnfreezeBalanceV2SignRequest struct {
	TRONOwnerSignRequestBase
	TRONRawDataEnvelope
	Resource string `json:"resource"`
	Amount   int64  `json:"amount"`
}

func (r *TRONUnfreezeBalanceV2SignRequest) UnmarshalJSON(data []byte) error {
	type alias TRONUnfreezeBalanceV2SignRequest
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = TRONUnfreezeBalanceV2SignRequest(decoded)
	return nil
}

type TRONDelegateResourceSignRequest struct {
	TRONOwnerSignRequestBase
	TRONRawDataEnvelope
	ReceiverAddress string `json:"receiver_address"`
	Resource        string `json:"resource"`
	Amount          int64  `json:"amount"`
	Lock            bool   `json:"lock,omitempty"`
	LockPeriod      int64  `json:"lock_period,omitempty"`
}

func (r *TRONDelegateResourceSignRequest) UnmarshalJSON(data []byte) error {
	type alias TRONDelegateResourceSignRequest
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = TRONDelegateResourceSignRequest(decoded)
	return nil
}

type TRONUndelegateResourceSignRequest struct {
	TRONOwnerSignRequestBase
	TRONRawDataEnvelope
	ReceiverAddress string `json:"receiver_address"`
	Resource        string `json:"resource"`
	Amount          int64  `json:"amount"`
}

func (r *TRONUndelegateResourceSignRequest) UnmarshalJSON(data []byte) error {
	type alias TRONUndelegateResourceSignRequest
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = TRONUndelegateResourceSignRequest(decoded)
	return nil
}

type TRONWithdrawExpireUnfreezeSignRequest struct {
	TRONOwnerSignRequestBase
	TRONRawDataEnvelope
}

func (r *TRONWithdrawExpireUnfreezeSignRequest) UnmarshalJSON(data []byte) error {
	type alias TRONWithdrawExpireUnfreezeSignRequest
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = TRONWithdrawExpireUnfreezeSignRequest(decoded)
	return nil
}

func strictUnmarshalJSON(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(new(struct{})); err != io.EOF {
		return err
	}
	return nil
}
