package v1

type TRONWithdrawBalanceSignRequest struct {
	TRONOwnerSignRequestBase
	TRONRawDataEnvelope
}

func (r *TRONWithdrawBalanceSignRequest) UnmarshalJSON(data []byte) error {
	type alias TRONWithdrawBalanceSignRequest
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = TRONWithdrawBalanceSignRequest(decoded)
	return nil
}
