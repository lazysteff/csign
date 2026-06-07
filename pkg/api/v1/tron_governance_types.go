package v1

type TRONVoteWitnessVote struct {
	VoteAddress string `json:"vote_address"`
	VoteCount   int64  `json:"vote_count"`
}

type TRONVoteWitnessSignRequest struct {
	TRONOwnerSignRequestBase
	TRONRawDataEnvelope
	Votes []TRONVoteWitnessVote `json:"votes"`
}

func (r *TRONVoteWitnessSignRequest) UnmarshalJSON(data []byte) error {
	type alias TRONVoteWitnessSignRequest
	var decoded alias
	if err := strictUnmarshalJSON(data, &decoded); err != nil {
		return err
	}
	*r = TRONVoteWitnessSignRequest(decoded)
	return nil
}
