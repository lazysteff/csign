package vaultbackend

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/chain-signer/chain-signer/internal/faults"
	"github.com/chain-signer/chain-signer/internal/routes"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func decode(input map[string]interface{}, out any) error {
	if len(input) == 0 {
		input = map[string]interface{}{}
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func response(payload any) *logical.Response {
	raw, err := json.Marshal(payload)
	if err != nil {
		return logical.ErrorResponse(err.Error())
	}
	out := make(map[string]interface{})
	if err := json.Unmarshal(raw, &out); err != nil {
		return logical.ErrorResponse(err.Error())
	}
	return &logical.Response{Data: out}
}

func fieldString(d *framework.FieldData, name string) string {
	value := d.Get(name)
	if value == nil {
		return ""
	}
	asString, _ := value.(string)
	return asString
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, logical.ErrUnsupportedPath) || errors.Is(err, logical.ErrUnsupportedOperation) {
		return err
	}
	message := err.Error()
	if code := faults.CodeOf(err); code != "" {
		message = "[" + string(code) + "] " + message
	}
	switch faults.KindOf(err) {
	case faults.Invalid, faults.PolicyDenied, faults.CustodyFailed, faults.Unsupported:
		return logical.CodedError(http.StatusBadRequest, message)
	case faults.NotFound:
		return logical.CodedError(http.StatusNotFound, message)
	case faults.Conflict:
		return logical.CodedError(http.StatusConflict, message)
	default:
		return logical.CodedError(http.StatusInternalServerError, "internal error")
	}
}

func structuredDecodeError(route string, err error) error {
	switch route {
	case routes.EVMEIP712Sign, routes.EVMEIP712Verify:
		return faults.NewCode(faults.Invalid, faults.InvalidEIP712Message, err.Error())
	case routes.EVMERC4337UserOperationSign, routes.EVMERC4337UserOperationVerify:
		return faults.NewCode(faults.Invalid, faults.InvalidUserOperation, err.Error())
	case routes.EVMEIP7702AuthorizationSign, routes.EVMEIP7702AuthorizationVerify:
		return faults.NewCode(faults.Invalid, faults.InvalidEIP7702Authorization, err.Error())
	case routes.EVMEIP7702TransactionSign, routes.EVMEIP7702TransactionRecover:
		return faults.NewCode(faults.Invalid, faults.InvalidAuthorizationList, err.Error())
	default:
		return faults.Wrap(faults.Invalid, err)
	}
}
