package service

import (
	"errors"
	"reflect"

	"github.com/chain-signer/chain-signer/internal/faults"
)

type keyIDCarrier interface {
	GetKeyID() string
}

func newOperationRequest(descriptor OperationDescriptor) (request any, err error) {
	if descriptor.NewRequest == nil {
		return nil, errors.New("request factory is required")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			request = nil
			err = errors.New("request factory panicked")
		}
	}()
	request = descriptor.NewRequest()
	if request == nil || isNilValue(request) {
		return nil, errors.New("request factory returned nil")
	}
	if _, ok := request.(keyIDCarrier); !ok {
		return nil, errors.New("request type does not expose key_id")
	}
	return request, nil
}

func keyIDFromRequest(request any) (string, error) {
	if request == nil || isNilValue(request) {
		return "", faults.New(faults.Internal, "request is required")
	}
	typed, ok := request.(keyIDCarrier)
	if !ok {
		return "", faults.New(faults.Internal, "request does not contain key_id")
	}
	return typed.GetKeyID(), nil
}

func isNilValue(value any) bool {
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
