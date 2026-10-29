package evm

import (
	"context"

	"github.com/lazysteff/csign/v2/internal/custody"
	v1 "github.com/lazysteff/csign/v2/pkg/api/v1"
)

// Direct helpers preserve existing package integrations; Vault requests use
// operation preparation and the generalized signing service.
func SignContractCall(ctx context.Context, material custody.Material, req *v1.EVMContractCallSignRequest) (*v1.SignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareContractCall(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.SignResponse), nil
}
func SignEIP1559Transfer(ctx context.Context, material custody.Material, req *v1.EVMEIP1559TransferSignRequest) (*v1.SignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareEIP1559Transfer(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.SignResponse), nil
}
func SignEIP712(ctx context.Context, material custody.Material, req *v1.EVMEIP712SignRequest) (*v1.EVMEIP712SignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareEIP712(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.EVMEIP712SignResponse), nil
}
func SignEIP7702Authorization(ctx context.Context, material custody.Material, req *v1.EVMEIP7702AuthorizationSignRequest) (*v1.EVMEIP7702AuthorizationSignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareEIP7702Authorization(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.EVMEIP7702AuthorizationSignResponse), nil
}
func SignEIP7702Transaction(ctx context.Context, material custody.Material, req *v1.EVMEIP7702TransactionSignRequest) (*v1.EVMEIP7702TransactionSignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareEIP7702Transaction(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.EVMEIP7702TransactionSignResponse), nil
}
func SignLegacyTransfer(ctx context.Context, material custody.Material, req *v1.EVMLegacyTransferSignRequest) (*v1.SignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareLegacyTransfer(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.SignResponse), nil
}
func SignUserOperation(ctx context.Context, material custody.Material, req *v1.EVMUserOperationSignRequest) (*v1.EVMUserOperationSignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareUserOperation(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.EVMUserOperationSignResponse), nil
}
