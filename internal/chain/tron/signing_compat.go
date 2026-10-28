package tron

import (
	"context"

	"github.com/chain-signer/chain-signer/internal/custody"
	v1 "github.com/chain-signer/chain-signer/pkg/api/v1"
)

// Direct helpers preserve existing package integrations; Vault requests use
// operation preparation and the generalized signing service.
func SignTRC20Transfer(ctx context.Context, material custody.Material, req *v1.TRC20TransferSignRequest) (*v1.SignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareTRC20Transfer(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.SignResponse), nil
}
func SignTRONDelegateResource(ctx context.Context, material custody.Material, req *v1.TRONDelegateResourceSignRequest) (*v1.SignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareTRONDelegateResource(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.SignResponse), nil
}
func SignTRONFreezeBalanceV2(ctx context.Context, material custody.Material, req *v1.TRONFreezeBalanceV2SignRequest) (*v1.SignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareTRONFreezeBalanceV2(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.SignResponse), nil
}
func SignTRONUndelegateResource(ctx context.Context, material custody.Material, req *v1.TRONUndelegateResourceSignRequest) (*v1.SignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareTRONUndelegateResource(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.SignResponse), nil
}
func SignTRONUnfreezeBalanceV2(ctx context.Context, material custody.Material, req *v1.TRONUnfreezeBalanceV2SignRequest) (*v1.SignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareTRONUnfreezeBalanceV2(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.SignResponse), nil
}
func SignTRONVoteWitness(ctx context.Context, material custody.Material, req *v1.TRONVoteWitnessSignRequest) (*v1.SignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareTRONVoteWitness(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.SignResponse), nil
}
func SignTRONWithdrawBalance(ctx context.Context, material custody.Material, req *v1.TRONWithdrawBalanceSignRequest) (*v1.SignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareTRONWithdrawBalance(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.SignResponse), nil
}
func SignTRONWithdrawExpireUnfreeze(ctx context.Context, material custody.Material, req *v1.TRONWithdrawExpireUnfreezeSignRequest) (*v1.SignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareTRONWithdrawExpireUnfreeze(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.SignResponse), nil
}
func SignTRXTransfer(ctx context.Context, material custody.Material, req *v1.TRXTransferSignRequest) (*v1.SignResponse, error) {
	pub, err := custody.PublicKeyOf(material)
	if err != nil {
		return nil, err
	}
	prepared, err := PrepareTRXTransfer(pub, req)
	if err != nil {
		return nil, err
	}
	result, err := custody.ExecutePreparedECDSA(ctx, material, prepared)
	if err != nil {
		return nil, err
	}
	return result.(*v1.SignResponse), nil
}
