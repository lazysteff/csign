package advancedcodec

import "errors"

var ErrUserOperationHashMismatch = errors.New("expected_user_operation_hash does not match reconstructed hash")
