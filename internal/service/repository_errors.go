package service

import (
	"errors"

	"github.com/chain-signer/chain-signer/internal/repository"
)

func isRepositoryKeyNotFound(err error) bool {
	return errors.Is(err, repository.ErrKeyNotFound)
}
