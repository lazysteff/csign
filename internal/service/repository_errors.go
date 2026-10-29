package service

import (
	"errors"

	"github.com/lazysteff/csign/v2/internal/repository"
)

func isRepositoryKeyNotFound(err error) bool {
	return errors.Is(err, repository.ErrKeyNotFound)
}
