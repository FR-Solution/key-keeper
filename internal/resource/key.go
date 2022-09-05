package resource

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

func (s *resource) checkKey(i config.Key) {
	private, public, err := s.readKey(i)
	if err != nil {
		zap.L().Warn(
			"read rsa",
			zap.String("name", i.Name),
			zap.Error(err),
		)
	} else {
		zap.L().Debug("rsa is read", zap.String("name", i.Name))
	}

	if err := s.storeKey(i.HostPath, private, public); err != nil {
		zap.L().Error(
			"store rsa in host",
			zap.String("name", i.Name),
			zap.String("path", i.HostPath),
			zap.Error(err),
		)
		return
	}
	zap.L().Debug("rsa is stored", zap.String("name", i.Name))
}

func (s *resource) readKey(i config.Key) (private []byte, public []byte, err error) {
	storedRSA, err := s.vault.Get(i.Name)
	if err != nil {
		err = fmt.Errorf("get from vault_kv : %w", err)
		return
	}

	private, public = []byte(storedRSA["private"].(string)), []byte(storedRSA["public"].(string))
	return
}
