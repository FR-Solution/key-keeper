package vault

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

func (s *vault) checkSecret(i config.Secret) {
	logger := zap.L().With(zap.String("resource_type", "secret"), zap.String("name", i.Name))

	secret, err := s.readSecret(i)
	if err != nil {
		logger.Warn("read", zap.Error(err))
	}

	if err = writeToFile(i.HostPath, secret); err != nil {
		zap.L().Error("store", zap.String("path", i.HostPath), zap.Error(err))
	}
}

func (s *vault) readSecret(i config.Secret) ([]byte, error) {
	storedSecrete, err := s.cli.Get(s.kv, i.Name)
	if err != nil {
		return nil, fmt.Errorf("get from vault_kv : %w", err)
	}

	if data, ok := storedSecrete[i.Key]; ok {
		return []byte(data.(string)), nil
	}
	return nil, fmt.Errorf("secrete not found : %w", err)
}
