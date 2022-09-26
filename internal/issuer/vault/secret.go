package vault

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

func (s *vault) checkSecret(i config.Secret) {
	secret, err := s.readSecret(i)
	if err != nil {
		zap.L().Warn(
			"read",
			zap.String("secret_name", i.Name),
			zap.Error(err),
		)
	}

	if err := writeToFile(i.HostPath, secret); err != nil {
		zap.L().Error(
			"store in host",
			zap.String("secret_name", i.Name),
			zap.String("path", i.HostPath),
			zap.Error(err),
		)
		return
	}
	zap.L().Debug("secret is stored", zap.String("secret_name", i.Name))
}

func (s *vault) readSecret(i config.Secret) (secrete []byte, err error) {
	storedSecrete, err := s.Get(s.kvMountPath, i.Name)
	if err != nil {
		err = fmt.Errorf("get from vault_kv : %w", err)
		return
	}

	if data, ok := storedSecrete[i.Key]; ok {
		secrete = []byte(data.(string))
	}
	return
}
