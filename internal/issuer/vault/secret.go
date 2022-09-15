package vault

import (
	"fmt"
	"os"
	"path"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

func (s *vault) checkSecret(i config.Secret) {
	secret, err := s.readSecret(i)
	if err != nil {
		zap.L().Warn(
			"read secret",
			zap.String("name", i.Name),
			zap.Error(err),
		)
	} else {
		zap.L().Debug("secret is read", zap.String("name", i.Name))
	}

	if err := s.storeSecret(path.Join(i.HostPath, i.Name), secret); err != nil {
		zap.L().Error(
			"store secrete in host",
			zap.String("name", i.Name),
			zap.String("path", i.HostPath),
			zap.Error(err),
		)
		return
	}
	zap.L().Debug("secret is stored", zap.String("name", i.Name))
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

func (s *vault) storeSecret(path string, secret []byte) error {
	if err := os.WriteFile(path, secret, 0600); err != nil {
		return fmt.Errorf("failed to save secrete with path %s: %w", path, err)
	}
	return nil
}
