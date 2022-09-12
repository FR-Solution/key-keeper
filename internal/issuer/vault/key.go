package vault

import (
	"fmt"
	"os"
	"path"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

func (s *vault) checkKeyPair(i config.Key) {
	private, public, err := s.readKey(i)
	if err != nil {
		zap.L().Warn(
			"read key",
			zap.String("name", i.Name),
			zap.Error(err),
		)
		return
	} else {
		zap.L().Debug("key is read", zap.String("name", i.Name))
	}

	if err := s.saveKeyOnHost(path.Join(i.HostPath, i.Name), private, public); err != nil {
		zap.L().Error(
			"save key in host",
			zap.String("name", i.Name),
			zap.String("path", i.HostPath),
			zap.Error(err),
		)
		return
	}
	zap.L().Debug("key is save in host", zap.String("name", i.Name))
}

func (s *vault) readKey(i config.Key) (private []byte, public []byte, err error) {
	storedKye, err := s.Get(s.kvMountPath,i.Name)
	if err != nil {
		err = fmt.Errorf("get from vault_kv : %w", err)
		return
	}

	if c, ok := storedKye["private"]; ok {
		private = []byte(c.(string))
	}
	if k, ok := storedKye["public"]; ok {
		public = []byte(k.(string))
	}

	return
}

func (s *vault) saveKeyOnHost(path string, private, public []byte) error {
	if err := os.WriteFile(path+".pem", private, 0600); err != nil {
		return fmt.Errorf("failed to save private key with path %s: %w", path, err)
	}

	if err := os.WriteFile(path+".pub", public, 0600); err != nil {
		return fmt.Errorf("failed to public key file: %w", err)
	}
	return nil
}
