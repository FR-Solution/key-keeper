package resource

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

func (s *resource) checkCertificate(cfg config.Certificate) {
	cert, err := s.readCertificate(cfg.HostPath, cfg.Name)
	if cert != nil && time.Until(cert.NotAfter) > cfg.RenewBefore {
		return
	}
	if err != nil && !os.IsNotExist(err) {
		zap.L().Error("read csr", zap.String("path", cfg.HostPath), zap.Error(err))
	}

	crt, key, err := s.generateCertificate(cfg)
	if err != nil {
		zap.L().Error(
			"generate csr",
			zap.String("name", cfg.Name),
			zap.Error(err),
		)
	}

	if err = s.storeKeyPair(cfg.HostPath, cfg.Name, crt, key); err != nil {
		zap.L().Error(
			"store csr",
			zap.String("name", cfg.Name),
			zap.Error(err),
		)
		return
	}

	for _, command := range cfg.Trigger {
		cmd := strings.Split(command, " ")
		err := exec.Command(cmd[0], cmd[1:]...).Run()
		zap.L().Error(
			"csr trigger",
			zap.String("name", cfg.Name),
			zap.String("command", command),
			zap.Error(err),
		)
	}
	zap.L().Info("csr generated", zap.String("name", cfg.Name))
}

func (s *resource) generateCertificate(cfg config.Certificate) ([]byte, []byte, error) {
	csr, key := createCSR(cfg.Spec)

	certData := map[string]interface{}{
		"csr": string(csr),
		"ttl": cfg.Spec.TTL,
	}

	path := path.Join(cfg.Vault.Path, "sign", cfg.Vault.Role)
	cert, err := s.vault.Write(path, certData)
	if err != nil {
		return nil, nil, fmt.Errorf("generate with path %s : %w", path, err)
	}

	return []byte(cert["certificate"].(string)), key, nil
}
