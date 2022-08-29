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

func (s *resource) checkCSR(i config.Certificate) {
	csr, err := s.readCertificate(i.HostPath)
	if csr != nil && time.Until(csr.Leaf.NotAfter) > i.RenewBefore {
		return
	}
	if err != nil && !os.IsNotExist(err) {
		zap.L().Error("read csr", zap.String("path", i.HostPath), zap.Error(err))
	}

	cert, key, err := s.generateCSR(i)
	if err != nil {
		zap.L().Error(
			"generate csr",
			zap.String("common_name", i.Spec.CommonName),
			zap.Error(err),
		)
	}

	if err = s.storeCertificate(i.HostPath, cert, key); err != nil {
		zap.L().Error(
			"store csr",
			zap.String("common_name", i.Spec.CommonName),
			zap.Error(err),
		)
		return
	}

	for _, command := range i.Trigger {
		cmd := strings.Split(command, " ")
		err := exec.Command(cmd[0], cmd[1:]...).Run()
		zap.L().Error(
			"csr trigger",
			zap.String("common_name", i.Spec.CommonName),
			zap.String("command", command),
			zap.Error(err),
		)
	}
	zap.L().Info("csr generated", zap.String("common_name", i.Spec.CommonName))
}

func (s *resource) generateCSR(i config.Certificate) ([]byte, []byte, error) {
	certData := map[string]interface{}{
		"common_name": i.Spec.CommonName,
		"alt_names":   strings.Join(i.Spec.Hostnames, ","),
		"ip_sans":     strings.Join(i.Spec.IPAddresses, ","),
	}
	path := path.Join(i.VaultPath, "issue", i.VaultRole)
	cert, err := s.vault.Write(path, certData)
	if err != nil {
		return nil, nil, fmt.Errorf("generate with path %s : %w", path, err)
	}

	return []byte(cert["certificate"].(string)), []byte(cert["private_key"].(string)), nil
}
