package controller

import (
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"go.uber.org/zap"
)

func (s *controller) csr(i CSR) {
	csr, err := s.readCertificate(i.HostPath)
	if csr != nil && time.Until(csr.Leaf.NotAfter) > s.cfg.Certificates.ReissueInterval {
		return
	}
	if err != nil && !os.IsNotExist(err) {
		zap.L().Error("read csr", zap.String("path", i.HostPath), zap.Error(err))
	}

	cert, key, err := s.generateCSR(i)
	if err != nil {
		zap.L().Error(
			"generate csr",
			zap.String("common_name", i.CommonName),
			zap.Error(err),
		)
	}

	if err = s.storeCSR(i, cert, key); err != nil {
		zap.L().Error(
			"store csr",
			zap.String("common_name", i.CommonName),
			zap.Error(err),
		)
		return
	}
	zap.L().Info("csr generated", zap.String("common_name", i.CommonName))
}

func (s *controller) generateCSR(i CSR) ([]byte, []byte, error) {
	certData := map[string]interface{}{
		"common_name": i.CommonName,
		"alt_names":   strings.Join(i.Hosts, ","),
		"ip_sans":     strings.Join(i.IPs, ","),
	}
	path := path.Join(i.CertPath, "issue", i.Role)
	cert, err := s.vault.Write(path, certData)
	if err != nil {
		return nil, nil, fmt.Errorf("generate with path %s : %w", path, err)
	}

	return []byte(cert["certificate"].(string)), []byte(cert["private_key"].(string)), nil
}

func (s *controller) storeCSR(i CSR, cert, key []byte) error {
	if err := s.storeCertificate(i.HostPath, cert, key); err != nil {
		return fmt.Errorf("host path %s : %w", i.HostPath, err)
	}
	return nil
}
