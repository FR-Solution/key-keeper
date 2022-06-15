package controller

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
)

func (s *controller) CSR() error {
	csr, err := s.readCertificate(s.cfg.Certs.CSR.HostPath)
	if csr != nil && time.Until(csr.Leaf.NotAfter) > s.cfg.Certs.ValidInterval {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		zap.L().Error("read csr", zap.String("path", s.cfg.Certs.CSR.HostPath), zap.Error(err))
		return err
	}

	cert, key, err := s.GenerateCSR()
	if err != nil {
		zap.L().Error("generate csr", zap.Error(err))
		return err
	}

	err = s.StoreCSR(cert, key)
	if err != nil {
		zap.L().Error("store csr", zap.Error(err))
		return err
	}

	return err
}

func (s *controller) GenerateCSR() ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Vault.Timeout)
	defer cancel()

	certData := map[string]interface{}{
		"common_name": s.cfg.Certs.CSR.CommonName,
	}
	path := s.cfg.Certs.CertPath + "/issue/" + s.cfg.Certs.CSR.Role
	cert, err := s.vault.Write(ctx, path, certData)
	if err != nil {
		return nil, nil, fmt.Errorf("generate with path %s : %w", path, err)
	}
	return []byte(cert["certificate"].(string)), []byte(cert["private_key"].(string)), nil
}

func (s *controller) StoreCSR(cert, key []byte) error {
	if err := s.storeCertificate(s.cfg.Certs.CSR.HostPath, cert, key); err != nil {
		return fmt.Errorf("host path %s : %w", s.cfg.Certs.CSR.HostPath, err)
	}
	return nil
}
