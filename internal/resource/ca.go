package resource

import (
	"crypto/tls"
	"fmt"
	"path"
	"time"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

func (s *resource) checkCA(cert config.Certificate) {
	var (
		crt, key []byte
		err      error
	)

	defer func() {
		if err := s.storeCertificate(cert.HostPath, crt, key); err != nil {
			zap.L().Error(
				"stored intermediate-ca",
				zap.Error(err),
			)
		}
	}()

	crt, key, err = s.readCA(cert.VaultPath)
	if err == nil {
		var ca *tls.Certificate
		ca, err = parseToCert(crt, key)
		if err != nil {
			err = fmt.Errorf("parse : %w", err)
		}
		if ca != nil && time.Until(ca.Leaf.NotAfter) < cert.RenewBefore {
			err = fmt.Errorf("expired until(h) %f", time.Until(ca.Leaf.NotAfter).Hours())
		}
	}

	if err != nil {
		zap.L().Warn(
			"intermediate ca",
			zap.String("common_name", cert.Spec.CommonName+"-ca"),
			zap.Error(err),
		)
	} else {
		return
	}

	crt, key, err = s.generateCA(cert)
	if err != nil {
		zap.L().Error(
			"generate intermediate-ca",
			zap.Error(err),
		)
	}

}

func (s *resource) generateCA(cert config.Certificate) (crt, key []byte, err error) {
	// create  intermediate ca with exported key
	csrData := map[string]interface{}{
		"common_name": fmt.Sprintf("%s Intermediate Authority", cert.Spec.CommonName),
		"ttl":         "8760h",
	}

	vaultPath := path.Join(cert.VaultPath, "intermediate/generate/exported")
	csr, err := s.vault.Write(vaultPath, csrData)
	if err != nil {
		err = fmt.Errorf("create: %w", err)
		return
	}

	// send the  intermediate ca with exported key's CSR to the root CA for signing
	icaData := map[string]interface{}{
		"csr":    csr["csr"],
		"format": "pem_bundle",
		"ttl":    "8760h",
	}

	vaultPath = path.Join(cert.VaultRootCAPath, "root/sign-intermediate")
	ica, err := s.vault.Write(vaultPath, icaData)
	if err != nil {
		err = fmt.Errorf("send the intermediate ca with exported key's CSR to the root CA for signing CA: %w", err)
		return
	}

	// publish the signed certificate back to the  intermediate ca with exported key
	certData := map[string]interface{}{
		"certificate": ica["certificate"],
	}

	vaultPath = path.Join(cert.VaultPath, "intermediate/set-signed")
	if _, err = s.vault.Write(vaultPath, certData); err != nil {
		err = fmt.Errorf("publish the signed certificate back to the  intermediate ca with exported key: %w", err)
		return
	}

	zap.L().Info("intermediate-ca generated", zap.String("common_name", cert.Spec.CommonName))
	return []byte(ica["certificate"].(string)), []byte(csr["private_key"].(string)), nil
}
