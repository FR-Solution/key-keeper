package resource

import (
	"crypto/x509"
	"encoding/pem"
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
		if err := s.storeKeyPair(cert.HostPath, crt, key); err != nil {
			zap.L().Error(
				"stored intermediate-ca",
				zap.Error(err),
			)
		}
	}()

	crt, key, err = s.readCA(cert.Vault.Path)
	if err == nil {
		var ca *x509.Certificate
		pBlock, _ := pem.Decode(crt)
		ca, err = x509.ParseCertificate(pBlock.Bytes)
		if err != nil {
			err = fmt.Errorf("parse : %w", err)
		}
		if ca != nil && time.Until(ca.NotAfter) < cert.RenewBefore {
			err = fmt.Errorf("expired until(h) %f", time.Until(ca.NotAfter).Hours())
		}
	}

	if err != nil {
		zap.L().Warn(
			"intermediate ca",
			zap.String("name", cert.Name),
			zap.Error(err),
		)
	} else {
		return
	}

	if cert.CA.Generate {
		crt, key, err = s.generateCA(cert)
		if err != nil {
			zap.L().Error(
				"generate intermediate-ca",
				zap.String("name", cert.Name),
				zap.Error(err),
			)
			return
		} else {
			zap.L().Info(
				"intermediate-ca generated",
				zap.String("name", cert.Name),
			)
		}
	}
}

func (s *resource) generateCA(cert config.Certificate) (crt, key []byte, err error) {
	// create  intermediate ca
	csrData := map[string]interface{}{
		"common_name": fmt.Sprintf("%s Intermediate Authority", cert.Name),
		"ttl":         cert.Spec.TTL,
	}

	keyType := "internal"
	if cert.CA.ExportedKey {
		keyType = "exported"
	}

	vaultPath := path.Join(cert.Vault.Path, "intermediate/generate", keyType)
	csr, err := s.vault.Write(vaultPath, csrData)
	if err != nil {
		err = fmt.Errorf("generate: %w", err)
		return
	}

	// send the  intermediate ca 's CSR to the root CA for signing
	icaData := map[string]interface{}{
		"csr":    csr["csr"],
		"format": "pem_bundle",
		"ttl":    cert.Spec.TTL,
	}

	vaultPath = path.Join(cert.Vault.RootCAPath, "root/sign-intermediate")
	ica, err := s.vault.Write(vaultPath, icaData)
	if err != nil {
		err = fmt.Errorf("send the intermediate ca CSR to the root CA for signing CA: %w", err)
		return
	}

	// publish the signed certificate back to the  intermediate ca
	certData := map[string]interface{}{
		"certificate": ica["certificate"],
	}

	vaultPath = path.Join(cert.Vault.Path, "intermediate/set-signed")
	if _, err = s.vault.Write(vaultPath, certData); err != nil {
		err = fmt.Errorf("publish the signed certificate back to the  intermediate ca : %w", err)
		return
	}

	if c, ok := ica["certificate"]; ok {
		crt = []byte(c.(string))
	}
	if k, ok := csr["private_key"]; ok {
		key = []byte(k.(string))
	}

	return
}
