package vault

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"reflect"
	"time"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

func (s *vault) checkCA(cert config.Certificate) {
	var (
		crt, key []byte
		err      error
	)

	defer func() {
		if isInfoChanged(cert.HostPath, cert.Name, crt, key) {
			if err := storeKeyPair(cert.HostPath, cert.Name, crt, key); err != nil {
				zap.L().Error(
					"stored intermediate-ca",
					zap.Error(err),
				)
			}
		}
	}()

	crt, key, err = s.readCA(s.caPath)
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

func (s *vault) generateCA(cert config.Certificate) (crt, key []byte, err error) {
	csrData := map[string]interface{}{
		"common_name": fmt.Sprintf("%s Intermediate Authority", cert.Name),
		"ttl":         cert.Spec.TTL,
	}

	keyType := "internal"
	if cert.CA.ExportedKey {
		keyType = "exported"
	}

	vaultPath := path.Join(s.caPath, "intermediate/generate", keyType)
	csr, err := s.Write(vaultPath, csrData)
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

	vaultPath = path.Join(s.rootCAPath, "root/sign-intermediate")
	ica, err := s.Write(vaultPath, icaData)
	if err != nil {
		err = fmt.Errorf("send the intermediate ca CSR to the root CA for signing CA: %w", err)
		return
	}

	certData := map[string]interface{}{
		"certificate": ica["certificate"],
	}

	vaultPath = path.Join(s.caPath, "intermediate/set-signed")
	if _, err = s.Write(vaultPath, certData); err != nil {
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

func (s *vault) readCA(vaultPath string) (crt, key []byte, err error) {
	vaultPath = path.Join(vaultPath, "cert/ca_chain")
	ica, err := s.Read(vaultPath)
	if ica != nil {
		if c, ok := ica["certificate"]; ok {
			crt = []byte(c.(string))
		}
		if k, ok := ica["private_key"]; ok {
			key = []byte(k.(string))
		}
	}
	return
}

func isInfoChanged(storePath string, name string, crt, key []byte) bool {
	if crt != nil {
		if data, err := os.ReadFile(path.Join(storePath, name+".pem")); err != nil || reflect.DeepEqual(crt, data) {
			return true
		}
	}

	if key != nil {
		if data, err := os.ReadFile(path.Join(storePath, name+"-key.pem")); err != nil || reflect.DeepEqual(key, data) {
			return true
		}
	}
	return false
}
