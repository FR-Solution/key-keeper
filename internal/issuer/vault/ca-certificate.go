package vault

import (
	"crypto/x509"
	"fmt"
	"path"
	"time"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

func (s *vault) checkCA(cert config.Certificate) {
	logger := zap.L().With(zap.String("resource_type", "intermediate_ca"), zap.String("name", cert.Name))

	var (
		crt, key []byte
		err      error
	)

	defer func() {
		if err := storeKeyPair(cert.HostPath, cert.Name, crt, key); err != nil {
			logger.Error("store", zap.Error(err))
		}
		logger.Debug("store")
	}()

	crt, key, err = s.readCA(s.caPath)
	if err == nil {
		var ca *x509.Certificate
		ca, err = parseCertificate(crt)
		if err == nil {
			logger.Debug("ttl", zap.Float64("remaining time(h)", time.Until(ca.NotAfter).Hours()))
			if time.Until(ca.NotAfter) < cert.UpdateBefore {
				err = fmt.Errorf("expired until(h) %f", time.Until(ca.NotAfter).Hours())
			}
		}
	}

	if err == nil {
		return
	}
	logger.Warn("check", zap.Error(err))

	if cert.CA.Generate {
		crt, key, err = s.generateCA(cert)
		if err != nil {
			logger.Error("generate", zap.Error(err))
			return
		}
		zap.L().Info("generated")
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

	if data, ok := ica["certificate"]; ok {
		crt = []byte(data.(string))
	}
	if data, ok := csr["private_key"]; ok {
		key = []byte(data.(string))
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
