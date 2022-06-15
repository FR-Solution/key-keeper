package controller

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
)

var intermediateCommonNameLayout = "%s Intermediate Authority"

type vault interface {
	Write(ctx context.Context, path string, data map[string]interface{}) (map[string]interface{}, error)
	Read(ctx context.Context, path string) (map[string]interface{}, error)
	List(ctx context.Context, path string) (map[string]interface{}, error)
	Put(ctx context.Context, mountPath, secretePath string, data map[string]interface{}) error
	Get(ctx context.Context, mountPath, secretePath string) (map[string]interface{}, error)
}

type controller struct {
	vault vault

	vaultTimeout time.Duration

	certs Certificates
}

func New(store vault, cfg Config) *controller {
	c := &controller{
		vault: store,

		vaultTimeout: cfg.Vault.Timeout,
		certs:        cfg.Certs,
	}
	return c
}

func (s *controller) TurnOn() error {
	defer func() {
		go s.runtime()
	}()

	cert, err := s.readCertificate(s.certs.Cert.HostPath)
	if cert != nil && time.Until(cert.Leaf.NotAfter) > s.certs.ValidInterval {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	//create intermediate CA with common name example.com
	icaCert, icaKey, err := s.GenerateIntermediateCA()
	if err != nil {
		return err
	}

	if err := s.storeCertificate(s.certs.CA.HostPath, icaCert, icaKey); err != nil {
		return err
	}

	certData, keyData, err := s.GenerateCert()
	if err != nil {
		return err
	}
	if err := s.storeCertificate(s.certs.Cert.HostPath, certData, keyData); err != nil {
		return err
	}
	return nil
}

func (s *controller) GenerateIntermediateCA() (crt []byte, key []byte, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.vaultTimeout)
	defer cancel()
	storedICA, err := s.vault.Get(ctx, s.certs.VaultKV, s.certs.CA.CommonName+"-ca")
	if err != nil {
		zap.L().Error(
			"getting",
			zap.Any("certificate", "intermediate-ca"),
			zap.String("mount_path", s.certs.VaultKV),
			zap.String("secrete_path", s.certs.CA.CommonName+"-ca"),
			zap.Error(err),
		)
	}
	if storedICA != nil {
		crt, key = []byte(storedICA["certificate"].(string)), []byte(storedICA["private_key"].(string))
		var cert *tls.Certificate
		cert, err = parseToCert(crt, key)
		if cert != nil && time.Until(cert.Leaf.NotAfter) < s.certs.ValidInterval {
			err = fmt.Errorf("the certificate expires after %f h.", time.Until(cert.Leaf.NotAfter).Hours())
		}
		if err != nil {
			zap.L().Error(
				"analize",
				zap.Any("certificate", "intermediate-ca"),
				zap.Error(err),
			)
		}
		if err == nil {
			return
		}
	}

	// create intermediate CA
	ctx, cancel = context.WithTimeout(context.Background(), s.vaultTimeout)
	defer cancel()

	csrData := map[string]interface{}{
		"common_name": fmt.Sprintf(intermediateCommonNameLayout, s.certs.CA.CommonName),
		"ttl":         "8760h",
	}

	csr, err := s.vault.Write(ctx, s.certs.CertPath+"/intermediate/generate/exported", csrData)
	if err != nil {
		err = fmt.Errorf("create intermediate CA: %w", err)
		return
	}

	// send the intermediate CA's CSR to the root CA for signing
	ctx, cancel = context.WithTimeout(context.Background(), s.vaultTimeout)
	defer cancel()

	icaData := map[string]interface{}{
		"csr":    csr["csr"],
		"format": "pem_bundle",
		"ttl":    "8760h",
	}

	ica, err := s.vault.Write(ctx, s.certs.RootPath+"/root/sign-intermediate", icaData)
	if err != nil {
		err = fmt.Errorf("send the intermediate CA's CSR to the root CA for signing CA: %w", err)
		return
	}

	// publish the signed certificate back to the Intermediate CA
	ctx, cancel = context.WithTimeout(context.Background(), s.vaultTimeout)
	defer cancel()

	certData := map[string]interface{}{
		"certificate": ica["certificate"],
	}

	if _, err = s.vault.Write(ctx, s.certs.CertPath+"/intermediate/set-signed", certData); err != nil {
		err = fmt.Errorf("publish the signed certificate back to the Intermediate CA: %w", err)
		return
	}

	// saving the created Intermediate CA
	storedICA = map[string]interface{}{
		"certificate": ica["certificate"],
		"private_key": csr["private_key"],
	}
	if err = s.vault.Put(ctx, s.certs.VaultKV, "intermediate-ca", storedICA); err != nil {
		err = fmt.Errorf("saving the created Intermediate CA: %w", err)
		return
	}
	return []byte(ica["certificate"].(string)), []byte(csr["private_key"].(string)), nil
}

func (s *controller) GenerateCert() ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.vaultTimeout)
	defer cancel()

	certData := map[string]interface{}{
		"common_name": s.certs.Cert.CommonName,
	}
	cert, err := s.vault.Write(ctx, s.certs.CertPath+"/issue/"+s.certs.Cert.Role, certData)
	if err != nil {
		return nil, nil, err
	}
	return []byte(cert["certificate"].(string)), []byte(cert["private_key"].(string)), nil
}

func (s *controller) runtime() {
	t := time.Tick(time.Hour)
	for {
		select {
		case <-t:
			cert, err := s.readCertificate(s.certs.Cert.HostPath)
			if cert == nil || time.Until(cert.Leaf.NotAfter) < s.certs.ValidInterval {
				certData, keyData, err := s.GenerateCert()
				if err != nil {
					zap.L().Error(
						"generate certificate",
						zap.Error(err),
					)
				}
				if err := s.storeCertificate(s.certs.Cert.HostPath, certData, keyData); err != nil {
					zap.L().Error(
						"store certificate",
						zap.String("path", s.certs.Cert.HostPath),
						zap.Error(err),
					)
				}
			}
			if err != nil {
				zap.L().Error("read certificate", zap.Error(err))
			}
		}
	}
}
