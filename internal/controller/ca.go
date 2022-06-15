package controller

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"go.uber.org/zap"
)

func (s *controller) CA(i CA) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Vault.Timeout)
	defer cancel()
	storedICA, err := s.vault.Get(ctx, s.cfg.Certs.VaultKV, i.CommonName+"-ca")
	if err != nil {
		zap.L().Warn(
			"get intermediate ca",
			zap.String("name", i.CommonName+"-ca"),
			zap.String("vault_kv", s.cfg.Certs.VaultKV),
			zap.Error(err),
		)
		return err
	}
	if storedICA != nil {
		cert, key := []byte(storedICA["certificate"].(string)), []byte(storedICA["private_key"].(string))
		var ca *tls.Certificate
		ca, err = parseToCert(cert, key)
		if ca != nil && time.Until(ca.Leaf.NotAfter) < s.cfg.Certs.ValidInterval {
			zap.L().Warn(
				"expired intermediate-ca",
				zap.Float64("until_h", time.Until(ca.Leaf.NotAfter).Hours()),
				zap.Error(err),
			)
		}
		if err != nil {
			zap.L().Error(
				"analize",
				zap.Any("certificate", "intermediate-ca"),
				zap.Error(err),
			)
		}
		if err == nil {
			return nil
		}
	}

	cert, key, err := s.GenerateIntermediateCA(i)
	if err != nil {
		zap.L().Error(
			"generate intermediate-ca",
			zap.Error(err),
		)
		return err
	}

	if err = s.StoreCA(i, cert, key); err != nil {
		zap.L().Error(
			"stored intermediate-ca",
			zap.Error(err),
		)
		return err
	}

	return nil
}
func (s *controller) GenerateIntermediateCA(i CA) (crt, key []byte, err error) {
	// create intermediate CA
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Vault.Timeout)
	defer cancel()

	csrData := map[string]interface{}{
		"common_name": fmt.Sprintf(intermediateCommonNameLayout, i.CommonName),
		"ttl":         "8760h",
	}

	csr, err := s.vault.Write(ctx, s.cfg.Certs.CertPath+"/intermediate/generate/exported", csrData)
	if err != nil {
		err = fmt.Errorf("create intermediate CA: %w", err)
		return
	}

	// send the intermediate CA's CSR to the root CA for signing
	ctx, cancel = context.WithTimeout(context.Background(), s.cfg.Vault.Timeout)
	defer cancel()

	icaData := map[string]interface{}{
		"csr":    csr["csr"],
		"format": "pem_bundle",
		"ttl":    "8760h",
	}

	ica, err := s.vault.Write(ctx, s.cfg.Certs.RootPath+"/root/sign-intermediate", icaData)
	if err != nil {
		err = fmt.Errorf("send the intermediate CA's CSR to the root CA for signing CA: %w", err)
		return
	}

	// publish the signed certificate back to the Intermediate CA
	ctx, cancel = context.WithTimeout(context.Background(), s.cfg.Vault.Timeout)
	defer cancel()

	certData := map[string]interface{}{
		"certificate": ica["certificate"],
	}

	if _, err = s.vault.Write(ctx, s.cfg.Certs.CertPath+"/intermediate/set-signed", certData); err != nil {
		err = fmt.Errorf("publish the signed certificate back to the Intermediate CA: %w", err)
		return
	}

	return []byte(ica["certificate"].(string)), []byte(csr["private_key"].(string)), nil
}

func (s *controller) StoreCA(i CA, crt, key []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Vault.Timeout)
	defer cancel()
	// saving the created Intermediate CA
	storedICA := map[string]interface{}{
		"certificate": string(crt),
		"private_key": string(key),
	}
	if err := s.vault.Put(ctx, s.cfg.Certs.VaultKV, i.CommonName+"-ca", storedICA); err != nil {
		return fmt.Errorf("saving in vault: %w", err)
	}

	if err := s.storeCertificate(i.HostPath, crt, key); err != nil {
		return fmt.Errorf("host path %s : %w", i.HostPath, err)
	}
	return nil
}
