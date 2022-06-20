package controller

import (
	"crypto/tls"
	"fmt"
	"time"

	"go.uber.org/zap"
)

func (s *controller) intermediateCA(i IntermediateCA) {
	var (
		crt, key []byte
		err      error
	)

	defer func() {
		if err := s.storeIntermediateCA(i, crt, key); err != nil {
			zap.L().Error(
				"stored intermediate-ca",
				zap.Error(err),
			)
		}
	}()

	crt, key, err = s.readIntermediateCA(i)
	if err != nil {
		zap.L().Error(
			"read intermediate ca",
			zap.String("common_name", i.CommonName+"-ca"),
			zap.Error(err),
		)
	} else {
		return
	}

	crt, key, err = s.generateIntermediateCA(i)
	if err != nil {
		zap.L().Error(
			"generate intermediate-ca",
			zap.Error(err),
		)
	}
}

func (s *controller) readIntermediateCA(i IntermediateCA) (crt, key []byte, err error) {
	storedICA, err := s.vault.Get(s.certs.VaultKV, i.CommonName+"-ca")
	if err != err {
		err = fmt.Errorf("get from vault_kv %s : %w", s.certs.VaultKV, err)
		return
	}

	crt, key = []byte(storedICA["certificate"].(string)), []byte(storedICA["private_key"].(string))

	var ca *tls.Certificate
	ca, err = parseToCert(crt, key)
	if err != nil {
		err = fmt.Errorf("parse : %w", err)
	}
	if ca != nil && time.Until(ca.Leaf.NotAfter) < s.certs.ReissueInterval {
		err = fmt.Errorf("expired until(h) %f", time.Until(ca.Leaf.NotAfter).Hours())
	}
	return
}

func (s *controller) generateIntermediateCA(i IntermediateCA) (crt, key []byte, err error) {
	// create intermediate CA
	csrData := map[string]interface{}{
		"common_name": fmt.Sprintf(intermediateCommonNameLayout, i.CommonName),
		"ttl":         "8760h",
	}

	path := i.CertPath + "/intermediate/generate/exported"
	csr, err := s.vault.Write(path, csrData)
	if err != nil {
		err = fmt.Errorf("create intermediate CA: %w", err)
		return
	}

	// send the intermediate CA's CSR to the root CA for signing
	icaData := map[string]interface{}{
		"csr":    csr["csr"],
		"format": "pem_bundle",
		"ttl":    "8760h",
	}

	path = i.RootPathCA + "/sign-intermediate"
	ica, err := s.vault.Write(path, icaData)
	if err != nil {
		err = fmt.Errorf("send the intermediate CA's CSR to the root CA for signing CA: %w", err)
		return
	}

	// publish the signed certificate back to the Intermediate CA
	certData := map[string]interface{}{
		"certificate": ica["certificate"],
	}

	path = i.CertPath + "/intermediate/set-signed"
	if _, err = s.vault.Write(path, certData); err != nil {
		err = fmt.Errorf("publish the signed certificate back to the Intermediate CA: %w", err)
		return
	}

	zap.L().Info("intermediate-ca generated", zap.String("common_name", i.CommonName))
	return []byte(ica["certificate"].(string)), []byte(csr["private_key"].(string)), nil
}

func (s *controller) storeIntermediateCA(i IntermediateCA, crt, key []byte) error {
	// saving the created Intermediate CA
	storedICA := map[string]interface{}{
		"certificate": string(crt),
		"private_key": string(key),
	}
	if err := s.vault.Put(s.certs.VaultKV, i.CommonName+"-ca", storedICA); err != nil {
		return fmt.Errorf("saving in vault: %w", err)
	}

	if err := s.storeCertificate(i.HostPath, crt, key); err != nil {
		return fmt.Errorf("host path %s : %w", i.HostPath, err)
	}
	return nil
}
