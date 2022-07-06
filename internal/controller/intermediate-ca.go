package controller

import (
	"fmt"
	"path"

	"go.uber.org/zap"
)

func (s *controller) intermediateCA(i IntermediateCA) {
	var (
		crt []byte
		err error
	)

	defer func() {
		if err := s.storeIntermediateCA(i, crt, nil); err != nil {
			zap.L().Error(
				"stored intermediate-ca",
				zap.Error(err),
			)
		}
	}()

	crt, err = s.readIntermediateCA(i)
	if err != nil {
		zap.L().Error(
			"read intermediate ca",
			zap.String("common_name", i.CommonName+"-ca"),
			zap.Error(err),
		)
	} else {
		return
	}

	if i.Generate {
		crt, err = s.generateIntermediateCA(i)
		if err != nil {
			zap.L().Error(
				"generate intermediate-ca",
				zap.Error(err),
			)
		}
	}
}

func (s *controller) readIntermediateCA(i IntermediateCA) (crt []byte, err error) {
	path := path.Join(i.CertPath, "cert/ca_chain")
	ica, err := s.vault.Read(path)
	if ica != nil {
		return []byte(ica["certificate"].(string)), err
	}
	return
}

func (s *controller) generateIntermediateCA(i IntermediateCA) (crt []byte, err error) {
	// create intermediate CA
	csrData := map[string]interface{}{
		"common_name": fmt.Sprintf(intermediateCommonNameLayout, i.CommonName),
		"ttl":         "8760h",
	}

	path := path.Join(i.CertPath, "intermediate/generate/internal")
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

	path = i.RootPathCA + "/root/sign-intermediate"
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
	return []byte(ica["certificate"].(string)), nil
}

func (s *controller) storeIntermediateCA(i IntermediateCA, crt, key []byte) error {
	if err := s.storeCertificate(i.HostPath, crt, key); err != nil {
		return fmt.Errorf("host path %s : %w", i.HostPath, err)
	}
	return nil
}
