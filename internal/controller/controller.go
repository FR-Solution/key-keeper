package controller

import (
	"context"
	"fmt"
	"time"
)

var intermediateCommonNameLayout = "%s Intermediate Authority"

type vault interface {
	Write(ctx context.Context, path string, data map[string]interface{}) (map[string]interface{}, error)
	Read(ctx context.Context, path string) (map[string]interface{}, error)
	List(ctx context.Context, path string) (map[string]interface{}, error)
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
	// cert, err := s.readCertificate(s.domainName)
	// if cert != nil && time.Until(cert.Leaf.NotAfter) > s.validInterval {
	// 	return nil
	// }
	// if err != nil && !os.IsNotExist(err) {
	// 	return err
	// }

	//create intermediate CA with common name example.com
	icaCert, icaKey, err := s.GenerateIntermediateCA()
	if err != nil {
		return err
	}

	if err := s.storeCertificate("/etc/kubernetes/pki/ca/root-ca.pem", icaCert); err != nil {
		return err
	}

	if err := s.storeKey("/etc/kubernetes/pki/ca/root-ca-key.pem", icaKey); err != nil {
		return err
	}

	// ctx, cancel = context.WithTimeout(context.Background(), s.vaultTimeout)
	// defer cancel()
	// certData, keyData, err := s.GenerateCert(ctx)
	// if err != nil {
	// 	return err
	// }
	// if err := s.storeCertificate(s.certPath, certData); err != nil {
	// 	return err
	// }
	// if err := s.storeKey(s.keyPath, keyData); err != nil {
	// 	return err
	// }

	// go s.runtime()
	return nil
}

func (s *controller) GenerateIntermediateCA() (cert []byte, key []byte, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.vaultTimeout)
	defer cancel()
	storedICA, _ := s.vault.Read(ctx, s.certs.CA.StorePath)
	if cert != nil {
		return storedICA["certificate"].([]byte), storedICA["private_key"].([]byte), nil
	}
	//TODO: check expire

	// create intermediate CA
	ctx, cancel = context.WithTimeout(context.Background(), s.vaultTimeout)
	defer cancel()

	csrData := map[string]interface{}{
		"common_name": fmt.Sprintf(intermediateCommonNameLayout, s.certs.CA.CommonName),
		"ttl":         "8760h",
	}

	csr, err := s.vault.Write(ctx, s.certs.CertPath+"/intermediate/generate/internal", csrData)
	if err != nil {
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
		return
	}

	// publish the signed certificate back to the Intermediate CA
	ctx, cancel = context.WithTimeout(context.Background(), s.vaultTimeout)
	defer cancel()

	certData := map[string]interface{}{
		"certificate": ica["certificate"],
	}

	if _, err = s.vault.Write(ctx, s.certs.CertPath+"/intermediate/set-signed", certData); err != nil {
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), s.vaultTimeout)
	defer cancel()

	if _, err = s.vault.Write(ctx, s.certs.CA.StorePath, ica); err != nil {
		return
	}
	return ica["certificate"].([]byte), ica["private_key"].([]byte), nil
}

// func (s *controller) GenerateCert(ctx context.Context) ([]byte, []byte, error) {
// 	certData := map[string]interface{}{
// 		"common_name": s.domainName,
// 	}
// 	cert, err := s.vault.Write(ctx, s.vaultCertPath, certData)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	return cert["certificate"].([]byte), cert["private_key"].([]byte), nil
// }

// func (s *controller) runtime() {
// 	t := time.Tick(time.Hour)
// 	for {
// 		select {
// 		case <-t:
// 			cert, err := s.readCertificate(s.domainName)
// 			if cert == nil || time.Until(cert.Leaf.NotAfter) < s.validInterval {
// 				ctx, cancel := context.WithTimeout(context.Background(), s.vaultTimeout)
// 				certData, keyData, err := s.GenerateCert(ctx)
// 				if err != nil {
// 					zap.L().Error("generate certificate", zap.Error(err))
// 				}
// 				cancel()
// 				if err := s.storeCertificate(s.certPath, certData); err != nil {
// 					zap.L().Error("store certificate", zap.Error(err))
// 				}
// 				if err := s.storeKey(s.keyPath, keyData); err != nil {
// 					zap.L().Error("store key", zap.Error(err))
// 				}
// 			}
// 			if err != nil {
// 				zap.L().Error("read certificate", zap.Error(err))
// 			}
// 		}
// 	}
// }
