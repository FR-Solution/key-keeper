package controller

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
)

var intermediateCommonNameLayout = "%s Intermediate Authority"

type store interface {
	Write(ctx context.Context, path string, data map[string]interface{}) (map[string]interface{}, error)
	Read(ctx context.Context, path string) (map[string]interface{}, error)
	List(ctx context.Context, path string) (map[string]interface{}, error)
}

type controller struct {
	store store

	commonName              string
	domainName              string
	storeIntermediateCAPath string
	storeCertPath           string
	storeTimeout            time.Duration
	certPath                string
	keyPath                 string
	caPath                  string
	validInterval           time.Duration
}

func New(store store, cfg Config) *controller {
	c := &controller{
		store: store,

		commonName:              cfg.CommonName,
		domainName:              cfg.DomainName,
		storeIntermediateCAPath: cfg.VaultCertPath,
		storeCertPath:           cfg.VaultCertPath,
		storeTimeout:            cfg.VaultTimeout,
		certPath:                cfg.CertPath,
		keyPath:                 cfg.KeyPath,
		caPath:                  cfg.CaPath,
		validInterval:           cfg.ValidInterval,
	}
	return c
}

func (s *controller) TurnOn() error {
	cert, err := s.readCertificate(s.domainName)
	if cert != nil && time.Until(cert.Leaf.NotAfter) > s.validInterval {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.storeTimeout)
	defer cancel()

	intermediateCA, err := s.GenerateIntermediateCA(ctx)
	if err != nil {
		return err
	}
	if err := s.storeCertificate(s.caPath, intermediateCA); err != nil {
		return err
	}

	ctx, cancel = context.WithTimeout(context.Background(), s.storeTimeout)
	defer cancel()

	certData, keyData, err := s.GenerateCert(ctx)
	if err != nil {
		return err
	}
	if err := s.storeCertificate(s.certPath, certData); err != nil {
		return err
	}
	if err := s.storeKey(s.keyPath, keyData); err != nil {
		return err
	}

	go s.runtime()
	return nil
}

func (s *controller) GenerateIntermediateCA(ctx context.Context) ([]byte, error) {
	cert, _ := s.store.Read(ctx, s.storeIntermediateCAPath)
	if cert != nil {
		return cert["certificate"].([]byte), nil
	}

	//TODO: check expire
	csrData := map[string]interface{}{
		"common_name": fmt.Sprintf(intermediateCommonNameLayout, s.commonName),
		"ttl":         "8760h",
	}
	csr, err := s.store.Write(ctx, "pki_int/intermediate/generate/internal", csrData)
	if err != nil {
		return nil, err
	}

	pemData := map[string]interface{}{
		"csr":    csr["csr"],
		"format": "pem_bundle",
		"ttl":    "8760h",
	}
	pem, err := s.store.Write(ctx, "pki/root/sign-intermediate", pemData)
	if err != nil {
		return nil, err
	}

	certData := map[string]interface{}{
		"certificate": pem["certificate"],
	}
	if _, err = s.store.Write(ctx, "pki_int/intermediate/set-signed", certData); err != nil {
		return nil, err
	}

	if _, err = s.store.Write(ctx, s.storeIntermediateCAPath, pem); err != nil {
		return nil, err
	}
	return pem["certificate"].([]byte), nil
}

func (s *controller) GenerateCert(ctx context.Context) ([]byte, []byte, error) {
	certData := map[string]interface{}{
		"common_name": s.domainName,
	}
	cert, err := s.store.Write(ctx, "pki_int/issue/example-dot-com", certData)
	if err != nil {
		return nil, nil, err
	}
	return cert["certificate"].([]byte), cert["private_key"].([]byte), nil
}

func (s *controller) runtime() {
	t := time.Tick(time.Hour)
	for {
		select {
		case <-t:
			cert, err := s.readCertificate(s.domainName)
			if cert == nil || time.Until(cert.Leaf.NotAfter) < s.validInterval {
				ctx, cancel := context.WithTimeout(context.Background(), s.storeTimeout)
				certData, keyData, err := s.GenerateCert(ctx)
				if err != nil {
					zap.L().Error("generate certificate", zap.Error(err))
				}
				cancel()
				if err := s.storeCertificate(s.certPath, certData); err != nil {
					zap.L().Error("store certificate", zap.Error(err))
				}
				if err := s.storeKey(s.keyPath, keyData); err != nil {
					zap.L().Error("store key", zap.Error(err))
				}
			}
			if err != nil {
				zap.L().Error("read certificate", zap.Error(err))
			}
		}
	}
}
