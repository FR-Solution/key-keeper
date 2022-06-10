package controller

import (
	"context"
	"os"
	"time"
)

type store interface {
	Write(ctx context.Context, path string, data map[string]interface{}) (map[string]interface{}, error)
	Read(ctx context.Context, path string) (map[string]interface{}, error)
	List(ctx context.Context, path string) (map[string]interface{}, error)
}

type controller struct {
	store store

	commonName   string
	domain       string
	storeCAPath  string
	storeTimeout time.Duration

	certPath string
	keyPath  string
	caPath   string

	validInterval time.Duration
}

func New(store store, cfg Config) (*controller, error) {
	c := &controller{
		store:       store,
		commonName:  cfg.CommonName,
		storeCAPath: cfg.VaultCAPath,
	}

	return c, nil
}

func (s *controller) TurnOn() error {
	cert, err := s.readCertificate(s.domain)
	if time.Until(cert.Leaf.NotAfter) > s.validInterval {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.storeTimeout)
	defer cancel()
	err = s.GenerateCA(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *controller) GenerateCA(ctx context.Context) error {
	caData := map[string]interface{}{
		"common_name": s.commonName,
		"ttl":         "8760h",
	}
	caCert, err := s.store.Write(ctx, "pki/root/generate/internal", caData)
	if err != nil {
		return err
	}
	if len(caCert) == 0 {
		return nil
	}

	_, err = s.store.Write(ctx, s.storeCAPath, caCert)
	return err
}
