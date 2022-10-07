package vault

import (
	"github.com/fraima/key-keeper/internal/config"
	"github.com/fraima/key-keeper/internal/controller"
)

type Driver interface {
	Read(path string) (map[string]interface{}, error)
	Write(path string, data map[string]interface{}) (map[string]interface{}, error)
	Put(kvMountPath, secretePath string, data map[string]interface{}) error
	Get(kvMountPath, secretePath string) (map[string]interface{}, error)
}

type vault struct {
	driver Driver

	name       string
	role       string
	caPath     string
	rootCAPath string

	certificate map[string]config.Certificate
}

func Connector(
	connect func(name string, cfg config.Vault) (Driver, error),
) func(cfg config.Issuer) (controller.Issuer, error) {
	return func(cfg config.Issuer) (controller.Issuer, error) {
		driver, err := connect(cfg.Name, cfg.Vault)
		if err != nil {
			return nil, err
		}

		return &vault{
			driver: driver,

			name:       cfg.Name,
			role:       cfg.Role,
			caPath:     cfg.CAPath,
			rootCAPath: cfg.RootCAPath,

			certificate: make(map[string]config.Certificate),
		}, nil
	}
}

func (s *vault) Name() string {
	return s.name
}

func (s *vault) AddResource(r config.Resources) {
	for _, cert := range r.Certificates {
		s.certificate[cert.Name] = cert
	}
	for _, secret := range r.Secrets {
		go func(secret config.Secret) {
			s.checkSecret(secret)
		}(secret)
	}
	s.CheckResource()
}

func (s *vault) CheckResource() {
	for _, cert := range s.certificate {
		go func(c config.Certificate) {
			if c.IsCA {
				s.checkCA(c)
				return
			}
			s.checkCertificate(c)
		}(cert)
	}
}
