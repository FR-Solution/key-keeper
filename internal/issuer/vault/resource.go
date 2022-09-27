package vault

import (
	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

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
	zap.L().Debug("checking")

	for _, cert := range s.certificate {
		go func(c config.Certificate) {
			if c.IsCA {
				s.checkCA(c)
				return
			}
			s.checkCertificate(c)
		}(cert)
	}

	zap.L().Debug("done")
}
