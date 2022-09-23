package vault

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

func (s *vault) AddResource(r config.Resources) {
	for i, cert := range r.Certificates {
		name := fmt.Sprintf("%s-%d", cert.Name, i)
		s.certificate[name] = cert
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
