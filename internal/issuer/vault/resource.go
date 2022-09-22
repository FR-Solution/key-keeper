package vault

import (
	"fmt"
	"sync"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

func (s *vault) AddResource(r config.Resources) {
	for _, cert := range r.Certificates {
		s.certificate[cert.Name] = cert
	}
	for i, secret := range r.Secrets {
		name := fmt.Sprintf("%s-%d", secret.Name, i)
		s.secret[name] = secret
	}
	s.CheckResource()
}

func (s *vault) CheckResource() {
	zap.L().Debug("checking")
	wg := &sync.WaitGroup{}

	zap.L().Debug("certificate-ca")
	for _, cert := range s.certificate {
		wg.Add(1)
		go func(c config.Certificate) {
			defer wg.Done()
			if c.IsCA {
				s.checkCA(c)
				return
			}
			s.checkCertificate(c)
		}(cert)
	}
	wg.Wait()

	zap.L().Debug("secrets")
	for _, secret := range s.secret {
		wg.Add(1)
		go func(secret config.Secret) {
			s.checkSecret(secret)
		}(secret)
	}
	wg.Wait()

	zap.L().Debug("done")
}
