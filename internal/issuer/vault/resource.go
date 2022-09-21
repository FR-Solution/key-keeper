package vault

import (
	"sync"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

func (s *vault) AddResource(r config.Resources) {
	for _, cert := range r.Certificates {
		s.certificate[cert.Name] = cert
	}
	for _, key := range r.Keys {
		s.key[key.Name] = key
	}
	for _, secret := range r.Secrets {
		s.secret[secret.Name] = secret
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

	zap.L().Debug("keys")
	for _, key := range s.key {
		wg.Add(1)
		go func(k config.Key) {
			s.checkKeyPair(k)
		}(key)
	}

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
