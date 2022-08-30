package resource

import (
	"sync"

	"github.com/fraima/key-keeper/internal/config"
	"github.com/fraima/key-keeper/internal/controller"
	"go.uber.org/zap"
)

type resource struct {
	vault       controller.Vault
	certificate map[string]config.Certificate
	key         map[string]config.Key
}

func Preparing(
	vault controller.Vault,
) controller.Resource {
	return &resource{
		vault:       vault,
		certificate: make(map[string]config.Certificate),
		key:         make(map[string]config.Key),
	}
}

func (s *resource) Check() {
	zap.L().Debug("checking")
	wg := &sync.WaitGroup{}

	zap.L().Debug("certificate-intermediate-ca")
	for _, cert := range s.certificate {
		wg.Add(1)
		go func(c config.Certificate) {
			defer wg.Done()
			if c.IsCA {
				if c.IsCA {
					s.checkCA(c)
				} else {
					s.checkCSR(c)
				}
			}
		}(cert)
	}
	wg.Wait()

	zap.L().Debug("keys")
	for _, key := range s.key {
		wg.Add(1)
		go func(k config.Key) {
			s.checkKey(k)
		}(key)
	}
	wg.Wait()

	zap.L().Debug("done")
}

func (s *resource) Add(r config.Resources) {
	for _, cert := range r.Certificates {
		s.certificate[cert.Name] = cert
	}
	for _, key := range r.Keys {
		s.key[key.Name] = key
	}
	s.Check()
}
