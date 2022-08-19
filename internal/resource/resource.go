package resource

import (
	"sync"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/controller"
)

type resource struct {
	vault controller.Vault
	cfg   controller.RecourceConfig
}

func Preparing(
	vault controller.Vault,
	cfg controller.RecourceConfig,
) controller.Resource {
	r := &resource{
		vault: vault,
		cfg:   cfg,
	}
	r.Check()
	return r
}

func (s *resource) Check() {
	wg := &sync.WaitGroup{}

	zap.L().Debug("certificate-root-ca")
	for _, c := range s.cfg.Certificates.RootCA {
		wg.Add(1)
		go func(c controller.RootCA) {
			defer wg.Done()
			s.rootCA(c)
		}(c)
	}
	wg.Wait()

	zap.L().Debug("certificate-intermediate-ca")
	for _, c := range s.cfg.Certificates.IntermediateCA {
		wg.Add(1)
		go func(c controller.IntermediateCA) {
			defer wg.Done()
			if c.ExportedKey {
				s.intermediateCAWithExportedKey(c)
			} else {
				s.intermediateCA(c)
			}
		}(c)
	}
	wg.Wait()

	zap.L().Debug("certificate-csr")
	for _, c := range s.cfg.Certificates.CSR {
		go func(c controller.CSR) {
			s.csr(c)
		}(c)
	}

	zap.L().Debug("key-rsa")
	for _, k := range s.cfg.Keys.RSA {
		go func(k controller.RSA) {
			s.rsa(k)
		}(k)
	}
}
