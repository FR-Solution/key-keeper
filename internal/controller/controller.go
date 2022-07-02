package controller

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

var intermediateCommonNameLayout = "%s Intermediate Authority"

type vault interface {
	Write(path string, data map[string]interface{}) (map[string]interface{}, error)
	Read(path string) (map[string]interface{}, error)
	Put(mountPath, secretePath string, data map[string]interface{}) error
	Get(mountPath, secretePath string) (map[string]interface{}, error)
}

type controller struct {
	vault vault

	cfg Config
}

func New(store vault, certs Config) *controller {
	c := &controller{
		vault: store,
		cfg:   certs,
	}
	return c
}

// Start controller of key-keeper.
func (s *controller) Start() error {
	s.workflow()

	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		s.workflow()
	}

	return nil
}

func (s *controller) workflow() {
	wg := &sync.WaitGroup{}

	zap.L().Debug("certificate-root-ca")
	for _, c := range s.cfg.Certificates.RootCA {
		wg.Add(1)
		go func(c RootCA) {
			defer wg.Done()
			s.rootCA(c)
		}(c)
	}
	wg.Wait()

	zap.L().Debug("certificate-intermediate-ca")
	for _, c := range s.cfg.Certificates.IntermediateCA {
		wg.Add(1)
		go func(c IntermediateCA) {
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
		go func(c CSR) {
			s.csr(c)
		}(c)
	}

	zap.L().Debug("key-rsa")
	for _, k := range s.cfg.Keys.RSA {
		go func(k RSA) {
			s.Rsa(k)
		}(k)
	}

}
