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

	certs Config
}

func New(store vault, certs Config) *controller {
	c := &controller{
		vault: store,
		certs: certs,
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

	zap.L().Debug("root-ca")
	for _, c := range s.certs.RootCA {
		wg.Add(1)
		go func(c RootCA) {
			defer wg.Done()
			s.rootCA(c)
		}(c)
	}
	wg.Wait()

	zap.L().Debug("intermediate-ca")
	for _, c := range s.certs.IntermediateCA {
		wg.Add(1)
		go func(c IntermediateCA) {
			defer wg.Done()
			if c.WithLocalKey {
				s.intermediateCAWithKey(c)
			} else {
				s.intermediateCAWithoutKey(c)
			}

		}(c)
	}
	wg.Wait()

	zap.L().Debug("csr")
	for _, c := range s.certs.CSR {
		go func(c CSR) {
			s.csr(c)
		}(c)
	}
}
