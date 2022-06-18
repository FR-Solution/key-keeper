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
	for _, c := range s.certs.CA {
		wg.Add(1)
		go func(c CA) {
			defer wg.Done()
			if err := s.ca(c); err != nil {
				zap.L().Error("ca", zap.String("common_name", c.CommonName), zap.Error(err))
			}
		}(c)
	}
	wg.Wait()

	for _, c := range s.certs.CSR {
		go func(c CSR) {
			if err := s.csr(c); err != nil {
				zap.L().Error("ca", zap.String("common_name", c.CommonName), zap.Error(err))
			}
		}(c)
	}
}
