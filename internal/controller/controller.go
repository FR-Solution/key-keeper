package controller

import (
	"time"
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
	if err := s.workflow(); err != nil {
		return err
	}

	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		if err := s.workflow(); err != nil {
			return err
		}
	}

	return nil
}

func (s *controller) workflow() error {
	for _, c := range s.certs.CA {
		if err := s.ca(c); err != nil {
			return err
		}
	}

	for _, c := range s.certs.CSR {
		if err := s.csr(c); err != nil {
			return err
		}
	}
	return nil
}
