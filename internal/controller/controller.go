package controller

import (
	"time"
)

var intermediateCommonNameLayout = "%s Intermediate Authority"

type vault interface {
	Write(path string, data map[string]interface{}) (map[string]interface{}, error)
	Read(path string) (map[string]interface{}, error)
	List(path string) (map[string]interface{}, error)
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

func (s *controller) TurnOn() error {
	if err := s.Workflow(); err != nil {
		return err
	}

	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		if err := s.Workflow(); err != nil {
			return err
		}
	}

	return nil
}

func (s *controller) Workflow() error {
	for _, c := range s.certs.CA {
		if err := s.CA(c); err != nil {
			return err
		}
	}

	for _, c := range s.certs.CSR {
		if err := s.CSR(c); err != nil {
			return err
		}
	}
	return nil
}
