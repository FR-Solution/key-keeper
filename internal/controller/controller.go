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
	if err := s.CA(s.certs.CA); err != nil {
		return err
	}

	for _, i := range s.certs.CSR {
		if err := s.CSR(i); err != nil {
			return err
		}
	}
	return nil
}
