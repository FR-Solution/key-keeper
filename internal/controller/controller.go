package controller

import (
	"context"
	"time"
)

var intermediateCommonNameLayout = "%s Intermediate Authority"

type vault interface {
	Write(ctx context.Context, path string, data map[string]interface{}) (map[string]interface{}, error)
	Read(ctx context.Context, path string) (map[string]interface{}, error)
	List(ctx context.Context, path string) (map[string]interface{}, error)
	Put(ctx context.Context, mountPath, secretePath string, data map[string]interface{}) error
	Get(ctx context.Context, mountPath, secretePath string) (map[string]interface{}, error)
}

type controller struct {
	vault vault

	cfg Config
}

func New(store vault, cfg Config) *controller {
	c := &controller{
		vault: store,

		cfg: cfg,
	}
	return c
}

func (s *controller) TurnOn() error {
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
	for _, i := range s.cfg.Certs.CA {
		if err := s.CA(i); err != nil {
			return err
		}
	}
	for _, i := range s.cfg.Certs.CSR {
		if err := s.CSR(i); err != nil {
			return err
		}
	}
	return nil
}
