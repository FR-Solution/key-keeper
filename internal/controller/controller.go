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

	certs []func() error
}

func New(store vault, cfg Config) *controller {
	c := &controller{
		vault: store,

		cfg: cfg,
	}

	if cfg.Certs.CA != nil {
		c.certs = append(c.certs, c.CA)
	}
	if cfg.Certs.CSR != nil {
		c.certs = append(c.certs, c.CSR)
	}
	return c
}

func (s *controller) TurnOn() error {
	for _, f := range s.certs {
		if err := f(); err != nil {
			return err
		}
	}

	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		for _, f := range s.certs {
			if err := f(); err != nil {
				return err
			}
		}
	}

	return nil
}
