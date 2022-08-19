package controller

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

type config interface {
	GetNewConfig() (cfgs []Config, err error)
}

type Vault interface {
	Write(path string, data map[string]interface{}) (map[string]interface{}, error)
	Read(path string) (map[string]interface{}, error)
	Put(mountPath, secretePath string, data map[string]interface{}) error
	Get(mountPath, secretePath string) (map[string]interface{}, error)
}

type Resource interface {
	Check()
}

type controller struct {
	config         config
	vaultConnector func(cfg VaultConfig) (Vault, error)

	resourcePreparing func(vault Vault, cfg RecourceConfig) Resource
	lock              sync.RWMutex
	resources         []Resource
}

func New(
	config config,
	vaultConnector func(cfg VaultConfig) (Vault, error),
	resourcePreparing func(vault Vault, cfg RecourceConfig) Resource,
) *controller {
	return &controller{
		config:            config,
		vaultConnector:    vaultConnector,
		resourcePreparing: resourcePreparing,
	}
}

// Start controller of key-keeper.
func (s *controller) Start() {
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			if err := s.getNewRecource(); err != nil {
				zap.L().Error("runtime", zap.Error(err))
			}
		}
	}()

	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		s.lock.RLock()
		for _, r := range s.resources {
			r.Check()
		}
		s.lock.RUnlock()
	}
}

func (s *controller) getNewRecource() error {
	cfgList, err := s.config.GetNewConfig()
	if err != nil {
		return fmt.Errorf("get new configs: %w", err)
	}

	for _, cfg := range cfgList {
		vaultConnect, err := s.vaultConnector(cfg.Vault)
		if err != nil {
			zap.L().Error("connect to vault", zap.Error(err))
		}
		r := s.resourcePreparing(vaultConnect, cfg.Recource)
		s.lock.Lock()
		s.resources = append(s.resources, r)
		s.lock.Unlock()
	}
	return nil
}
