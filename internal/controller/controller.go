package controller

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fraima/key-keeper/internal/config"
	"go.uber.org/zap"
)

type Config interface {
	GetNewConfig() (cfgs config.Config, err error)
}

type Vault interface {
	Write(path string, data map[string]interface{}) (map[string]interface{}, error)
	Read(path string) (map[string]interface{}, error)
	Put(secretePath string, data map[string]interface{}) error
	Get(secretePath string) (map[string]interface{}, error)
}

type Resource interface {
	Add(r config.Resources)
	Check()
}

type controller struct {
	config         Config
	vaultConnector func(cfg config.Vault) (Vault, error)

	newResource func(vault Vault) Resource
	resource    sync.Map
}

func New(
	config Config,
	vaultConnector func(cfg config.Vault) (Vault, error),
	newResource func(vault Vault) Resource,
) *controller {
	return &controller{
		config:         config,
		vaultConnector: vaultConnector,
		newResource:    newResource,
	}
}

// Start controller of key-keeper.
func (s *controller) Start() {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		s.resource.Range(func(key, value any) bool {
			value.(Resource).Check()
			return true
		})
	}
}

func (s *controller) RefreshResource() {
	if err := s.getNewResource(); err != nil {
		zap.L().Error("refresh resources", zap.Error(err))
	}

	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		if err := s.getNewResource(); err != nil {
			zap.L().Error("refresh resources", zap.Error(err))
		}
	}
}

func (s *controller) getNewResource() error {
	cfg, err := s.config.GetNewConfig()
	if err != nil {
		return fmt.Errorf("get new configs: %w", err)
	}

	for _, vaultCfg := range cfg.Issuers {
		// TODO: что делать если приходит несколько issuer с одинаковыми именами
		_, isExist := s.resource.Load(vaultCfg.Name)
		if isExist {
			zap.L().Warn(
				"preparing resource",
				zap.String("issuer_name", vaultCfg.Name),
				zap.String("step", "connect to issuer"),
				zap.Error(errors.New("issuer is exist")),
			)
			continue
		}
		vaultConnection, err := s.vaultConnector(vaultCfg.Vault)
		if err != nil {
			zap.L().Error(
				"preparing resource",
				zap.String("issuer_name", vaultCfg.Name),
				zap.String("step", "connect to issuer"),
				zap.Error(err),
			)
			continue
		}

		r := s.newResource(vaultConnection)
		s.resource.Store(vaultCfg.Name, r)
	}

	resources := s.separateResources(cfg.Resource)
	for issuerName, resourceCfg := range resources {
		r, isExist := s.resource.Load(issuerName)
		if !isExist {
			zap.L().Warn(
				"preparing resource",
				zap.String("issuer_name", issuerName),
				zap.String("step", "add recource"),
				zap.Error(errors.New("issuer is not exist")),
			)
			continue
		}
		r.(Resource).Add(resourceCfg)
	}

	return nil
}

func (s *controller) separateResources(cfg config.Resources) map[string]config.Resources {
	// TODO: что делать если приходит несколько ресурсов с одинаковыми именами для одного issuer
	r := make(map[string]config.Resources)

	for _, cert := range cfg.Certificates {
		resources := r[cert.IssuerRef.Name]
		resources.Certificates = append(resources.Certificates, cert)
		r[cert.IssuerRef.Name] = resources
	}

	for _, key := range cfg.Keys {
		resources := r[key.IssuerRef.Name]
		resources.Keys = append(resources.Keys, key)
		r[key.IssuerRef.Name] = resources
	}
	return r
}
