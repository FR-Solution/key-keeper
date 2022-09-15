package controller

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

type Config interface {
	GetNewConfig() (cfgs config.Config, err error)
}

type Issuer interface {
	AddResource(r config.Resources)
	CheckResource()
}

type controller struct {
	config          Config
	issuerConnector func(cfg config.Vault) (Issuer, error)

	issuer sync.Map
}

func New(
	config Config,
	vaultConnector func(cfg config.Vault) (Issuer, error),
) *controller {
	return &controller{
		config:          config,
		issuerConnector: vaultConnector,
	}
}

// Start controller of key-keeper.
func (s *controller) Start() {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		s.issuer.Range(func(key, value any) bool {
			value.(Issuer).CheckResource()
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

	for _, iCfg := range cfg.Issuers {
		// TODO: что делать если приходит несколько issuer с одинаковыми именами
		_, isExist := s.issuer.Load(iCfg.Name)
		if isExist {
			zap.L().Warn(
				"preparing resource",
				zap.String("issuer_name", iCfg.Name),
				zap.String("step", "connect to issuer"),
				zap.Error(errors.New("issuer is exist")),
			)
			continue
		}
		conn, err := s.issuerConnector(iCfg.Vault)
		if err != nil {
			zap.L().Error(
				"preparing resource",
				zap.String("issuer_name", iCfg.Name),
				zap.String("step", "connect to issuer"),
				zap.Error(err),
			)
			continue
		}

		s.issuer.Store(iCfg.Name, conn)
	}

	resources := s.separateResources(cfg.Resource)
	for issuerName, rCfg := range resources {
		r, isExist := s.issuer.Load(issuerName)
		if !isExist {
			zap.L().Warn(
				"preparing resource",
				zap.String("issuer_name", issuerName),
				zap.String("step", "add recource"),
				zap.Error(errors.New("issuer is not exist")),
			)
			continue
		}
		r.(Issuer).AddResource(rCfg)
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

	for _, secret := range cfg.Secrets {
		resources := r[secret.IssuerRef.Name]
		resources.Secrets = append(resources.Secrets, secret)
		r[secret.IssuerRef.Name] = resources
	}
	return r
}
