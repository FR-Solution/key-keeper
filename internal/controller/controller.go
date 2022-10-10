package controller

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

type Issuer interface {
	Name() string
	AddResource(config.Resources)
	CheckResource()
}

type controller struct {
	getConfig       func() (config.Config, error)
	issuerConnector func(cfg config.Issuer) (Issuer, error)

	issuer sync.Map
}

// New returns controller.
func New(
	config func() (config.Config, error),
	issuerConnector func(cfg config.Issuer) (Issuer, error),
) *controller {
	return &controller{
		getConfig:       config,
		issuerConnector: issuerConnector,
	}
}

// Start controller.
func (s *controller) Start() error {
	if err := s.getNewResource(); err != nil {
		return err
	}

	// start getting new resources and issuers
	go func() {
		for range time.NewTicker(30 * time.Second).C {
			if err := s.getNewResource(); err != nil {
				zap.L().Error("refresh_resources", zap.Error(err))
			}
		}
	}()

	// start resource checking
	go func() {
		for range time.NewTicker(30 * time.Second).C {

			s.issuer.Range(func(key, value any) bool {
				issuer := value.(Issuer)
				zap.L().Debug("start_checking", zap.String("issuer", issuer.Name()))
				issuer.CheckResource()
				zap.L().Debug("finish_checking", zap.String("issuer", issuer.Name()))
				return true
			})
		}
	}()

	return nil
}

func (s *controller) getNewResource() error {
	cfg, err := s.getConfig()
	if err != nil {
		return fmt.Errorf("get new configs: %w", err)
	}

	for _, issuer := range cfg.Issuers {
		_, isExist := s.issuer.Load(issuer.Name)
		if isExist {
			zap.L().Error(
				"issuer_connect",
				zap.String("issuer_name", issuer.Name),
				zap.String("status", "failed"),
				zap.Error(errIssuerIsExist),
			)
			continue
		}

		conn, err := s.issuerConnector(issuer)
		if err != nil {
			zap.L().Error("issuer_connect", zap.String("issuer_name", issuer.Name), zap.Error(err))
			continue
		}

		s.issuer.Store(issuer.Name, conn)

		zap.L().Debug("issuer_connect", zap.String("issuer_name", issuer.Name))
	}

	resources := s.separateResourcesByIssuers(cfg.Resource)
	for issuerName, rCfg := range resources {
		issuer, isExist := s.issuer.Load(issuerName)
		if !isExist {
			zap.L().Error("add_resource", zap.String("issuer_name", issuerName), zap.Error(errIssuerIsNotExist))
			continue
		}
		issuer.(Issuer).AddResource(rCfg)

		zap.L().Debug("add_resource", zap.String("issuer_name", issuerName))
	}
	return nil
}

func (s *controller) separateResourcesByIssuers(cfg config.Resources) map[string]config.Resources {
	r := make(map[string]config.Resources)

	for _, cert := range cfg.Certificates {
		resources := r[cert.IssuerRef.Name]
		resources.Certificates = append(resources.Certificates, cert)
		r[cert.IssuerRef.Name] = resources
	}

	for _, secret := range cfg.Secrets {
		resources := r[secret.IssuerRef.Name]
		resources.Secrets = append(resources.Secrets, secret)
		r[secret.IssuerRef.Name] = resources
	}
	return r
}
