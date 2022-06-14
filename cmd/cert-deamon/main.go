package main

import (
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/terra-cube/key-keeper/internal/config"
	"github.com/terra-cube/key-keeper/internal/controller"
	"github.com/terra-cube/key-keeper/internal/vault"
)

const configPath = "./config.yml"

func main() {
	cfg, err := config.Read(configPath)
	if err != nil {
		zap.L().Fatal("read configuration", zap.Error(err))
	}

	zap.L().Debug("configuration", zap.Any("config", cfg))

	v, err := vault.New(
		cfg.Vault.Address,
		cfg.Vault.Token,
	)
	if err != nil {
		zap.L().Fatal("init vault", zap.Error(err))
	}

	cntl := controller.New(
		v,
		controller.Config{
			VaultIntermediateCAPath: cfg.Vault.IntermediateCAPath,
			VaultCertPath:           cfg.Vault.CertPath,
			VaultTimeout:            cfg.Vault.Timeout.Duration,

			CommonName:    cfg.Certificate.CommonName,
			DomainName:    cfg.Certificate.DomainName,
			CaPath:        cfg.Certificate.CaPath,
			CertPath:      cfg.Certificate.CertPath,
			KeyPath:       cfg.Certificate.KeyPath,
			ValidInterval: cfg.Certificate.ValidInterval.Duration,
		},
	)

	go func() {
		if err := cntl.TurnOn(); err != nil {
			zap.L().Fatal("start", zap.Error(err))
		}
	}()

	zap.L().Info("started")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}
