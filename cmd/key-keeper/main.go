package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
	"github.com/fraima/key-keeper/internal/controller"
	"github.com/fraima/key-keeper/internal/issuer/vault"
)

var (
	Version = "undefined"
)

func main() {
	loggerConfig := zap.NewProductionConfig()
	loggerConfig.Level.SetLevel(zap.DebugLevel)
	logger, err := loggerConfig.Build()
	if err != nil {
		panic(err)
	}
	zap.ReplaceGlobals(logger)

	var configDir, configNameLayout string
	flag.StringVar(&configDir, "config-dir", "", "path to dir with configs")
	flag.StringVar(&configNameLayout, "config-regexp", "", "regexp for config files names")
	flag.Parse()

	if configDir == "" {
		zap.L().Fatal("not found config path param")
	}

	if configNameLayout == "" {
		zap.L().Fatal("not found regexp for config file's name")
	}

	cfg, err := config.New(configDir, configNameLayout)
	if err != nil {
		zap.L().Fatal("read configuration", zap.Error(err))
	}

	zap.L().Debug("configuration", zap.Any("config", cfg), zap.String("version", Version))

	cntl := controller.New(
		cfg.GetNewConfig,
		vault.Connect,
	)

	if err := cntl.Start(); err != nil {
		zap.L().Fatal("start controller", zap.Error(err))
	}

	zap.L().Info("started")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	zap.L().Info("goodbye")
}
