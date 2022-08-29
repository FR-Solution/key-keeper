package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
	"github.com/fraima/key-keeper/internal/controller"
	"github.com/fraima/key-keeper/internal/resource"
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

	var globalConfig, configDir, configNameLayout string
	flag.StringVar(&globalConfig, "config-global", "", "path to global config")
	flag.StringVar(&configDir, "config-dir", "", "path to dir with configs")
	flag.StringVar(&configNameLayout, "config-regexp", "", "regexp for config files names")
	flag.Parse()

	if globalConfig == "" {
		zap.L().Fatal("not found global config param")
	}

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
		cfg,
		vault.Connect,
		resource.Preparing,
	)
	go cntl.Start()

	zap.L().Info("started")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}
