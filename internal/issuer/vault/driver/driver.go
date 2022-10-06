package driver

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/vault/api"

	"github.com/fraima/key-keeper/internal/config"
	"github.com/fraima/key-keeper/internal/issuer/vault"
)

type driver struct {
	cli *api.Client
}

// Connect to vault issuer.
func Connect(name string, cfg config.Vault) (vault.Driver, error) {
	client, err := api.NewClient(
		&api.Config{
			Address: cfg.Server,
			HttpClient: &http.Client{
				Timeout: cfg.Timeout,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("new vault client: %w", err)
	}

	token, err := getToken(cfg.Auth.Bootstrap)
	if err != nil {
		return nil, fmt.Errorf("get vault token: %w", err)
	}

	client.SetToken(token)
	if !cfg.Auth.TLSInsecure {
		err = client.CloneConfig().ConfigureTLS(&api.TLSConfig{CACert: cfg.Auth.CABundle})
		if err != nil {
			return nil, fmt.Errorf("configuring tls: %w", err)
		}
	}

	s := &driver{
		cli: client,
	}
	return s, s.auth(name, cfg.Auth)
}

// Read secret from vault by path.
func (s *driver) Read(path string) (map[string]interface{}, error) {
	sec, err := s.cli.Logical().Read(path)
	if sec != nil {
		return sec.Data, err
	}
	return nil, err
}

// Write secret in vault by path.
func (s *driver) Write(path string, data map[string]interface{}) (map[string]interface{}, error) {
	sec, err := s.cli.Logical().Write(path, data)
	if sec != nil {
		return sec.Data, err
	}
	return nil, err
}

// Put in Vault KV.
func (s *driver) Put(kvMountPath, secretePath string, data map[string]interface{}) error {
	_, err := s.cli.KVv2(kvMountPath).Put(context.Background(), secretePath, data)
	return err
}

// Get from Vault KV.
func (s *driver) Get(kvMountPath, secretePath string) (map[string]interface{}, error) {
	sec, err := s.cli.KVv2(kvMountPath).Get(context.Background(), secretePath)
	if sec != nil {
		return sec.Data, err
	}
	return nil, err
}

func getToken(b config.Bootstrap) (string, error) {
	if b.Token != "" {
		return b.Token, nil
	}

	data, err := os.ReadFile(b.File)
	return string(data), err
}
