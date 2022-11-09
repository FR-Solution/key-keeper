package client

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/fraima/key-keeper/internal/config"
	"github.com/fraima/key-keeper/internal/issuer/vault"
)

type client struct {
	cli *api.Client
}

// Connect to vault issuer.
func Connect(name string, cfg config.Vault) (vault.Client, error) {
	cli, err := api.NewClient(
		&api.Config{
			Address: cfg.Server,
			HttpClient: &http.Client{
				Timeout: 10 * time.Second,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("new vault client: %w", err)
	}

	if !cfg.Auth.TLSInsecure {
		err = cli.CloneConfig().ConfigureTLS(&api.TLSConfig{CACert: cfg.Auth.CABundle})
		if err != nil {
			return nil, fmt.Errorf("configuring tls: %w", err)
		}
	}

	s := &client{
		cli: cli,
	}

	token, err := s.getToken(cfg.Auth)
	if err != nil {
		return nil, fmt.Errorf("get vault token: %w", err)
	}

	s.cli.SetToken(token)

	return s, s.auth(name, cfg.Auth)
}

// Read secret from vault by path.
func (s *client) Read(path string) (map[string]interface{}, error) {
	sec, err := s.cli.Logical().Read(path)
	if sec != nil {
		return sec.Data, err
	}
	return nil, err
}

// Write secret in vault by path.
func (s *client) Write(path string, data map[string]interface{}) (map[string]interface{}, error) {
	sec, err := s.cli.Logical().Write(path, data)
	if sec != nil {
		return sec.Data, err
	}
	return nil, err
}

// Put in Vault KV.
func (s *client) Put(kvMountPath, secretePath string, data map[string]interface{}) error {
	_, err := s.cli.KVv2(kvMountPath).Put(context.Background(), secretePath, data)
	return err
}

// Get from Vault KV.
func (s *client) Get(kvMountPath, secretePath string) (map[string]interface{}, error) {
	sec, err := s.cli.KVv2(kvMountPath).Get(context.Background(), secretePath)
	if sec != nil {
		return sec.Data, err
	}
	return nil, err
}
