package vault

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/vault/api"

	"github.com/fraima/key-keeper/internal/config"
	"github.com/fraima/key-keeper/internal/controller"
)

type vault struct {
	cli *api.Client

	role        string
	caPath      string
	rootCAPath  string
	kvMountPath string

	certificate map[string]config.Certificate
}

// Connect to vault issuer.
func Connect(name string, cfg config.Vault) (controller.Issuer, error) {
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

	s := &vault{
		cli: client,

		role:        cfg.Certificate.Role,
		caPath:      cfg.Certificate.CAPath,
		rootCAPath:  cfg.Certificate.RootCAPath,
		kvMountPath: cfg.KV.Path,

		certificate: make(map[string]config.Certificate),
	}
	return s, s.auth(name, cfg.Auth)
}

// Read secret from vault by path.
func (s *vault) Read(path string) (map[string]interface{}, error) {
	sec, err := s.cli.Logical().Read(path)
	if sec != nil {
		return sec.Data, err
	}
	return nil, err
}

// Write secret in vault by path.
func (s *vault) Write(path string, data map[string]interface{}) (map[string]interface{}, error) {
	sec, err := s.cli.Logical().Write(path, data)
	if sec != nil {
		return sec.Data, err
	}
	return nil, err
}

// Put in Vault KV.
func (s *vault) Put(kvMountPath, secretePath string, data map[string]interface{}) error {
	_, err := s.cli.KVv2(kvMountPath).Put(context.Background(), secretePath, data)
	return err
}

// Get from Vault KV.
func (s *vault) Get(kvMountPath, secretePath string) (map[string]interface{}, error) {
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
