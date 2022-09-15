package vault

import (
	"context"
	"fmt"
	"net/http"
	"path"

	"github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"

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
	key         map[string]config.Key
	secret      map[string]config.Secret
}

func Connect(cfg config.Vault) (controller.Issuer, error) {
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
	client.SetToken(cfg.Auth.Bootstrap.Token)
	if !cfg.Auth.TLSInsecure {
		if err = client.CloneConfig().ConfigureTLS(&api.TLSConfig{CACert: cfg.Auth.CABundle}); err != nil {
			return nil, fmt.Errorf("configurate tls: %w", err)
		}
	}

	s := &vault{
		cli: client,

		role:        cfg.Certificate.Role,
		caPath:      cfg.Certificate.CAPath,
		rootCAPath:  cfg.Certificate.RootCAPath,
		kvMountPath: cfg.KV.Path,

		certificate: make(map[string]config.Certificate),
		key:         make(map[string]config.Key),
		secret:      make(map[string]config.Secret),
	}

	roleID, err := s.roleID(cfg.Auth.AppRole)
	if err != nil {
		return nil, fmt.Errorf("get role id: %w", err)
	}
	secretID, err := s.secretID(cfg.Auth.AppRole)
	if err != nil {
		return nil, fmt.Errorf("get secret id: %w", err)
	}

	appRoleAuth, err := auth.NewAppRoleAuth(
		roleID,
		&auth.SecretID{
			FromString: secretID,
		},
		auth.WithMountPath(cfg.Auth.AppRole.Path),
	)
	if err != nil {
		return nil, err
	}

	authInfo, err := client.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		return nil, err
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no auth info was returned after login")
	}
	return s, nil
}

func (s *vault) roleID(appRole config.AppRole) (string, error) {
	path := path.Join("auth", appRole.Path, "role", appRole.Name, "role-id")
	approle, err := s.Read(path)
	if err != nil {
		if roleID, rErr := readFromFile(appRole.RoleIDLocalPath); rErr == nil {
			return string(roleID), nil
		}
		return "", fmt.Errorf("read role_id for path: %s : %w", path, err)
	}
	if approle == nil {
		return "", fmt.Errorf("no role_id info was returned")
	}

	roleID, ok := approle["role_id"]
	if !ok {
		return "", fmt.Errorf("not found role_id")
	}
	if err = writeToFile(appRole.RoleIDLocalPath, roleID.(string)); err != nil {
		return "", fmt.Errorf("save role id path: %s id: %w", appRole.RoleIDLocalPath, err)
	}
	return roleID.(string), err
}

func (s *vault) secretID(appRole config.AppRole) (string, error) {
	path := path.Join("auth", appRole.Path, "role", appRole.Name, "secret-id")
	approle, err := s.Write(path, nil)
	if err != nil {
		if secretID, rErr := readFromFile(appRole.SecretIDLocalPath); rErr == nil {
			return string(secretID), nil
		}
		return "", fmt.Errorf("read secrete_id for path: %s : %w", path, err)
	}
	if approle == nil {
		return "", fmt.Errorf("no secrete_id info was returned")
	}

	secretID, ok := approle["secret_id"]
	if !ok {
		return "", fmt.Errorf("not found secrete_id")
	}

	if err = writeToFile(appRole.SecretIDLocalPath, secretID.(string)); err != nil {
		return "", fmt.Errorf("save secret id path: %s id: %w", appRole.SecretIDLocalPath, err)
	}
	return secretID.(string), err
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

// Put in KV.
func (s *vault) Put(kvMountPath, secretePath string, data map[string]interface{}) error {
	_, err := s.cli.KVv2(kvMountPath).Put(context.Background(), secretePath, data)
	return err
}

// Get from KV.
func (s *vault) Get(kvMountPath, secretePath string) (map[string]interface{}, error) {
	sec, err := s.cli.KVv2(kvMountPath).Get(context.Background(), secretePath)
	if sec != nil {
		return sec.Data, err
	}
	return nil, err
}
