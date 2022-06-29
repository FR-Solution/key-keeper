package vault

import (
	"context"
	"fmt"
	"net/http"
	"path"

	"github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
)

type vault struct {
	cli *api.Client
}

func New(cfg Config) (*vault, error) {
	client, err := api.NewClient(
		&api.Config{
			Address: cfg.Address,
			HttpClient: &http.Client{
				Timeout: cfg.RequestTimeout,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("new vault client: %w", err)
	}
	client.SetToken(cfg.BootsrapToken)

	s := &vault{
		cli: client,
	}

	roleID, err := s.roleID(cfg)
	if err != nil {
		return nil, fmt.Errorf("get role id: %w", err)
	}
	secretID, err := s.secretID(cfg)
	if err != nil {
		return nil, fmt.Errorf("get secret id: %w", err)
	}

	appRoleAuth, err := auth.NewAppRoleAuth(
		roleID,
		&auth.SecretID{
			FromString: secretID,
		},
		auth.WithMountPath(cfg.AppRolePath),
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

func (s *vault) roleID(cfg Config) (string, error) {
	path := path.Join("auth", cfg.AppRolePath, "role", cfg.AppRoleName, "role-id")
	approle, err := s.Read(path)
	if err != nil {
		if roleID, rErr := readFromFile(cfg.LocalPathToRoleID); rErr == nil {
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
	if err = writeToFile(cfg.LocalPathToRoleID, roleID.(string)); err != nil {
		return "", fmt.Errorf("save role id path: %s id: %w", cfg.LocalPathToRoleID, err)
	}
	return roleID.(string), err
}

func (s *vault) secretID(cfg Config) (string, error) {
	path := path.Join("auth", cfg.AppRolePath, "role", cfg.AppRoleName, "secret-id")
	approle, err := s.Write(path, nil)
	if err != nil {
		if secretID, rErr := readFromFile(cfg.LocalPathToSecretID); rErr == nil {
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

	if err = writeToFile(cfg.LocalPathToSecretID, secretID.(string)); err != nil {
		return "", fmt.Errorf("save secret id path: %s id: %w", cfg.LocalPathToSecretID, err)
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
func (s *vault) Put(mountPath, secretePath string, data map[string]interface{}) error {
	_, err := s.cli.KVv2(mountPath).Put(context.Background(), secretePath, data)
	return err
}

// Get from KV.
func (s *vault) Get(mountPath, secretePath string) (map[string]interface{}, error) {
	sec, err := s.cli.KVv2(mountPath).Get(context.Background(), secretePath)
	if sec != nil {
		return sec.Data, err
	}
	return nil, err
}
