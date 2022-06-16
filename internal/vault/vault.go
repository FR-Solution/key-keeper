package vault

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
)

type vault struct {
	cli *api.Client
	cfg Config
}

func New(cfg Config) (*vault, error) {
	client, err := api.NewClient(
		&api.Config{
			Address: cfg.Address,
			HttpClient: &http.Client{
				Timeout: cfg.Timeout,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("new vault client: %w", err)
	}
	client.SetToken(cfg.Token)

	s := &vault{
		cli: client,
		cfg: cfg,
	}

	roleID, err := s.roleID()
	if err != nil {
		return nil, fmt.Errorf("get role id: %w", err)
	}
	secretID, err := s.secretID()
	if err != nil {
		return nil, fmt.Errorf("get secret id: %w", err)
	}

	appRoleAuth, err := auth.NewAppRoleAuth(
		roleID,
		&auth.SecretID{
			FromString: secretID,
		},
		auth.WithMountPath(fmt.Sprintf("auth/%s/login", cfg.RolePath)),
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

func (s *vault) roleID() (string, error) {
	path := fmt.Sprintf("auth/%s/%s/role-id", s.cfg.RolePath, s.cfg.RoleName)
	approle, err := s.Read(path)
	if err != nil {
		if roleID, rErr := readFromFile(s.cfg.PathToRoleID); rErr == nil {
			return string(roleID), nil
		}
		return "", fmt.Errorf("read role_id fo role %s : %w", s.cfg.RoleName, err)
	}
	if approle == nil {
		return "", fmt.Errorf("no role_id info was returned")
	}

	roleID, ok := approle["role_id"]
	if !ok {
		return "", fmt.Errorf("not found role_id")
	}
	err = writeToFile(s.cfg.PathToRoleID, roleID.(string))
	return roleID.(string), err
}

func (s *vault) secretID() (string, error) {
	path := fmt.Sprintf("auth/%s/%s/secret-id", s.cfg.RolePath, s.cfg.RoleName)
	approle, err := s.Write(path, nil)
	if err != nil {
		if secretID, rErr := readFromFile(s.cfg.PathToSecretID); rErr == nil {
			return string(secretID), nil
		}
		return "", fmt.Errorf("read secrete_id fo role %s : %w", s.cfg.RoleName, err)
	}
	if approle == nil {
		return "", fmt.Errorf("no secrete_id info was returned")
	}

	secretID, ok := approle["secret_id"]
	if !ok {
		return "", fmt.Errorf("not found secrete_id")
	}
	err = writeToFile(s.cfg.PathToRoleID, secretID.(string))
	return secretID.(string), err
}

func (s *vault) List(path string) (map[string]interface{}, error) {
	sec, err := s.cli.Logical().List(path)
	if sec != nil {
		return sec.Data, err
	}
	return nil, err
}

func (s *vault) Read(path string) (map[string]interface{}, error) {
	sec, err := s.cli.Logical().Read(path)
	if sec != nil {
		return sec.Data, err
	}
	return nil, err
}

func (s *vault) Write(path string, data map[string]interface{}) (map[string]interface{}, error) {
	sec, err := s.cli.Logical().Write(path, data)
	if sec != nil {
		return sec.Data, err
	}
	return nil, err
}

func (s *vault) Put(mountPath, secretePath string, data map[string]interface{}) error {
	_, err := s.cli.KVv2(mountPath).Put(context.Background(), secretePath, data)
	return err
}

func (s *vault) Get(mountPath, secretePath string) (map[string]interface{}, error) {
	sec, err := s.cli.KVv2(mountPath).Get(context.Background(), secretePath)
	if sec != nil {
		return sec.Data, err
	}
	return nil, err
}
