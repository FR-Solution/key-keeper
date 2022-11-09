package client

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	auth "github.com/hashicorp/vault/api/auth/approle"
	"go.uber.org/zap"

	"github.com/fraima/key-keeper/internal/config"
)

func (s *client) auth(name string, a config.Auth) error {
	token, err := s.getBootstrapToken(a.Bootstrap)
	if err != nil {
		return fmt.Errorf("get vault token: %w", err)
	}
	s.cli.SetToken(token)

	roleID, err := s.getRoleID(name, a.AppRole)
	if err != nil {
		return fmt.Errorf("get role id: %w", err)
	}
	secretID, err := s.getSecretID(name, a.AppRole)
	if err != nil {
		return fmt.Errorf("get secret id: %w", err)
	}

	appRoleAuth, err := auth.NewAppRoleAuth(
		roleID,
		&auth.SecretID{
			FromString: secretID,
		},
		auth.WithMountPath(a.AppRole.Path),
	)
	if err != nil {
		return fmt.Errorf("app role auth: %w", err)
	}

	token, ttl, err := s.getRoleToken(appRoleAuth)
	if err != nil {
		return fmt.Errorf("get role token: %w", err)
	}
	s.cli.SetToken(token)

	go func() {
		t := time.NewTimer(ttl / 2)
		for range t.C {
			token, ttl, err := s.getRoleToken(appRoleAuth)
			if err != nil {
				zap.L().Error("update auth token", zap.String("issuer_name", name), zap.Error(err))
			}
			s.cli.SetToken(token)
			t.Reset(ttl / 2)
		}
	}()
	return nil
}

func (s *client) getBootstrapToken(a config.Bootstrap) (string, error) {
	if a.Token != "" {
		return a.Token, nil
	}

	data, err := os.ReadFile(a.File)
	return strings.TrimSuffix(string(data), "\n"), err
}

func (s *client) getRoleID(name string, appRole config.AppRole) (string, error) {
	if roleID, err := os.ReadFile(appRole.RoleIDLocalPath); err == nil {
		return string(roleID), nil
	}

	vaultPath := path.Join("auth", appRole.Path, "role", appRole.Name, "role-id")
	role, err := s.Read(vaultPath)
	if err != nil {
		return "", fmt.Errorf("read role_id for path: %s : %w", vaultPath, err)
	}
	if role == nil {
		return "", fmt.Errorf("role_id info was not  returned")
	}

	roleID, ok := role["role_id"]
	if !ok {
		return "", fmt.Errorf("not found role_id")
	}

	if err = writeToFile(appRole.RoleIDLocalPath, []byte(roleID.(string))); err != nil {
		return "", fmt.Errorf("save role id path: %s : %w", appRole.RoleIDLocalPath, err)
	}
	return roleID.(string), err
}

func (s *client) getSecretID(name string, appRole config.AppRole) (string, error) {
	if secretID, err := os.ReadFile(appRole.SecretIDLocalPath); err == nil {
		return string(secretID), nil
	}

	vaultPath := path.Join("auth", appRole.Path, "role", appRole.Name, "secret-id")
	secret, err := s.Write(vaultPath, nil)
	if err != nil {
		return "", fmt.Errorf("read secrete_id for path: %s : %w", vaultPath, err)
	}
	if secret == nil {
		return "", fmt.Errorf("secrete_id info was  not returned")
	}

	secretID, ok := secret["secret_id"]
	if !ok {
		return "", fmt.Errorf("not found secrete_id")
	}

	if err = writeToFile(appRole.SecretIDLocalPath, []byte(secretID.(string))); err != nil {
		return "", fmt.Errorf("save secret id path: %s : %w", appRole.SecretIDLocalPath, err)
	}
	return secretID.(string), err
}

func (s *client) getRoleToken(appRoleAuth *auth.AppRoleAuth) (string, time.Duration, error) {
	authInfo, err := s.cli.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		return "", 0, err
	}
	if authInfo == nil {
		return "", 0, fmt.Errorf("auth info was not returned after login")
	}

	token, err := authInfo.TokenID()
	if err != nil {
		return "", 0, err
	}

	ttl, err := authInfo.TokenTTL()
	if err != nil {
		return "", 0, err
	}
	return token, ttl, nil
}
