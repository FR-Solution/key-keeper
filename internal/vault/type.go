package vault

import (
	"time"
)

type Config struct {
	Address        string        `yaml:"address"`
	Token          string        `yaml:"token"`
	RolePath       string        `yaml:"role_path"`
	RoleName       string        `yaml:"role_name"`
	PathToRoleID   string        `yaml:"path_to_role_id"`
	PathToSecretID string        `yaml:"path_to_secret_id"`
	Timeout        time.Duration `yaml:"timeout"`
}
