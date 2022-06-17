package vault

import (
	"time"
)

type Config struct {
	Address             string        `yaml:"address"`
	BootsrapToken       string        `yaml:"bootstrap_token"`
	AppRolePath         string        `yaml:"approle_path"`
	AppRoleName         string        `yaml:"approle_name"`
	LocalPathToRoleID   string        `yaml:"local_path_to_role_id"`
	LocalPathToSecretID string        `yaml:"local_path_to_secret_id"`
	RequestTimeout      time.Duration `yaml:"request_timeout"`
}
