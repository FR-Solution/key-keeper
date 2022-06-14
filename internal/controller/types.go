package controller

import (
	"time"
)

type Config struct {
	Vault Vault        `yaml:"vault"`
	Certs Certificates `yaml:"certificates"`
}

type Vault struct {
	Address string        `yaml:"address"`
	Token   string        `yaml:"token"`
	Timeout time.Duration `yaml:"timeout"`
}

type Certificates struct {
	RootPath      string        `yaml:"root_path"`
	CertPath      string        `yaml:"cert_path"`
	ValidInterval time.Duration `yaml:"valid_interval"`
	CA            struct {
		CommonName string `yaml:"common_name"`
		VaultPath  string `yaml:"vault_path"`
		HostPath   string `yaml:"host_path"`
	} `yaml:"ca"`
}
