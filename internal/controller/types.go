package controller

import (
	"time"
)

type Config struct {
	VaultKV         string        `yaml:"vault_kv"`
	ReissueInterval time.Duration `yaml:"reissue_interval"`
	CA              []CA          `yaml:"ca,omitempty"`
	CSR             []CSR         `yaml:"csr,omitempty"`
}

type CA struct {
	CommonName string `yaml:"common_name"`
	RootPathCA string `yaml:"root_path_ca"`
	CertPath   string `yaml:"cert_path"`
	HostPath   string `yaml:"host_path"`
}

type CSR struct {
	CommonName string   `yaml:"common_name"`
	Hosts      []string `yaml:"hosts"`
	IPs        []string `yaml:"ips"`
	CertPath   string   `yaml:"cert_path"`
	Role       string   `yaml:"role"`
	HostPath   string   `yaml:"host_path"`
}
