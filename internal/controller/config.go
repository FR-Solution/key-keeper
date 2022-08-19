package controller

import (
	"time"
)

type Config struct {
	Vault    VaultConfig    `yaml:"vault"`
	Recource RecourceConfig `yaml:",inline"`
}

// VaultConfig for work with vault
type VaultConfig struct {
	Address             string        `yaml:"address"`
	BootsrapToken       string        `yaml:"bootstrap_token"`
	AppRolePath         string        `yaml:"approle_path"`
	AppRoleName         string        `yaml:"approle_name"`
	LocalPathToRoleID   string        `yaml:"local_path_to_role_id"`
	LocalPathToSecretID string        `yaml:"local_path_to_secret_id"`
	RequestTimeout      time.Duration `yaml:"request_timeout"`
}

// RecourceConfig for work controller.
type RecourceConfig struct {
	Certificates Certificates `json:"certificates"`
	Keys         Keys         `json:"keys"`
}

type Certificates struct {
	VaultKV         string           `yaml:"vault_kv"`
	ReissueInterval time.Duration    `yaml:"reissue_interval"`
	RootCA          []RootCA         `yaml:"root_ca,omitempty"`
	IntermediateCA  []IntermediateCA `yaml:"intermediate_ca,omitempty"`
	CSR             []CSR            `yaml:"csr,omitempty"`
}

type RootCA struct {
	CommonName string `yaml:"common_name"`
	RootPathCA string `yaml:"root_path_ca"`
}

type IntermediateCA struct {
	CommonName  string `yaml:"common_name"`
	RootPathCA  string `yaml:"root_path_ca"`
	CertPath    string `yaml:"cert_path"`
	Generate    bool   `yaml:"generate"`
	ExportedKey bool   `yaml:"exported_key"`
	HostPath    string `yaml:"host_path"`
}

type CSR struct {
	CommonName string   `yaml:"common_name"`
	Hosts      []string `yaml:"hosts"`
	IPs        []string `yaml:"ips"`
	CertPath   string   `yaml:"cert_path"`
	Role       string   `yaml:"role"`
	HostPath   string   `yaml:"host_path"`
	Trigger    []string `yaml:"trigger"`
}

type Keys struct {
	VaultKV string `yaml:"vault_kv"`
	RSA     []RSA  `yaml:"rsa"`
}

type RSA struct {
	Name     string `yaml:"name"`
	HostPath string `yaml:"host_path"`
}
