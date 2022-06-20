package controller

import (
	"time"
)

type Config struct {
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
	CommonName string `yaml:"common_name"`
	RootPathCA string `yaml:"root_path_ca"`
	CertPath   string `yaml:"cert_path"`
	Create     bool   `yaml:"create"`
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
