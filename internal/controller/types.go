package controller

import (
	"time"
)

type Config struct {
	VaultIntermediateCAPath string
	VaultCertPath           string
	VaultTimeout            time.Duration

	CommonName    string
	DomainName    string
	CertPath      string
	KeyPath       string
	CaPath        string
	ValidInterval time.Duration
}
