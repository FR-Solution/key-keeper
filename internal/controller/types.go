package controller

import (
	"time"
)

type Config struct {
	CommonName              string
	DomainName              string
	VaultIntermediateCAPath string
	VaultCertPath           string
	VaultTimeout            time.Duration

	CertPath string
	KeyPath  string
	CaPath   string

	ValidInterval time.Duration
}
